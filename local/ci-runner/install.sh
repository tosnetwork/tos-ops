#!/bin/bash
# Install or update the self-hosted CI runner host side. Run as root from this
# directory: sudo ./install.sh. Idempotent. It does not start the supervisor;
# build an image first (see README.md).
set -euo pipefail
[[ $EUID == 0 ]] || { echo "run as root" >&2; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
LIB=/usr/lib/tos-ci
ETC=/etc/tos-ci
STORE=/var/lib/tos-ci
STORE_IMG=/var/lib/tos-ci.img
STORE_SIZE=340G

echo "== accounts"
id tos-ci > /dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tos-ci
for n in 1 2 3; do
  id "tos-ci-slot$n" > /dev/null 2>&1 \
    || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --groups kvm "tos-ci-slot$n"
done
id tos-ci-build > /dev/null 2>&1 \
  || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --groups kvm tos-ci-build
for a in tos-ci tos-ci-slot1 tos-ci-slot2 tos-ci-slot3 tos-ci-build; do
  for g in sudo docker lxd adm; do
    if id -nG "$a" | tr ' ' '\n' | grep -qx "$g"; then echo "refusing: $a is in $g" >&2; exit 1; fi
  done
done
if id -nG tos-ci | tr ' ' '\n' | grep -qx kvm; then echo "refusing: tos-ci is in kvm" >&2; exit 1; fi

echo "== store ($STORE_SIZE, preallocated)"
if [[ ! -e $STORE_IMG ]]; then
  fallocate -l "$STORE_SIZE" "$STORE_IMG"
  chmod 0600 "$STORE_IMG"
  mkfs.ext4 -q -m 0 -L tos-ci "$STORE_IMG"
fi
install -d -m 0755 -o root -g root "$STORE"

echo "== files"
install -d -m 0755 -o root -g root "$LIB" "$LIB/guest" "$ETC"
for f in slot-prepare slot-cleanup slot-qemu net-setup; do
  install -m 0755 -o root -g root "$HERE/host/lib/$f" "$LIB/$f"
done
for f in slotctl.py supervisor.py build-image.py; do
  install -m 0644 -o root -g root "$HERE/host/lib/$f" "$LIB/$f"
done
install -m 0644 -o root -g root "$HERE/host/nft/tos-ci.nft" "$LIB/tos-ci.nft"
install -m 0644 -o root -g root "$HERE/README.md" "$LIB/README.md"
for f in "$HERE"/guest/*; do
  [[ -f $f ]] || continue
  install -m 0644 -o root -g root "$f" "$LIB/guest/$(basename "$f")"
done
for f in "$HERE"/host/systemd/*.service "$HERE"/host/systemd/*.slice "$HERE"/host/systemd/*.socket \
         "$HERE"/host/systemd/*.timer "$HERE"/host/systemd/*.mount; do
  install -m 0644 -o root -g root "$f" "/etc/systemd/system/$(basename "$f")"
done
for n in 1 2 3; do
  install -d -m 0755 -o root -g root "/etc/systemd/system/tos-ci-vm@$n.service.d"
  install -m 0644 -o root -g root "$HERE/host/systemd/tos-ci-vm@$n.service.d/cpus.conf" \
    "/etc/systemd/system/tos-ci-vm@$n.service.d/cpus.conf"
done
install -m 0644 -o root -g root "$HERE"/host/network/60-tosci0.* /etc/systemd/network/
install -m 0644 -o root -g root "$HERE/host/tmpfiles/tos-ci.conf" /etc/tmpfiles.d/tos-ci.conf
install -m 0644 -o root -g root "$HERE/host/config.json" "$ETC/config.json"
install -m 0644 -o root -g root "$HERE/host/trusted-logins" "$ETC/trusted-logins"

echo "== token"
owner_home=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)
src="$owner_home/.config/tos-ci/token"
if [[ -s $src ]]; then
  install -m 0600 -o tos-ci -g tos-ci "$src" "$ETC/token"
  shred -u -z "$src"
  echo "token moved to $ETC/token; the source was shredded"
fi
[[ -s $ETC/token && $(stat -c '%U %a' "$ETC/token") == "tos-ci 600" ]] || { echo "no usable $ETC/token" >&2; exit 1; }

echo "== manifest"
{
  for f in /etc/systemd/system/tos-ci-vm@.service /etc/systemd/system/tos-ci-vm@{1,2,3}.service.d/cpus.conf \
           /etc/systemd/system/tos-ci.slice /etc/systemd/system/tos-ci-slotctl.socket \
           /etc/systemd/system/tos-ci-slotctl@.service /etc/systemd/system/tos-ci-supervisor.service \
           /etc/systemd/system/tos-ci-net.service "$LIB"/slot-prepare "$LIB"/slot-cleanup "$LIB"/slot-qemu \
           "$LIB"/net-setup "$LIB"/slotctl.py "$LIB"/supervisor.py "$LIB"/tos-ci.nft "$ETC"/config.json; do
    printf '%s  %s\n' "$(sha256sum < "$f" | cut -d' ' -f1)" "$f"
  done
} > "$LIB/MANIFEST.sha256"
chmod 0644 "$LIB/MANIFEST.sha256"

echo "== activate"
systemd-tmpfiles --create /etc/tmpfiles.d/tos-ci.conf
systemctl daemon-reload
networkctl reload
systemctl enable --now 'var-lib-tos\x2dci.mount'
for d in images state; do install -d -m 0755 -o root -g root "$STORE/$d"; done
for n in 1 2 3; do install -d -m 2750 -o tos-ci -g "tos-ci-slot$n" "$STORE/seed$n"; done
systemctl enable --now tos-ci-net.service tos-ci-dnsmasq.service tos-ci-net-refresh.timer tos-ci-slotctl.socket
systemctl restart tos-ci-net.service tos-ci-dnsmasq.service
echo "installed; next: sudo python3 -I $LIB/build-image.py, then systemctl enable --now tos-ci-supervisor"
