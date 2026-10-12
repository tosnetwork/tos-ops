#!/usr/bin/env bash
# Retire this host's node from an ended testnet epoch, before a reset. Run as root.
#
#   retire-host.sh --confirm-zerostate ROOT_HASH_BASE64
#
# ROOT_HASH_BASE64 is the retired epoch's zero state root hash, exactly as its
# global-config.json publishes it (validator.zero_state.root_hash). The script
# refuses unless the installed /etc/tos/global-config.json names that zero
# state, so it cannot wipe a node of an epoch the operator did not mean.
#
# Evidence first. Before it deletes anything it writes an archive under
# /var/lib/tos-retired/<epoch>/ with a .sha256 beside it:
#   live.txt     process memory, free/df/uptime, NTP peers, every testnet
#                unit's systemctl show (restarts, exit status, memory peak),
#                taken while the units still run
#   var-log-tos  every log the nodes wrote, session stats included
#   journal.txt  the journal of every testnet unit
#   kernel-*.txt this boot's and the previous boot's kernel log (OOM kills)
#   etc-tos      BUILD-INFO and the retired global config
# It holds no database and no key. If the archive cannot be written or read
# back, nothing is deleted. The coordinator copies the archives off the host
# before the next epoch (CEREMONY.md section 9).
#
# Then it stops and disables every testnet unit on the host, and deletes:
#   /var/lib/tos/{validator,fullnode,dht}   databases, consensus seed, keys
#   /var/log/tos/{validator,fullnode,dht}   logs (now in the archive)
#   /etc/tos/global-config.json             the retired epoch's config
#   /var/lib/tos-ctl, /etc/tos/tosctl.env   the operator tool's vault and its master key
# and keeps the installed binaries, /var/lib/tos-build and the time setup.
#
# A consensus seed and a controller root key are never carried into a new
# epoch (CEREMONY.md section 9), so no key is worth keeping; the coordinator
# keeps the retired epoch's genesis-records.json for `manifest --previous`.
# Afterwards run install-node.sh prepare again.
set -euo pipefail

die() { echo "retire-host: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
CONFIRM=""
while [ $# -gt 0 ]; do
  case "$1" in
    --confirm-zerostate) CONFIRM=$2; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[ -n "$CONFIRM" ] || die "--confirm-zerostate ROOT_HASH_BASE64 is required"

CONFIG=/etc/tos/global-config.json
[ -f "$CONFIG" ] || die "$CONFIG is missing; nothing on this host names an epoch to retire"
installed=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validator"]["zero_state"]["root_hash"])' "$CONFIG") \
  || die "$CONFIG has no validator.zero_state.root_hash"
[ "$installed" = "$CONFIRM" ] || die "this host runs zero state $installed, not $CONFIRM; refusing"

UNITS=(tos-testnet-elections tos-testnet-validator tos-testnet-fullnode tos-testnet-dht)
present_units() {
  local unit
  for unit in "${UNITS[@]}"; do
    if systemctl list-unit-files --no-legend "$unit.service" | grep -q .; then echo "$unit"; fi
  done
}

# ---------------------------------------------------------------- evidence
# The epoch is named by its zero state, in hex, so archives of two resets never mix.
epoch=$(python3 -c 'import base64,sys; print(base64.b64decode(sys.argv[1]).hex()[:16])' "$CONFIRM") \
  || die "--confirm-zerostate is not base64"
ARCHIVE_DIR=/var/lib/tos-retired/$epoch
install -d -m 0700 -o root -g root /var/lib/tos-retired "$ARCHIVE_DIR"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="$(hostname)-$stamp"
STAGE=$(mktemp -d "$ARCHIVE_DIR/.stage-XXXXXX")
trap 'rm -rf "$STAGE"' EXIT

log_bytes=$(du -sb /var/log/tos 2>/dev/null | cut -f1 || echo 0)
free_bytes=$(df -B1 --output=avail "$ARCHIVE_DIR" | tail -1 | tr -d ' ')
[ "$free_bytes" -gt $((log_bytes + 1073741824)) ] \
  || die "not enough free space under $ARCHIVE_DIR for the log archive; nothing was deleted"

{
  echo "# retire-host.sh evidence, $stamp, zero state $CONFIRM"
  echo "## uptime"; uptime
  echo "## free -m"; free -m
  echo "## df -h"; df -h
  echo "## processes by RSS"; ps -eo pid,rss,vsz,etime,stat,comm --sort=-rss | head -15
  echo "## ntpq -pn"; ntpq -pn 2>&1 || true
  for unit in $(present_units); do
    echo "## systemctl show $unit"
    systemctl show "$unit" -p ActiveState -p SubState -p ActiveEnterTimestamp -p NRestarts \
      -p ExecMainStatus -p ExecMainExitTimestamp -p Result -p MemoryCurrent -p MemoryPeak 2>&1 || true
  done
} > "$STAGE/live.txt"

for unit in $(present_units); do
  systemctl disable --now "$unit.service"
done
for unit in "${UNITS[@]}"; do
  if systemctl is-active --quiet "$unit"; then die "$unit is still running; nothing was deleted"; fi
done

journal_units=()
for unit in "${UNITS[@]}"; do journal_units+=(-u "$unit"); done
journalctl "${journal_units[@]}" --no-pager -o short-iso-precise > "$STAGE/journal.txt" 2>&1 || true
journalctl -k -b 0 --no-pager -o short-iso-precise > "$STAGE/kernel-this-boot.txt" 2>&1 || true
journalctl -k -b -1 --no-pager -o short-iso-precise > "$STAGE/kernel-previous-boot.txt" 2>&1 || true
install -d "$STAGE/etc-tos"
cp -p "$CONFIG" "$STAGE/etc-tos/"
[ -f /etc/tos/BUILD-INFO ] && cp -p /etc/tos/BUILD-INFO "$STAGE/etc-tos/"
[ -d /var/log/tos ] && cp -a /var/log/tos "$STAGE/var-log-tos"

ARCHIVE="$ARCHIVE_DIR/$name.tar.gz"
tar -C "$STAGE" -czf "$ARCHIVE" . || { rm -f "$ARCHIVE"; die "writing $ARCHIVE failed; nothing was deleted"; }
tar -tzf "$ARCHIVE" > /dev/null || { rm -f "$ARCHIVE"; die "$ARCHIVE does not read back; nothing was deleted"; }
(cd "$ARCHIVE_DIR" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
chmod 0600 "$ARCHIVE" "$ARCHIVE.sha256"
echo "evidence: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1)), sha256 $(cut -c1-16 "$ARCHIVE.sha256")"

# ---------------------------------------------------------------- delete
for role in validator fullnode dht; do
  rm -rf --one-file-system "/var/lib/tos/$role" "/var/log/tos/$role"
done
rm -rf --one-file-system /var/lib/tos-ctl
rm -f "$CONFIG" /etc/tos/tosctl.env

echo "retired zero state $CONFIRM; df after:"
df -h /var/lib | tail -1
echo "next: copy $ARCHIVE off this host, then install-node.sh prepare --role ROLE --public-ip IP"
