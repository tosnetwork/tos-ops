#!/usr/bin/env bash
# Make the host's clock follow NTP over IPv4, and prove it does. Run as root, first, on every
# testnet or production host (install-node.sh prepare calls it before anything else).
#
#   setup-time.sh [EXTRA_SERVER ...]      default extra server: ntp.nict.jp
#
# Why: on the first testnet hosts ntpsec was installed and "active", and the kernel reported
# NTPSynchronized=yes, but ntpd had no server at all. The VMs carry IPv6 addresses without a
# working IPv6 path; ntpd chose IPv6 servers, unlinked them, and kept nothing. The clocks were
# right only because the hypervisor kept them right, with nothing to correct a drift or a
# migration. Consensus timeouts and key validity (valid_from / expire_at) read the wall clock.
#
# Steps, each idempotent:
#   1. install ntpsec if no ntpd is present; stop and disable systemd-timesyncd and chrony so
#      only one daemon disciplines the clock;
#   2. run ntpd with -4 (IPv4 only: nodes announce IPv4 addresses, and IPv6 may not route);
#   3. add the extra servers (a nearby stratum-1 server by default) beside the distribution pool;
#   4. restart ntpsec and wait up to 90 s until ntpd has selected a reachable server ("*" in
#      `ntpq -pn`). Exit 1 if it has not, naming what to check.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "setup-time: run as root" >&2; exit 1; }
SERVERS=("$@")
[ ${#SERVERS[@]} -gt 0 ] || SERVERS=(ntp.nict.jp)
DEFAULTS=/etc/default/ntpsec
CONF=/etc/ntpsec/ntp.conf

if ! command -v ntpd >/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ntpsec >/dev/null
fi
for other in systemd-timesyncd chrony; do
  if systemctl is-enabled --quiet "$other" 2>/dev/null || systemctl is-active --quiet "$other" 2>/dev/null; then
    systemctl disable --now "$other" >/dev/null 2>&1 || true
    echo "setup-time: disabled $other (ntpsec disciplines the clock)"
  fi
done

[ -f "$DEFAULTS.orig" ] || cp "$DEFAULTS" "$DEFAULTS.orig"
[ -f "$CONF.orig" ] || cp "$CONF" "$CONF.orig"
python3 - "$DEFAULTS" "$CONF" "${SERVERS[@]}" <<'EOF'
import re
import sys
from pathlib import Path

defaults, conf, servers = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3:]
text = defaults.read_text()
match = re.search(r'^NTPD_OPTS="([^"]*)"', text, re.M)
if match is None:
    text = text.rstrip("\n") + '\nNTPD_OPTS="-4 -g -N"\n'
elif "-4" not in match.group(1).split():
    text = text[: match.start(1)] + "-4 " + match.group(1) + text[match.end(1) :]
defaults.write_text(text)

lines = conf.read_text()
missing = [s for s in servers if not re.search(rf"^server\s+{re.escape(s)}\b", lines, re.M)]
if missing:
    lines = lines.rstrip("\n") + "\n\n# Nearby servers added by setup-time.sh (IPv4)\n"
    lines += "".join(f"server {s} iburst\n" for s in missing)
    conf.write_text(lines)
EOF

systemctl enable ntpsec >/dev/null 2>&1
systemctl restart ntpsec
for _ in $(seq 1 18); do
  sleep 5
  selected=$(ntpq -pn 2>/dev/null | awk '/^\*/ {print $1 " offset " $9 " ms"}')
  if [ -n "$selected" ]; then
    reachable=$(ntpq -pn 2>/dev/null | awk 'NR > 2 && $1 !~ /POOL|DNS/ && $7 != "0"' | wc -l)
    echo "setup-time: ntpd IPv4, $reachable reachable servers, selected ${selected#\*}"
    exit 0
  fi
done
echo "setup-time: ntpd selected no server within 90 s; check outbound UDP 123 and DNS:" >&2
ntpq -pn >&2 || true
exit 1
