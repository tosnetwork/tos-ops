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
# It stops and disables every testnet unit on the host, then deletes:
#   /var/lib/tos/{validator,fullnode,dht}   databases, consensus seed, keys
#   /var/log/tos/{validator,fullnode,dht}   logs
#   /etc/tos/global-config.json             the retired epoch's config
#   /var/lib/tos-ctl, /etc/tos/tosctl.env   the operator tool's vault and its master key
# and keeps the installed binaries, /var/lib/tos-build and the time setup.
#
# A consensus seed and a controller root key are never carried into a new
# epoch (CEREMONY.md section 9), so nothing here is worth keeping; the
# coordinator keeps the retired epoch's genesis-records.json for
# `manifest --previous`. Afterwards run install-node.sh prepare again.
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
for unit in "${UNITS[@]}"; do
  if systemctl list-unit-files --no-legend "$unit.service" | grep -q .; then
    systemctl disable --now "$unit.service"
  fi
done
for unit in "${UNITS[@]}"; do
  if systemctl is-active --quiet "$unit"; then die "$unit is still running"; fi
done

for role in validator fullnode dht; do
  rm -rf --one-file-system "/var/lib/tos/$role" "/var/log/tos/$role"
done
rm -rf --one-file-system /var/lib/tos-ctl
rm -f "$CONFIG" /etc/tos/tosctl.env

echo "retired zero state $CONFIRM; df after:"
df -h /var/lib | tail -1
echo "next: install-node.sh prepare --role ROLE --public-ip IP"
