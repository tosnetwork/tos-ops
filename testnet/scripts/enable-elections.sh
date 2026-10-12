#!/usr/bin/env bash
# Enable the election task on a validator host. Run as root, after onboarding.
#
#   enable-elections.sh --name NAME
#
# Sets tosctl's election policy from network/profile.json (a fixed stake of
# elections.stake_tos, max factor elections.max_factor), enables elections for
# node NAME, installs systemd/tos-testnet-elections.service and starts it.
# Refuses unless the node is bound to a wallet and a pool (onboard-validator).
# Then waits until the task has opened the wallet and the pool, or reports
# what it logged instead.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TESTNET="$(dirname "$HERE")"
PROFILE="$TESTNET/network/profile.json"
UNIT=tos-testnet-elections.service
NAME=""
die() { echo "enable-elections: $*" >&2; exit 1; }
profile() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [d:=d[k] for k in sys.argv[2:]]; print(d)' "$PROFILE" "$@"; }

[ "$(id -u)" = 0 ] || die "run as root"
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "--name must be lower-case letters, digits and dashes"
[ -f /etc/tos/tosctl.env ] || die "/etc/tos/tosctl.env is missing; run init-operator.sh first"
set -a
# shellcheck disable=SC1091
. /etc/tos/tosctl.env
set +a
cd /var/lib/tos-ctl
python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); sys.exit(0 if c.get("pools", {}).get("pool-" + sys.argv[2]) else 1)' \
  "$CONFIG_PATH" "$NAME" || die "pool-$NAME is not configured; onboard the validator first"

tosctl config elections stake-policy --fixed "$(profile elections stake_tos)" >/dev/null
tosctl config elections max-factor "$(profile elections max_factor)" >/dev/null
tosctl config elections enable "$NAME" >/dev/null

install -m 0644 -o root -g root "$TESTNET/systemd/$UNIT" "/etc/systemd/system/$UNIT"
systemctl daemon-reload
systemd-analyze verify "/etc/systemd/system/$UNIT"
systemctl enable "$UNIT" >/dev/null 2>&1
systemctl restart "$UNIT"

for _ in $(seq 1 12); do
  sleep 5
  if journalctl -u "$UNIT" --since "-2min" --no-pager -o cat | sed 's/\x1b\[[0-9;]*m//g' \
      | grep -qE 'opened nominator pool|no active elections|submitted|stake'; then
    systemctl is-active "$UNIT"
    journalctl -u "$UNIT" --since "-2min" --no-pager -o cat | sed 's/\x1b\[[0-9;]*m//g' \
      | grep -E 'opened (wallet|nominator pool)|no active elections|stake' | tail -5 | cut -c1-160
    exit 0
  fi
done
journalctl -u "$UNIT" -n 30 --no-pager -o cat | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-200 >&2
die "the election task did not report a pool or an election within 60 s"
