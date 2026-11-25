#!/usr/bin/env bash
# Enable the election task on a validator host. Run as root, after onboarding.
#
#   enable-elections.sh --name NAME [--stake-tos TOS --max-factor F]
#
# Sets tosctl's election policy from network/profile.json: a fixed stake of
# elections.stake_tos and tosctl's default max factor
# (elections.external_max_factor) for an external pool, or, for a team pool,
# --stake-tos (the team multiple of the unit) and --max-factor
# (elections.max_factor). Refuses unless tosctl accepted the max factor and
# its configuration reads it back, so a tosctl that rejects a team pool's
# factor stops here instead of staking with a capped one. Enables elections for
# node NAME, turns tosctl's explorer indexer off (indexer_enabled: false),
# installs systemd/tos-testnet-elections.service and starts it. The task and
# every tosctl call here run as the non-login user tos-ctl (created if missing).
# Refuses unless the clock is NTP-disciplined (check-clock.py) and the node is
# bound to a wallet and a pool (onboard-validator).
# Then waits until the task has opened the wallet and the pool, or reports
# what it logged instead.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TESTNET="$(dirname "$HERE")"
PROFILE="$TESTNET/network/profile.json"
UNIT=tos-testnet-elections.service
USER_NAME=tos-ctl
DIR=/var/lib/tos-ctl
NAME=""
STAKE=""
FACTOR=""
die() { echo "enable-elections: $*" >&2; exit 1; }
profile() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [d:=d[k] for k in sys.argv[2:]]; print(d)' "$PROFILE" "$@"; }
as_ctl() { runuser -u "$USER_NAME" -- "$@"; }

[ "$(id -u)" = 0 ] || die "run as root"
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift 2 ;;
    --stake-tos) STAKE=$2; shift 2 ;;
    --max-factor) FACTOR=$2; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "--name must be lower-case letters, digits and dashes"
UNIT_STAKE="$(profile elections stake_tos)"
[ -n "$STAKE" ] || STAKE=$UNIT_STAKE
[[ "$STAKE" =~ ^[1-9][0-9]{0,9}$ ]] || die "--stake-tos must be a whole number of TOS"
[ "$STAKE" -ge "$UNIT_STAKE" ] || die "--stake-tos $STAKE is below elections.stake_tos $UNIT_STAKE"
[ -n "$FACTOR" ] || FACTOR="$(profile elections external_max_factor)"
[[ "$FACTOR" =~ ^[1-9][0-9]?(\.[0-9]+)?$|^100(\.0+)?$ ]] || die "--max-factor must be a decimal from 1.0 to 100.0"
[ -f /etc/tos/tosctl.env ] || die "/etc/tos/tosctl.env is missing; run init-operator.sh first"
[ -d "$DIR" ] || die "$DIR is missing; run init-operator.sh first"
# A validator stakes only with an NTP-disciplined clock: consensus reads it.
python3 "$HERE/check-clock.py" \
  || die "the clock is not NTP-disciplined (above); run setup-time.sh and check again before enabling elections"
# The task runs as tos-ctl (see the unit); so does every tosctl call here, so
# nothing it writes in /var/lib/tos-ctl becomes root-owned.
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "$DIR" --no-create-home \
    --shell /usr/sbin/nologin --comment "TOS operator tool" "$USER_NAME"
fi
stray=$(find "$DIR" ! -user "$USER_NAME" -print -quit)
[ -z "$stray" ] || die "$stray is not owned by $USER_NAME; run migrate-nonroot-services.sh --role validator first"
set -a
# shellcheck disable=SC1091
. /etc/tos/tosctl.env
set +a
cd "$DIR"
python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); sys.exit(0 if c.get("pools", {}).get("pool-" + sys.argv[2]) else 1)' \
  "$CONFIG_PATH" "$NAME" || die "pool-$NAME is not configured; onboard the validator first"

as_ctl tosctl config elections stake-policy --fixed "$STAKE" >/dev/null
as_ctl tosctl config elections max-factor "$FACTOR" >/dev/null \
  || die "tosctl refuses max factor $FACTOR; install a tosctl that accepts it (a team pool staked with a smaller one would count fewer units)"
python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); sys.exit(0 if abs(float(c["elections"]["max_factor"]) - float(sys.argv[2])) < 1e-6 else 1)' \
  "$CONFIG_PATH" "$FACTOR" || die "tosctl's configuration does not read back max factor $FACTOR"
as_ctl tosctl config elections enable "$NAME" >/dev/null
# A validator host serves no explorer, and the always-on indexer costs about as
# much CPU as the validator itself. The service reads the key when it starts.
# Written as tos-ctl, so the replaced file keeps its owner; the mode is copied.
as_ctl python3 -c '
import json, os, sys
path = sys.argv[1]
with open(path) as f:
    config = json.load(f)
config["indexer_enabled"] = False
with open(path + ".tmp", "w") as f:
    json.dump(config, f, indent=2)
os.chmod(path + ".tmp", os.stat(path).st_mode)
os.replace(path + ".tmp", path)
' "$CONFIG_PATH"

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
