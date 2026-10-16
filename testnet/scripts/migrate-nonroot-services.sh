#!/usr/bin/env bash
# Move a host's root service to its own non-login user. Run as root, once per host.
#
#   migrate-nonroot-services.sh --role validator   # tos-testnet-elections -> tos-ctl
#   migrate-nonroot-services.sh --role dht         # tos-testnet-alert-peer -> tos-alert
#
# Install the updated testnet/ tree at /opt/tos-testnet first: the new unit is
# taken from ../systemd beside this script.
#
# validator: the election task (tosctl service) runs as tos-ctl. Everything
#   under /var/lib/tos-ctl becomes tos-ctl's (tosctl refuses a vault, lock or
#   key file it does not own); /etc/tos/tosctl.env stays root:root 0600, read
#   by systemd before it drops privileges.
# dht: the alert peer runs as tos-alert. /var/lib/tos-alert becomes
#   tos-alert's; /etc/tos-alert/{token,chat} stay root:root 0600 and reach the
#   service through LoadCredential=.
#
# Order, with the unit stopped only between steps 4 and 8:
#   1 refuse unless the unit is installed and active (a task someone stopped
#     is not started behind their back)
#   2 create the user (idempotent), back up the installed unit and a listing
#     of every state file's owner and mode to /var/backups/tos-nonroot/<time>/
#   3 systemd-analyze verify the new unit before anything stops
#   4 stop the unit
#   5 chown the state to the new user; keep the secrets root-owned 0600
#   6 validator: open the vault as tos-ctl (`tosctl key ls` must list the
#     console key) while the task is stopped and the vault lock is free
#   7 install the new unit, daemon-reload, systemd-analyze verify it
#   8 start it
#   9 check: active with a stable MainPID whose user is the new one, no
#     permission error in its journal since the start, and
#       validator: `tosctl controller operations status` as tos-ctl answers
#       dht:       heartbeat-peer was rewritten by tos-alert after the start
#
# On any failure from step 4 on it stops the unit, restores the old unit and
# every recorded owner and mode, starts the old unit again and checks that it
# is active; the election task is never left stopped by this script. Run it
# again after fixing the cause: every step is idempotent, and a host that is
# already migrated is only checked.
#
# It cannot see the chain. The caller checks the election window first
# (testnet-elections.py status, or the window rule of the refund) and does not
# run the validator role while an election is open; the stop lasts seconds.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TESTNET="$(dirname "$HERE")"
ROLE=""
die() { echo "migrate-nonroot: $*" >&2; exit 1; }
say() { echo "== $*"; }

[ "$(id -u)" = 0 ] || die "run as root"
while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE=$2; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done

case "$ROLE" in
  validator)
    UNIT=tos-testnet-elections.service
    SVC_USER=tos-ctl
    STATE=/var/lib/tos-ctl
    # Stays root:root; a directory 0700, a file 0600.
    SECRETS=(/etc/tos/tosctl.env)
    COMMENT="TOS operator tool"
    ;;
  dht)
    UNIT=tos-testnet-alert-peer.service
    SVC_USER=tos-alert
    STATE=/var/lib/tos-alert
    SECRETS=(/etc/tos-alert /etc/tos-alert/token /etc/tos-alert/chat)
    COMMENT="TOS testnet alert peer"
    ;;
  *) die "--role must be validator or dht" ;;
esac
INSTALLED=/etc/systemd/system/$UNIT
NEW=$TESTNET/systemd/$UNIT

# ---------------------------------------------------------------- 1 preconditions
[ -f "$NEW" ] || die "$NEW is missing; install the updated testnet/ tree first"
grep -q "^User=$SVC_USER\$" "$NEW" || die "$NEW does not run as $SVC_USER; install the updated testnet/ tree first"
[ -f "$INSTALLED" ] || die "$INSTALLED is not installed; nothing to migrate"
[ -d "$STATE" ] || die "$STATE is missing; nothing to migrate"
for secret in "${SECRETS[@]}"; do
  [ -e "$secret" ] || die "$secret is missing"
done
systemctl is-active --quiet "$UNIT" || die "$UNIT is not active; start it (or find out why it stopped) first"

main_user() {
  local pid
  pid=$(systemctl show -p MainPID --value "$UNIT")
  [ -n "$pid" ] && [ "$pid" != 0 ] || return 1
  ps -o user= -p "$pid" | tr -d ' '
}

# Root-free reading of the env, as the unit does: systemd reads the file as
# root and the process gets the variables. The master key stays off argv.
as_svc() {
  if [ "$ROLE" = validator ]; then
    # shellcheck disable=SC1091
    (set -a; . /etc/tos/tosctl.env; set +a; cd "$STATE" && runuser -u "$SVC_USER" -- "$@")
  else
    (cd "$STATE" && runuser -u "$SVC_USER" -- "$@")
  fi
}

controller_of_config() {
  python3 -c '
import json, sys
pools = json.load(open(sys.argv[1])).get("pools", {})
found = [p["controller"] for p in pools.values() if isinstance(p, dict) and p.get("controller")]
print(found[0] if found else "")
' "$STATE/tosctl-config.json"
}

# Every check after a start. Prints what it saw; returns non-zero on a failure.
check_running() {
  local since=$1 pid user stray status beat_owner beat_mtime
  for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$UNIT" && main_user >/dev/null; then break; fi
    sleep 1
  done
  pid=$(systemctl show -p MainPID --value "$UNIT")
  user=$(main_user) || { echo "$UNIT has no main process" >&2; return 1; }
  # A service that starts and dies is restarted by Restart=always; the same
  # MainPID five seconds later is what tells a running task from a loop.
  sleep 5
  [ "$(systemctl show -p MainPID --value "$UNIT")" = "$pid" ] \
    || { echo "$UNIT restarted within 5 s of its start" >&2; return 1; }
  systemctl is-active --quiet "$UNIT" || { echo "$UNIT is not active" >&2; return 1; }
  echo "MainPID $pid user: $(ps -o user= -p "$pid")"
  [ "$user" = "$SVC_USER" ] || { echo "$UNIT runs as $user, not $SVC_USER" >&2; return 1; }
  stray=$(find "$STATE" ! -user "$SVC_USER" -print -quit)
  [ -z "$stray" ] || { echo "$stray is not owned by $SVC_USER" >&2; return 1; }
  # tosctl names a file it refuses by its owner uid; the relay prints REFUSED.
  if journalctl -u "$UNIT" --since "@$since" --no-pager -o cat \
      | grep -E '[Pp]ermission denied|[Oo]peration not permitted|owned by uid|Unsafe Vault|^REFUSED' >&2; then
    echo "$UNIT logged a permission error since its start" >&2
    return 1
  fi
  if [ "$ROLE" = validator ]; then
    status=$(as_svc timeout 90 tosctl controller operations status --controller "$controller" 2>&1) \
      || { echo "tosctl as $SVC_USER: $status" | tail -5 >&2; return 1; }
    echo "tosctl as $SVC_USER, controller operations status --controller $controller:"
    printf '%s\n' "$status" | sed 's/\x1b\[[0-9;]*m//g' | head -8
  else
    # The peer touches its beat as soon as it starts, then every 60 s.
    for _ in $(seq 1 15); do
      beat_mtime=$(stat -c %Y "$STATE/heartbeat-peer" 2>/dev/null || echo 0)
      [ "$beat_mtime" -ge "$since" ] && break
      sleep 1
    done
    [ "$beat_mtime" -ge "$since" ] || { echo "heartbeat-peer was not rewritten after the start" >&2; return 1; }
    beat_owner=$(stat -c %U "$STATE/heartbeat-peer")
    [ "$beat_owner" = "$SVC_USER" ] || { echo "heartbeat-peer is owned by $beat_owner" >&2; return 1; }
    echo "heartbeat-peer rewritten at $(date -u -d "@$beat_mtime" +%H:%M:%SZ) by $beat_owner"
  fi
}

# Read before the stop: the post-start check asks tosctl about this controller.
controller=""
if [ "$ROLE" = validator ]; then
  controller=$(controller_of_config) || die "cannot read $STATE/tosctl-config.json"
  [ -n "$controller" ] || die "no pool controller in $STATE/tosctl-config.json; onboard the validator first"
fi

if cmp -s "$NEW" "$INSTALLED" && [ "$(main_user || true)" = "$SVC_USER" ]; then
  say "$UNIT already runs as $SVC_USER from the current unit; checking only"
  active_since=$(date -d "$(systemctl show -p ActiveEnterTimestamp --value "$UNIT")" +%s)
  check_running "$active_since" || die "the migrated $UNIT fails its checks; see above"
  exit 0
fi

# ---------------------------------------------------------------- 2 user, backup
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "$STATE" --no-create-home \
    --shell /usr/sbin/nologin --comment "$COMMENT" "$SVC_USER"
  say "created system user $SVC_USER"
fi
BACKUP=/var/backups/tos-nonroot/$(date -u +%Y%m%dT%H%M%SZ)-$ROLE
install -d -m 0700 -o root -g root /var/backups/tos-nonroot "$BACKUP"
cp -p "$INSTALLED" "$BACKUP/$UNIT"
# NUL-separated `uid gid mode path`, read back by restore_owners.
find "$STATE" "${SECRETS[@]}" -printf '%U %G %m %p\0' > "$BACKUP/owners"
say "backup: $BACKUP"

# ---------------------------------------------------------------- 3 verify first
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp "$NEW" "$STAGE/$UNIT"
systemd-analyze verify "$STAGE/$UNIT" || die "systemd-analyze rejects $NEW; nothing was changed"

restore_owners() {
  local uid gid mode path
  # Files the new user created since the stop are not in the listing; the old
  # unit ran as root, so root gets them.
  chown -R root:root "$STATE"
  while IFS=' ' read -r -d '' uid gid mode path; do
    [ -e "$path" ] || continue
    chown -h "$uid:$gid" "$path"
    chmod "$mode" "$path"
  done < "$BACKUP/owners"
}

rollback() {
  # A failure inside a command substitution trips the inherited trap in that
  # subshell; only the main shell restores, once, when the failure reaches it.
  [ "$BASHPID" = "$$" ] || exit 1
  # Best effort from here on: every step runs even if one before it failed.
  trap - ERR
  set +eE
  echo "migrate-nonroot: FAILED; restoring the root unit from $BACKUP" >&2
  systemctl stop "$UNIT"
  restore_owners || echo "migrate-nonroot: restoring owners failed; see $BACKUP/owners" >&2
  install -m 0644 -o root -g root "$BACKUP/$UNIT" "$INSTALLED"
  systemctl daemon-reload
  systemctl start "$UNIT"
  sleep 5
  if systemctl is-active --quiet "$UNIT"; then
    echo "migrate-nonroot: $UNIT runs again as $(main_user || echo '?') from the old unit" >&2
  else
    echo "migrate-nonroot: $UNIT DID NOT START AGAIN; start it by hand now" >&2
  fi
  exit 1
}

# ---------------------------------------------------------------- 4-8 the stop window
say "stopping $UNIT"
set -E
trap rollback ERR
systemctl stop "$UNIT"
chown -R "$SVC_USER:$SVC_USER" "$STATE"
chmod 0700 "$STATE"
for secret in "${SECRETS[@]}"; do
  chown root:root "$secret"
  if [ -d "$secret" ]; then chmod 0700 "$secret"; else chmod 0600 "$secret"; fi
done
if [ "$ROLE" = validator ]; then
  keys=$(as_svc timeout 60 tosctl key ls 2>&1) || { echo "$keys" | tail -5 >&2; false; }
  grep -q console-client <<< "$keys" || { echo "the vault as $SVC_USER has no console-client key" >&2; false; }
  say "vault opens as $SVC_USER"
fi
install -m 0644 -o root -g root "$NEW" "$INSTALLED"
systemctl daemon-reload
systemd-analyze verify "$INSTALLED"
started=$(date +%s)
systemctl start "$UNIT"
say "started $UNIT as $SVC_USER"

# ---------------------------------------------------------------- 9 checks
check_running "$started"
trap - ERR
set +E
say "migrated: $UNIT runs as $SVC_USER; backup of the old unit and owners in $BACKUP"
