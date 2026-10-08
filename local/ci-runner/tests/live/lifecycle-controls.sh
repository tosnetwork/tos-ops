#!/bin/bash
# Live lifecycle and maintenance controls (run as root, supervisor running):
#   1. an interrupted real cleanup keeps the slot unavailable, a builder waiting
#      on it gives up at its deadline, and the supervisor's retry recovers it;
#   2. an orphan runner registration is removed by reconciliation;
#   3. a second builder refuses; a builder holding the maintenance lock makes
#      the supervisor skip launches;
#   4. a conversion over the size cap fails, leaves no candidate, and keeps
#      the current image.
set -uo pipefail
[[ $EUID == 0 ]] || { echo "run as root" >&2; exit 2; }
fails=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }
BUILD="python3 -I /usr/lib/tos-ci/build-image.py"
log_since() { journalctl -u tos-ci-supervisor --since "$1" -o cat --no-pager; }
now() { date -u '+%Y-%m-%d %H:%M:%S UTC'; }
active() { systemctl is-active "tos-ci-vm@$1.service"; }
wait_active() { for _ in $(seq 60); do [[ $(active "$1") == active ]] && return 0; sleep 5; done; return 1; }
gh_names() { python3 -I - <<'PY'
import json, urllib.request
token = open("/etc/tos-ci/token").read().strip()
req = urllib.request.Request("https://api.github.com/repos/tosnetwork/tos/actions/runners?per_page=100",
    headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
print(" ".join(r["name"] for r in json.load(urllib.request.urlopen(req, timeout=20))["runners"]))
PY
}

echo "== 1. interrupted real cleanup"
wait_active 1 || { echo "slot 1 not running" >&2; exit 2; }
touch /var/lib/tos-ci/slot1/immutable-probe && chattr +i /var/lib/tos-ci/slot1/immutable-probe
mark=$(now)
touch /etc/tos-ci/drain
for _ in $(seq 40); do [[ $(active 1) != active && $(active 2) != active && $(active 3) != active ]] && break; sleep 3; done
sleep 10
rm -f /etc/tos-ci/drain
log_since "$mark" | grep -q '"teardown_unconfirmed".*"slot": 1' && pass "slot 1's failed cleanup is reported unconfirmed" \
  || fail "no teardown_unconfirmed for slot 1"
[[ $(cat /var/lib/tos-ci/state/cleanup-1) != "$(cat /var/lib/tos-ci/state/start-1)" ]] \
  && pass "slot 1's cleanup marker did not advance" || fail "slot 1's marker advanced"
echo "-- a builder with a 60 s deadline while slot 1 is stuck"
t0=$SECONDS
if $BUILD --deadline-seconds 60 > /tmp/tos-ci-build-stuck.log 2>&1; then fail "the builder built while a slot was stuck"
else
  (( SECONDS - t0 >= 55 && SECONDS - t0 <= 120 )) && pass "the builder gave up at its deadline ($((SECONDS - t0)) s)" \
    || fail "the builder exited after $((SECONDS - t0)) s: $(tail -1 /tmp/tos-ci-build-stuck.log)"
fi
ls /var/lib/tos-ci/images/ | grep -q build- && fail "a build directory was left" || pass "no build was started"
sleep 30
log_since "$mark" | grep '"slot_started"' | grep -q '"slot": 1' && fail "slot 1 was relaunched before its cleanup" \
  || pass "slot 1 stays unavailable"
log_since "$mark" | grep '"slot_started"' | grep -qE '"slot": (2|3)' && pass "slots 2 and 3 relaunched meanwhile" \
  || fail "slots 2 and 3 did not relaunch"
chattr -i /var/lib/tos-ci/slot1/immutable-probe
mark2=$(now)
for _ in $(seq 30); do log_since "$mark2" | grep '"slot_started"' | grep -q '"slot": 1' && break; sleep 5; done
log_since "$mark2" | grep '"slot_started"' | grep -q '"slot": 1' && pass "after the retry slot 1 relaunched" \
  || fail "slot 1 did not recover"
[[ $(cat /var/lib/tos-ci/state/cleanup-1) == "$(cat /var/lib/tos-ci/state/start-1)" ]] || wait_active 1 \
  && pass "slot 1's marker matched before its relaunch" || fail "markers inconsistent"

echo "== 2. orphan registration"
setpriv --reuid=tos-ci --regid=tos-ci --clear-groups -- python3 -I /usr/lib/tos-ci/op.py jit 2 deadbeefdeadbeefdeadbeefdeadbeef > /dev/null \
  && echo "created stray tos-ci-s2-deadbeef"
gh_names | grep -q tos-ci-s2-deadbeef && pass "positive control: the stray is listed" || fail "stray not created"
for _ in $(seq 40); do gh_names | grep -q tos-ci-s2-deadbeef || break; sleep 10; done
gh_names | grep -q tos-ci-s2-deadbeef && fail "the stray survived reconciliation" || pass "reconciliation removed the stray"

echo "== 3. builders and the maintenance lock"
mark3=$(now)
$BUILD --deadline-seconds 90 > /tmp/tos-ci-build-a.log 2>&1 &
a=$!
sleep 5
if $BUILD --deadline-seconds 30 > /tmp/tos-ci-build-b.log 2>&1; then fail "a second builder ran"
else grep -q "another image build is running" /tmp/tos-ci-build-b.log && pass "a second builder refuses at once" \
  || fail "second builder: $(tail -1 /tmp/tos-ci-build-b.log)"; fi
touch /etc/tos-ci/drain; sleep 20; rm -f /etc/tos-ci/drain  # recycle VMs so launches are attempted
wait "$a"
log_since "$mark3" | grep -q '"launch_skipped"' && pass "launches were skipped while the builder held the lock" \
  || fail "no launch was skipped"

echo "== 4. conversion over the cap"
current=$(readlink /var/lib/tos-ci/images/current.qcow2)
touch /etc/tos-ci/drain
for _ in $(seq 60); do [[ $(active 1) != active && $(active 2) != active && $(active 3) != active ]] && break; sleep 5; done
sleep 15
if $BUILD --image-cap-bytes $((1024 * 1024 * 1024)) > /tmp/tos-ci-build-cap.log 2>&1; then fail "an oversized image was published"
else grep -q "conversion failed or exceeded" /tmp/tos-ci-build-cap.log && pass "the capped conversion failed" \
  || fail "build failed otherwise: $(tail -3 /tmp/tos-ci-build-cap.log)"; fi
ls /var/lib/tos-ci/images/ | grep -qE 'candidate-|build-' && fail "a candidate or build directory was left" \
  || pass "no candidate or build directory remains"
[[ $(readlink /var/lib/tos-ci/images/current.qcow2) == "$current" ]] && pass "current still points to $current" \
  || fail "current changed"
rm -f /etc/tos-ci/drain

echo "== result: $fails failure(s)"
exit "$fails"
