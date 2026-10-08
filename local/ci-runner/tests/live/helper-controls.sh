#!/bin/bash
# Live controls for the slot helper's desired-state rule (run as root, with the
# supervisor running and slot 1 holding a VM):
#   b. a delayed old stop/cleanup spares the newer VM;
#   c. a supervisor restart continues from the helper's latest generation,
#      while a stale request queued behind the slot lock answers "stale";
#   a. a delayed start after a stop of the same generation never runs
#      (supervisor stopped for this part, then started again).
set -uo pipefail
[[ $EUID == 0 ]] || { echo "run as root" >&2; exit 2; }
fails=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

ask() {  # request as the supervisor account; prints the reply
  setpriv --reuid=tos-ci --regid=tos-ci --clear-groups -- python3 -c 'import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(240); s.connect("/run/tos-ci/slotctl.sock")
s.sendall(sys.argv[1].encode()); r=b""
while not r.endswith(b"\n"):
    c=s.recv(4096)
    if not c: break
    r+=c
print(r.decode().strip())' "$1"
}
field() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"; }
hold_lock() {  # hold slot $1's op lock for $2 seconds, in the background
  python3 -c 'import fcntl,sys,time
f=open(f"/run/tos-ci/slot{sys.argv[1]}.op.lock","a+"); fcntl.flock(f,fcntl.LOCK_EX)
open(sys.argv[3],"w").close(); time.sleep(float(sys.argv[2]))' "$1" "$2" "$T/held" &
  for _ in $(seq 50); do [[ -e $T/held ]] && break; sleep 0.1; done
  rm -f "$T/held"
}
wait_running() {
  for _ in $(seq 60); do
    s=$(ask $'status 1\n'); [[ $(field "$s" active) == active ]] && { echo "$s"; return 0; }
    sleep 5
  done
  return 1
}

echo "== b. delayed old stop and cleanup spare the newer VM"
s=$(wait_running) || { echo "slot 1 never ran"; exit 2; }
g=$(field "$s" latest); pid=$(field "$s" pid)
echo "slot 1 runs generation $g (QEMU $pid)"
hold_lock 1 4
ask "down 1 $((g - 1))"$'\n' > "$T/old-down" &
ask "cleanup 1 $((g - 1))"$'\n' > "$T/old-cleanup" &
wait
[[ $(cat "$T/old-down") == stale ]] && pass "down for generation $((g - 1)) answers stale" || fail "old down: $(cat "$T/old-down")"
[[ $(cat "$T/old-cleanup") == stale ]] && pass "cleanup for generation $((g - 1)) answers stale" || fail "old cleanup: $(cat "$T/old-cleanup")"
s=$(ask $'status 1\n')
[[ $(field "$s" active) == active && $(field "$s" pid) == "$pid" ]] && pass "the generation-$g VM is still running" \
  || fail "the VM was touched: $s"

echo "== c. restart continues from latest; a queued stale request stays stale"
hold_lock 1 8
ask "down 1 1"$'\n' > "$T/stale-down" &
since=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
systemctl restart tos-ci-supervisor.service
wait
[[ $(cat "$T/stale-down") == stale ]] && pass "the stale down queued across the restart answers stale" \
  || fail "stale down: $(cat "$T/stale-down")"
for _ in $(seq 60); do
  line=$(journalctl -u tos-ci-supervisor --since "$since" -o cat --no-pager | grep '"slot_started"' | grep '"slot": 1' | head -1)
  [[ -n $line ]] && break; sleep 5
done
started=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["generation"])' "$line" 2>/dev/null || echo none)
(( started > g )) 2>/dev/null && pass "after the restart slot 1 launched generation $started > $g" \
  || fail "after the restart slot 1 launched: $started"

echo "== a. a delayed start never overturns a stop of the same generation"
systemctl stop tos-ci-supervisor.service
s=$(ask $'status 1\n'); L=$(field "$s" latest)
G=$((L + 1))
hold_lock 1 4
ask "down 1 $G"$'\n' > "$T/a-down" &
sleep 0.5
ask "up 1 $G"$'\n' > "$T/a-up" &
wait
echo "order down,up: down=$(cat "$T/a-down") up=$(cat "$T/a-up")"
[[ $(cat "$T/a-up") == "down wins" ]] && pass "the late up for generation $G answers 'down wins'" || fail "late up: $(cat "$T/a-up")"
s=$(ask $'status 1\n')
[[ $(field "$s" active) != active && $(field "$s" desired) == down ]] && pass "slot 1 is stopped, desired down" || fail "after down,up: $s"
G2=$((G + 1))
hold_lock 1 4
ask "up 1 $G2"$'\n' > "$T/b-up" &
sleep 0.5
ask "down 1 $G2"$'\n' > "$T/b-down" &
wait
echo "order up,down: up=$(cat "$T/b-up") down=$(cat "$T/b-down")"
s=$(ask $'status 1\n')
[[ $(field "$s" active) != active && $(field "$s" desired) == down ]] && pass "slot 1 ends stopped after up,down" || fail "after up,down: $s"
systemctl reset-failed tos-ci-vm@1.service 2> /dev/null
systemctl start tos-ci-supervisor.service

echo "== result: $fails failure(s)"
exit "$fails"
