#!/bin/bash
# Live controls for the verification-mode audit archive (run as root, supervisor
# running in audit mode, at least one audited lifetime already archived):
#   1. truncation of a real, valid archive: cut before its end marker is
#      invalid, cut after it is still valid;
#   2. pruning keeps an active (locked) archive and removes the oldest closed
#      files down to the budget;
#   3. a closed file that cannot be removed keeps the bound from being reached,
#      so the slot's VM refuses to start, and recovers once it can be removed.
set -uo pipefail
[[ $EUID == 0 ]] || { echo "run as root" >&2; exit 2; }
fails=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }
HERE=$(cd "$(dirname "$0")" && pwd)
ARCHIVE=/var/lib/tos-ci/audit
now() { date -u '+%Y-%m-%d %H:%M:%S UTC'; }

echo "== 1. truncating a real archive"
python3 -I - "$HERE/audit-check.py" "$ARCHIVE" <<'EOF'
import importlib.machinery, importlib.util, re, sys
from pathlib import Path
loader = importlib.machinery.SourceFileLoader("check", sys.argv[1])
spec = importlib.util.spec_from_loader("check", loader)
check = importlib.util.module_from_spec(spec); loader.exec_module(check)
for path in sorted(Path(sys.argv[2]).glob("slot*/*.log"), reverse=True):
    data = path.read_bytes()
    m = re.search(rb"tos-ci-audit-end nonce=([0-9a-f]{32})", data)
    if m and not check.evidence(data, m.group(1).decode())[0]:
        break
else:
    print("FAIL  no valid archive to truncate"); sys.exit(1)
nonce = m.group(1).decode()
marker_line = data.rfind(b"\n", 0, m.start()) + 1
end_of_marker = data.index(b"\n", m.end()) + 1
cases = {
    "cut just before the marker line": (data[:marker_line], False),
    "cut inside the marker line": (data[: m.start() + 10], False),
    "cut right after the marker": (data[:end_of_marker], True),
    "the full archive": (data, True),
}
bad = 0
for name, (cut, valid) in cases.items():
    problems = check.evidence(cut, nonce)[0]
    ok = (not problems) == valid
    bad += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {path.name}: {name}: {'valid' if not problems else problems[0]}")
sys.exit(bad)
EOF
fails=$((fails + $?))

echo "== 2. pruning around an active archive"
active=""
for _ in $(seq 60); do
  for f in "$ARCHIVE"/slot*/*.log; do
    [[ -e $f ]] || continue
    if ! flock -n -x "$f" true; then active=$f; break 2; fi
  done
  sleep 5
done
[[ -n $active ]] && pass "found an active archive: $active" || { fail "no active archive"; exit "$fails"; }
before=$(stat -c %Y "$active")
# Closed files, oldest first, totalling 6 GiB (sparse): the oldest must go.
for i in 1 2 3; do
  f="$ARCHIVE/slot3/00000000T00000$i.000000Z-control.log"
  truncate -s 2G "$f"
  touch -d "2000-01-0$i" "$f"
done
touch -d "1999-01-01" "$active"  # the active file is now the oldest of all
python3 -I /usr/lib/tos-ci/audit-prune 3
[[ -e $active ]] && pass "the active archive survived pruning although oldest" || fail "an active archive was pruned"
touch -d "@$before" "$active" 2> /dev/null
[[ ! -e "$ARCHIVE/slot3/00000000T000001.000000Z-control.log" ]] && pass "the oldest closed file was removed" \
  || fail "the oldest closed file survived"
total=$(find "$ARCHIVE" -name '*.log' -exec flock -n -x {} true \; -printf '%s\n' | awk '{s += $1} END {print s + 0}')
(( total <= 5 * 1024 ** 3 )) && pass "closed archives total $total bytes, within 5 GiB" || fail "closed total $total"
rm -f "$ARCHIVE"/slot3/*-control.log

echo "== 3. an unremovable closed file keeps the VM from starting"
f="$ARCHIVE/slot1/00000000T000000.000000Z-immutable.log"
truncate -s 6G "$f"
touch -d "2000-01-01" "$f"
chattr +i "$f"
mark=$(now)
touch /etc/tos-ci/drain; sleep 20; rm -f /etc/tos-ci/drain  # recycle slot 1 so it launches again
for _ in $(seq 40); do
  journalctl -u tos-ci-vm@1 --since "$mark" -o cat --no-pager | grep -q "audit-prune: cannot remove" && break
  sleep 5
done
journalctl -u tos-ci-vm@1 --since "$mark" -o cat --no-pager | grep -q "audit-prune: cannot remove" \
  && pass "slot 1's pruner refused the unremovable file" || fail "no prune refusal for slot 1"
journalctl -u tos-ci-supervisor --since "$mark" -o cat --no-pager | grep '"slot_started"' | grep -q '"slot": 1' \
  && fail "slot 1 started although its archive could not be bounded" || pass "slot 1 did not start"
chattr -i "$f"
mark2=$(now)
for _ in $(seq 60); do
  journalctl -u tos-ci-supervisor --since "$mark2" -o cat --no-pager | grep '"slot_started"' | grep -q '"slot": 1' && break
  sleep 10
done
[[ ! -e $f ]] && pass "once removable, the file was pruned" || { fail "the file is still there"; rm -f "$f"; }
journalctl -u tos-ci-supervisor --since "$mark2" -o cat --no-pager | grep '"slot_started"' | grep -q '"slot": 1' \
  && pass "slot 1 recovered" || fail "slot 1 did not recover"

echo "== result: $fails failure(s)"
exit "$fails"
