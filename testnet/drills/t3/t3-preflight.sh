#!/usr/bin/env bash
# T3 pre-flight (plan section 4): every check fails closed with a STOP line and a
# non-zero exit; nothing is changed on any host. Usage: RUN=<run> t3-preflight.sh S1..S5
# t3-run.sh calls it while holding the upgrade lock on fd 9 (T3_LOCK_HELD=1); standalone,
# it takes the lock itself. Evidence: ${T3_EVIDENCE:-/datax/t3}/$RUN/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LIB=$HERE/t3_lib.py
stop() { echo "STOP: $1"; exit "${2:-3}"; }
S=${1:-}
case "$S" in S1|S2|S3|S4|S5) ;; *) echo "usage: RUN=<run> $0 S1|S2|S3|S4|S5"; exit 2;; esac
RUN=${RUN:?set by t3-run.sh}
case "$RUN" in t3-*-"$S") ;; *) stop "RUN $RUN is not t3-<time>-$S" 2;; esac
DEPLOY=${T3_DEPLOY:-$HOME/tos-testnet-deploy/epoch-6/run}
OUT=${T3_EVIDENCE:-/datax/t3}/$RUN
case "$OUT" in */build/*|*/build) stop "evidence must never go under a build/ directory" 2;; esac

python3 -I "$LIB" pins-ok "$HERE/pins.sha256" "$DEPLOY" || stop "pinned outside scripts"
# shellcheck disable=SC1091
. "$DEPLOY/helpers.sh"
U=$E/run/u76af; HD=$E/run/remote-reval-20261105
mkdir -p "$OUT"

# The upgrade lock, held for the whole run by t3-run.sh (fd 9 inherited: same open file
# description, so flock succeeds there and nowhere else).
if [ "${T3_LOCK_HELD:-}" = 1 ]; then
  [ "$(readlink -f /proc/$$/fd/9 2>/dev/null)" = "$(readlink -f "$U/upgrade.lock")" ] \
    || stop "T3_LOCK_HELD set but fd 9 is not $U/upgrade.lock"
  flock -n 9 || stop "upgrade lock held"
else
  exec 9>"$U/upgrade.lock"; flock -n 9 || stop "upgrade lock held"
fi
! systemctl --user is-active -q e6-u76af-rollout5 e6-u76af-rollout4 e6-u76af-rollout3 \
  || stop "rollout unit active"
grep -q 'u76af rollout ACCEPTED' "$E/run/RUN-LOG.md" || stop "rollout not accepted"
# The rollout acceptance handovers (2026-11-09 21:18:07 and 23:18:07).
for b in 1794259087 1794266287; do
  d=$(date -u -d @"$b" +%Y%m%d-%H)18
  python3 -I "$LIB" classify-ok "$HD/handover-$d/CLASSIFY.json" "$b" || stop "acceptance handover $d"
done

# ConfigParam 34 from two sources, then the term, election-window and handover gates,
# including the current term's own handover verdict (four sources) and the remote lane's
# odd-hour :12-:27 rule.
python3 "$U/current-term.py" "$OUT/term.json" || stop "current term not read"
python3 -I "$LIB" gate "$OUT/term.json" "$S" "$HD" || stop "gate"

# No next set (ConfigParam 36 absent) and active_election_id == 0 on 18081 (validator-step.sh:30-37).
python3 - 18081 <<'PY' || stop "ConfigParam 36 published or an election is active"
import json, sys, urllib.request
url = f'http://127.0.0.1:{sys.argv[1]}/jsonRPC'
req = urllib.request.Request(url, json.dumps(dict(jsonrpc='2.0', id=1, method='getConfigParam', params=dict(param=36))).encode(), {'Content-Type': 'application/json'})
d = json.load(urllib.request.urlopen(req, timeout=15)); assert 'error' in d and 'CONFIG_PARAM_ABSENT' in str(d['error']), 'next set published: postpone'
req = urllib.request.Request(url, json.dumps(dict(jsonrpc='2.0', id=2, method='runGetMethod', params=dict(address='-1:' + '3' * 64, method='active_election_id', stack=[]))).encode(), {'Content-Type': 'application/json'})
r = json.load(urllib.request.urlopen(req, timeout=15))['result']; assert r['exit_code'] == 0 and int(r['stack'][0][1], 0) == 0, 'active election: postpone'
print('no next set, no active election')
PY

for p in 18081 38081 28081 48084; do
  curl -s -m10 -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getMasterchainInfo","params":{}}' "http://127.0.0.1:$p/jsonRPC"; echo
done > "$OUT/heads.json"
python3 -c 'import json,sys;h=[json.loads(l)["result"]["last"]["seqno"] for l in open(sys.argv[1])];assert len(h)==4 and max(h)-min(h)<=5,h' \
  "$OUT/heads.json" || stop "the four heads are not within 5 blocks"
python3 - <<'PY' || stop "a head is older than 30 s"
import json, time, urllib.request
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for port in (18081, 38081, 28081, 48084):
    req = urllib.request.Request(f'http://127.0.0.1:{port}/jsonRPC', json.dumps(dict(jsonrpc='2.0', id=1, method='getConsensusBlock', params={})).encode(), {'Content-Type': 'application/json'})
    age = time.time() - int(json.load(op.open(req, timeout=10))['result']['last_block_utime'])
    assert age < 30, (port, age)
print('head age < 30 s on all four')
PY
python3 "$U/block-rate.py" 18081 38081 300 > "$OUT/R0.json" || stop "R0 not measured"
python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));assert r["rate"]>0,r' "$OUT/R0.json" || stop "R0 is zero"

for n in $VALIDATORS; do
  on "$n" "bash -s -- $n" < "$HERE/t3-host-check.sh" > "$OUT/pre-$n.txt" || stop "host check on $n failed" 4
  python3 -I "$LIB" check-pre "$S" "$n" "$OUT/pre-$n.txt" || stop "host check on $n" 4
done

{ echo "== toserver validator-engine (a local net skews the observer)"; pgrep -ax validator-engin || echo none
  echo "== df /datax"; df -h /datax; } > "$OUT/pre-notes.txt"
echo "PREFLIGHT PASS $S $RUN $(date -u +%FT%TZ)"
