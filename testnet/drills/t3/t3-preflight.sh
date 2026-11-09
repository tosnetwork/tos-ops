#!/usr/bin/env bash
# T3 pre-flight (plan v2 section 4): every check fails closed with a STOP line and a
# non-zero exit; nothing is changed on any host. Usage: RUN=<run> t3-preflight.sh S1..S4
# t3-run.sh calls it while holding the upgrade lock on fd 9 (T3_LOCK_HELD=1); standalone,
# it takes the lock itself. Evidence: ${T3_EVIDENCE:-/datax/t3}/$RUN/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LIB=$HERE/t3_lib.py
stop() { echo "STOP: $1"; exit "${2:-3}"; }
S=${1:-}
case "$S" in S1|S2|S3|S4) ;; *) echo "usage: RUN=<run> $0 S1|S2|S3|S4"; exit 2;; esac
RUN=${RUN:?set by t3-run.sh}
case "$RUN" in t3-*-"$S") ;; *) stop "RUN $RUN is not t3-<time>-$S" 2;; esac
DEPLOY=${T3_DEPLOY:-$HOME/tos-testnet-deploy/epoch-6/run}
OUT=${T3_EVIDENCE:-/datax/t3}/$RUN
case "$OUT" in */build/*|*/build) stop "evidence must never go under a build/ directory" 2;; esac

python3 -I "$LIB" pins-ok "$HERE/pins.sha256" "$DEPLOY" || stop "pinned outside scripts"
echo "GATE pinned outside scripts: ok"
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
echo "GATE upgrade lock held by this run: ok"
! systemctl --user is-active -q e6-u76af-rollout5 e6-u76af-rollout4 e6-u76af-rollout3 \
  || stop "rollout unit active"
echo "GATE no rollout unit active: ok"
grep -q 'u76af rollout ACCEPTED' "$E/run/RUN-LOG.md" || stop "rollout not accepted"
echo "GATE rollout accepted: ok"
# The rollout acceptance handovers (2026-11-09 21:18:07 and 23:18:07).
for b in 1794259087 1794266287; do
  d=$(date -u -d @"$b" +%Y%m%d-%H)18
  python3 -I "$LIB" classify-ok "$HD/handover-$d/CLASSIFY.json" "$b" || stop "acceptance handover $d"
  echo "GATE acceptance handover $d PASS: ok"
done

# ConfigParam 34 from two sources, then every recorded gate (gates-pre.json): window and term
# left (full hard-abort budget before the recovery deadline and the next odd-hour :12), the
# current term's handover verdict (four sources), 4 equal weights, ConfigParam 36 absent and
# active_election_id 0, fresh advancing heads, each host's facts (each unit's rc, the restart
# policy, the version, the ledger binding, tools, endpoints), the clocks and the identities.
python3 "$U/current-term.py" "$OUT/term.json" || stop "current term not read"
python3 -I "$HERE/t3_run.py" --gates "$S" "$RUN" || stop "gate"

{ echo "== toserver validator-engine (a local net skews the observer)"; pgrep -ax validator-engin || echo none
  echo "== df /datax"; df -h /datax; } > "$OUT/pre-notes.txt"
echo "PREFLIGHT PASS $S $RUN $(date -u +%FT%TZ)"
