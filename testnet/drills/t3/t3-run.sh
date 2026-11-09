#!/usr/bin/env bash
# T3 drill runner (public-testnet T3 plan, section 5).
#
#   t3-run.sh S1|S2|S3|S4|S5|all [--dry-run]    print every command; execute nothing (default)
#   t3-run.sh S1|S2|S3|S4|S5 --execute          run the scenario against the testnet
#
# --execute holds $DEPLOY/u76af/upgrade.lock (flock, fd 9) for the whole run, refuses a
# drill tree with uncommitted changes, creates ${T3_EVIDENCE:-/datax/t3}/<run>/, runs
# t3-preflight.sh, then t3_run.py: sampler, mute, timed actions, deadlines, hard abort,
# abort ladder, log pulls, verdict.json and SHA256SUMS. Exit: 0 PASS (next handover
# pending), 1 FAIL, 2 INCONCLUSIVE or usage, 3/4 a pre-flight STOP.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
S=${1:-}; MODE=${2:---dry-run}
case "$S" in S1|S2|S3|S4|S5|all) ;; *) echo "usage: $0 S1|S2|S3|S4|S5|all [--dry-run|--execute]"; exit 2;; esac
case "$MODE" in --dry-run|--execute) ;; *) echo "usage: $0 S1..S5 [--dry-run|--execute]"; exit 2;; esac
[ $# -le 2 ] || { echo "usage: $0 S1..S5 [--dry-run|--execute]"; exit 2; }

if [ "$MODE" = --dry-run ]; then
  exec python3 -I "$HERE/t3_run.py" --dry-run "$S"
fi
[ "$S" != all ] || { echo "STOP: --execute runs one scenario at a time"; exit 2; }

DEPLOY=${T3_DEPLOY:-$HOME/tos-testnet-deploy/epoch-6/run}
EVIDENCE=${T3_EVIDENCE:-/datax/t3}
case "$EVIDENCE" in */build/*|*/build) echo "STOP: evidence must never go under a build/ directory"; exit 2;; esac
[ -z "$(git -C "$HERE" status --porcelain -- .)" ] || { echo "STOP: uncommitted changes in $HERE"; exit 3; }
T3_COMMIT=$(git -C "$HERE" rev-parse HEAD); export T3_COMMIT

exec 9>"$DEPLOY/u76af/upgrade.lock"
flock -n 9 || { echo "STOP: upgrade lock held"; exit 3; }
RUN=t3-$(date -u +%Y%m%dT%H%MZ)-$S
OUT=$EVIDENCE/$RUN
[ ! -e "$OUT" ] || { echo "STOP: $OUT exists"; exit 3; }
mkdir -p "$OUT"
echo "$T3_COMMIT" > "$OUT/tos-ops-commit.txt"
export RUN T3_DEPLOY=$DEPLOY T3_EVIDENCE=$EVIDENCE T3_LOCK_HELD=1
set +e
"$HERE/t3-preflight.sh" "$S" 2>&1 | tee "$OUT/preflight.txt"
rc=${PIPESTATUS[0]}
set -e
[ "$rc" = 0 ] || { echo "STOP: pre-flight refused ($rc); nothing was changed"; exit "$rc"; }
python3 -I "$HERE/t3_run.py" --execute "$S" "$RUN"
