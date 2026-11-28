#!/bin/bash
# Hours 0 and 1 of 28 Nov (UTC): two 100-token locks per asset per hour.
set -u
R=/tos/stablecoin-acceptance-tools/run.sh
L=/tos/stablecoin-acceptance-logs
wait_until() { until [ "$(date -u +%Y%m%d%H%M)" -ge "$1" ]; do sleep 10; done; }
wait_drill() { until grep -q "emergency drill resolved" $L/steps.log; do sleep 10; done; }
wait_idle() { while pgrep -f 'fee-drill.sh' >/dev/null || pgrep -f 'local-pq-stablecoin-acceptance.py' >/dev/null; do sleep 5; done; }
for spec in "202611280001 a b" "202611280101 c d"; do
  set -- $spec
  wait_until $1; wait_drill; wait_idle
  for asset in usdc usdt; do
    for x in $2 $3; do
      $R lock $asset-canary-1128-$x --asset $asset --amount 100000000 --execute || exit 1
    done
  done
done
echo "$(date -u +%FT%TZ) canary hours 0-1 complete" | tee -a $L/steps.log
