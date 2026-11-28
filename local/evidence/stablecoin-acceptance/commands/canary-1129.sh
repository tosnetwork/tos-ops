#!/bin/bash
# 29 Nov (UTC), hours 0-2: the remaining canary steps under the decided caps, then
# the lock-switch drill, the raise and a larger lock (which is also the resume after
# the switch), a post-raise window and the final reconciliation.
set -u
R=/tos/stablecoin-acceptance-tools/run.sh
L=/tos/stablecoin-acceptance-logs
M=1000000
log() { echo "$(date -u +%FT%TZ) $*" | tee -a $L/steps.log; }
wait_until() { until [ "$(date -u +%Y%m%d%H%M)" -ge "$1" ]; do sleep 10; done; }
for spec in "202611290001 a b" "202611290101 c d"; do
  set -- $spec
  wait_until $1
  for asset in usdc usdt; do
    for x in $2 $3; do
      $R lock $asset-canary-1129-$x --asset $asset --amount $((100*M)) --execute || exit 1
    done
  done
done
wait_until 202611290203
for i in 1 2 3; do $R observe canary-window-1129h2-$i --expect-clean || exit 1; [ $i -lt 3 ] && sleep 60; done
for asset in usdc usdt; do
  $R lock $asset-canary-1129-e --asset $asset --amount $((100*M)) --execute || exit 1
  $R probe $asset-canary-probe-daily --asset $asset --amount 1 --expect daily --execute || exit 1
  $R status $asset-balance-before-temp-total > /dev/null || exit 1
  BAL=$(python3 -c "import json;t=open('$L/$asset-balance-before-temp-total.log').read();print(json.loads(t[t.index('{'):])['$asset']['bridge_balance'])") || exit 1
  $R caps $asset-canary-temp-total --asset $asset --total $((BAL+50*M)) --per-lock $((100*M)) --hourly $((200*M)) --daily $((500*M)) --execute || exit 1
  $R probe $asset-canary-probe-total --asset $asset --amount $((100*M)) --expect total --execute || exit 1
done
# Bridge-wide lock switch: stop, both assets refused, allow.
$R switch-lock bridge-lock-stop --mode stop --execute || exit 1
$R probe usdc-bridge-stopped-probe --asset usdc --amount $M --expect paused --execute || exit 1
$R probe usdt-bridge-stopped-probe --asset usdt --amount $M --expect paused --execute || exit 1
$R switch-lock bridge-lock-allow --mode allow --execute || exit 1
# Raise, then a lock above the old per-lock cap: admitted, and the resume after the switch.
for asset in usdc usdt; do
  $R caps $asset-raised-caps --asset $asset --total $((10000*M)) --per-lock $((1000*M)) --hourly $((2000*M)) --daily $((5000*M)) --execute || exit 1
  $R lock $asset-raised-lock --asset $asset --amount $((150*M)) --execute || exit 1
done
sleep 90
for i in 1 2 3; do $R observe raised-window-1129h2-$i --expect-clean || exit 1; [ $i -lt 3 ] && sleep 60; done
$R reconcile final-reconcile --expect-reconciled || exit 1
log "29 Nov canary, lock-switch drill and raise complete"
