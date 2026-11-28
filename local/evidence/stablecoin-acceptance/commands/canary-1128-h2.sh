#!/bin/bash
# Hour 2 of 28 Nov: clean window, the daily-cap refusal, the total-cap refusal under
# a temporarily lowered total, the raise vote, a larger lock, a clean window, then
# the bridge-wide lock switch drill.
set -u
R=/tos/stablecoin-acceptance-tools/run.sh
L=/tos/stablecoin-acceptance-logs
M=1000000
until [ "$(date -u +%Y%m%d%H%M)" -ge 202611280203 ]; do sleep 10; done
until grep -q 'canary hours 0-1 complete' $L/steps.log; do sleep 10; done
for i in 1 2 3; do $R observe canary-window-1128h2-$i --expect-clean || exit 1; [ $i -lt 3 ] && sleep 60; done
for asset in usdc usdt; do
  $R lock $asset-canary-1128-e --asset $asset --amount $((100*M)) --execute || exit 1
  $R probe $asset-canary-probe-daily --asset $asset --amount 1 --expect daily --execute || exit 1
  $R status $asset-balance-before-temp-total > /dev/null || exit 1
  BAL=$(python3 -c "import json,sys;t=open('$L/$asset-balance-before-temp-total.log').read();print(json.loads(t[t.index('{'):])['$asset']['bridge_balance'])") || exit 1
  $R caps $asset-canary-temp-total --asset $asset --total $((BAL+50*M)) --per-lock $((100*M)) --hourly $((200*M)) --daily $((500*M)) --execute || exit 1
  $R probe $asset-canary-probe-total --asset $asset --amount $((100*M)) --expect total --execute || exit 1
  $R caps $asset-raised-caps --asset $asset --total $((10000*M)) --per-lock $((1000*M)) --hourly $((2000*M)) --daily $((5000*M)) --execute || exit 1
  $R lock $asset-raised-lock --asset $asset --amount $((150*M)) --execute || exit 1
done
sleep 90
for i in 1 2 3; do $R observe raised-window-1128h2-$i --expect-clean || exit 1; [ $i -lt 3 ] && sleep 60; done
$R switch-lock bridge-lock-stop --mode stop --execute || exit 1
$R probe usdc-bridge-stopped-probe --asset usdc --amount $M --expect paused --execute || exit 1
$R probe usdt-bridge-stopped-probe --asset usdt --amount $M --expect paused --execute || exit 1
$R switch-lock bridge-lock-allow --mode allow --execute || exit 1
$R lock usdc-after-lock-switch --asset usdc --amount $((10*M)) --execute || exit 1
$R lock usdt-after-lock-switch --asset usdt --amount $((10*M)) --execute || exit 1
echo "$(date -u +%FT%TZ) hour-2 canary and lock-switch drill complete" | tee -a $L/steps.log
