#!/bin/bash
# Remaining acceptance, redesigned to run within one UTC hour (owner instruction
# 2026-11-28): the daily and total refusals under temporarily lowered caps, the
# return to the canary caps, the lock-switch drill, the raise, a larger lock
# (also the resume after the switch), a short clean window and reconciliation.
set -u
R=/tos/stablecoin-acceptance-tools/run.sh
L=/tos/stablecoin-acceptance-logs
M=1000000
log() { echo "$(date -u +%FT%TZ) $*" | tee -a $L/steps.log; }
facts() { $R status "$1" > /dev/null || exit 1
  python3 -c "import json;t=open('$L/$1.log').read();d=json.loads(t[t.index('{'):])['$2'];print(d['$3'] if '$3'!='day_used' else d['cap']['day_used'])"; }
for i in 1 2 3; do $R observe finish-window-before-$i --expect-clean || exit 1; [ $i -lt 3 ] && sleep 30; done
for asset in usdc usdt; do
  DAY=$(facts $asset-day-before-daily-lowering $asset day_used) || exit 1
  # Daily lowered to today's use + 50: a 100 lock passes per-lock, total and hourly, and fails daily.
  $R caps $asset-daily-lowered --asset $asset --total $((1000*M)) --per-lock $((100*M)) --hourly $((200*M)) --daily $((DAY+50*M)) --execute || exit 1
  $R probe $asset-daily-probe --asset $asset --amount $((100*M)) --expect daily --execute || exit 1
  BAL=$(facts $asset-balance-before-total-lowering $asset bridge_balance) || exit 1
  # Total lowered to the balance + 50: a 100 lock fails the token cap (checked before the rate caps).
  $R caps $asset-total-lowered --asset $asset --total $((BAL+50*M)) --per-lock $((100*M)) --hourly $((200*M)) --daily $((500*M)) --execute || exit 1
  $R probe $asset-total-probe --asset $asset --amount $((100*M)) --expect total --execute || exit 1
  $R caps $asset-canary-restored --asset $asset --total $((1000*M)) --per-lock $((100*M)) --hourly $((200*M)) --daily $((500*M)) --execute || exit 1
  $R probe $asset-over-canary-per-lock --asset $asset --amount $((150*M)) --expect per-lock --execute || exit 1
done
$R switch-lock bridge-lock-stop --mode stop --execute || exit 1
$R probe usdc-bridge-stopped-probe --asset usdc --amount $M --expect paused --execute || exit 1
$R probe usdt-bridge-stopped-probe --asset usdt --amount $M --expect paused --execute || exit 1
$R switch-lock bridge-lock-allow --mode allow --execute || exit 1
for asset in usdc usdt; do
  $R caps $asset-raised-caps --asset $asset --total $((10000*M)) --per-lock $((1000*M)) --hourly $((2000*M)) --daily $((5000*M)) --execute || exit 1
  $R lock $asset-raised-lock --asset $asset --amount $((150*M)) --execute || exit 1
done
sleep 90
for i in 1 2 3; do $R observe raised-window-$i --expect-clean || exit 1; [ $i -lt 3 ] && sleep 45; done
$R reconcile final-reconcile --expect-reconciled || exit 1
log "remaining acceptance complete"
