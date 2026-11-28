#!/bin/bash
# Runbook gap reconciliation: one bounded batch per invocation, each result kept,
# until a batch reports caught_up. Stops on the first non-zero exit.
set -u
G=/tos/stablecoin-acceptance-logs/gap-reconciliation
OPS=/tos/worktrees/tos-ops/monitor-rpc-stale
for i in $(seq 1 1024); do
  out=$(sudo -n /tos/usdc-t5-tos/.venv/bin/python $OPS/testnet/scripts/reconcile-settlement-gap.py \
    --rpc http://127.0.0.1:18545 --binding /data/usdt-t15-monitor/binding.json \
    --state-dir /data/usdt-t15-monitor --gap-dir /data/usdt-t15-monitor-gap-20261128 --blocks 32)
  code=$?
  echo "$(date -u +%FT%TZ) batch $i exit=$code $out" >> $G/batches.log
  [ $code -eq 0 ] || { echo "batch $i failed"; exit 1; }
  echo "$out" | grep -q '"caught_up": true' && { echo "caught up after $i batches"; exit 0; }
done
echo "batch bound reached"; exit 1
