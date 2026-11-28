#!/bin/bash
# One acceptance step; its full output is kept under the log directory.
set -o pipefail
step=$1; label=$2; shift 2
cd /tos/worktrees/tos-ops/stablecoin-acceptance || exit 2
sudo -n env TOS_ROOT=/tos/usdc-t5-tos $HOME/tos/.venv/bin/python \
  local/scripts/local-pq-stablecoin-acceptance.py "$step" --label "$label" "$@" \
  --state /data/stablecoin-acceptance --tos-root /tos/usdc-t5-tos \
  --cast $HOME/.foundry/bin/cast > "/tos/stablecoin-acceptance-logs/$label.log" 2>&1
code=$?
echo "$(date -u +%FT%TZ) $step $label exit=$code" | tee -a /tos/stablecoin-acceptance-logs/steps.log
tail -n 2 "/tos/stablecoin-acceptance-logs/$label.log"
exit $code
