#!/bin/bash
set -euo pipefail
exec sudo /tos/usdc-t5-tos/.venv/bin/python /tos/worktrees/tos-ops/monitor-rpc-stale/local/scripts/local-settlement-monitor.py --data /data --source-state /data/usdc/state.json --asset-state /data/usdt-t15/state.json --source-pin /tos/usdt-t15-driver-evidence/source-bridge-pin.json --artifact /tos/usdt-t15-driver-evidence/artifacts/LocalUSDT.sol/LocalUSDT.json --build-log /tos/usdt-t15-driver-evidence/compile-current.log --state /data/usdt-t15-monitor "$@"
