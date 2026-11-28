#!/bin/bash
# The token-actor driver for the existing T18 USDT actor, with tools built from ai main.
exec sudo python3 /tos/stablecoin-acceptance-tools/with-env.py /tos/usdc-t5-tos/.venv/bin/python \
  /tos/worktrees/tos-ops/stablecoin-acceptance/local/scripts/local-pq-service-token.py "$@" \
  --bridge-state /data/usdt-t15 --state /data/service-token-usdt-t18 --running-tos /tos/usdc-t5-tos \
  --tools-tos /tos/usdc-t10-tos --fixture /tos/stablecoin-acceptance-tools/service-actor-token-e2e-fixture \
  --tosctl /tos/usdc-t10-evidence/installed/tosctl --verifier /tos/stablecoin-acceptance-tools/tos-service-verify \
  --provider-runtime /tos/stablecoin-acceptance-tools/tos-service-provider \
  --capability-id cap_5555555555555555555555555555555555555555555555555555555555555555
