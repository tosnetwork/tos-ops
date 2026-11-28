#!/bin/bash
# Resolution and resume, after the recovery reads above.
set -u
R=/tos/stablecoin-acceptance-tools/run.sh
L=/tos/stablecoin-acceptance-logs
TOOLS=/tos/stablecoin-acceptance-tools
BIN=/tos/usdt-t15-driver-evidence/bin
PY="sudo -n env TOS_ROOT=/tos/usdc-t5-tos $HOME/tos/.venv/bin/python"
M=1000000
log() { echo "$(date -u +%FT%TZ) $*" | tee -a $L/steps.log; }
step() { name=$1; shift; "$@" > $L/$name.log 2>&1; c=$?; log "$name exit=$c"; tail -n 3 $L/$name.log; return $c; }
$R resolve-incident usdt-incident-resolution --incident usdt:bridge_frozen \
  --authorization "stablecoin final acceptance (memo decision 32): resolve this drill's own bridge_frozen latch after unblacklist and re-enable" --execute || exit 1
sleep 30
$R observe emergency-resolved-1 --expect-clean || exit 1
step provider-resume-usdt sudo -n python3 $TOOLS/provider-action.py emergency-resume /data/service-token-usdt-t18/published-provider.json \
  0:dab3c57e833459f6b2481148009a8c0817540da8cfc1e64248be612f1fe06df3 resume $BIN/tos-service-provider-state || exit 1
sleep 20
step emergency-policies-resumed $PY $TOOLS/actor-policies.py emergency-policies-resumed || exit 1
$R lock usdt-after-recovery --asset usdt --amount $((10*M)) --execute || exit 1
sleep 90
for i in 1 2 3; do $R observe emergency-resolved-window-$i --expect-clean || exit 1; [ $i -lt 3 ] && sleep 60; done
$R reconcile after-emergency-reconcile --expect-reconciled || exit 1
log "emergency drill resolved"
