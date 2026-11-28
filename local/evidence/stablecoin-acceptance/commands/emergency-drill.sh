#!/bin/bash
# The USDT freeze drill on the running local services, end to end.
set -u
R=/tos/stablecoin-acceptance-tools/run.sh
L=/tos/stablecoin-acceptance-logs
TOOLS=/tos/stablecoin-acceptance-tools
BIN=/tos/usdt-t15-driver-evidence/bin
PY="sudo -n env TOS_ROOT=/tos/usdc-t5-tos $HOME/tos/.venv/bin/python"
M=1000000
RECEIVER=0x90f79bf6eb2c4f870365e785982e1f101e93b906
USDT_ACTOR=0:dab3c57e833459f6b2481148009a8c0817540da8cfc1e64248be612f1fe06df3
USDT_RAIL=/data/service-token-usdt-t18/published-provider.json
USDC_RAIL=/data/service-token-usdc-control-t18/published-provider.json
log() { echo "$(date -u +%FT%TZ) $*" | tee -a $L/steps.log; }
step() { name=$1; shift; "$@" > $L/$name.log 2>&1; c=$?; log "$name exit=$c"; tail -n 3 $L/$name.log; return $c; }
expect_refusal() { name=$1; text=$2; shift 2; "$@" > $L/$name.log 2>&1; c=$?;
  if [ $c -ne 0 ] && grep -q "$text" $L/$name.log; then log "$name refused as expected"; return 0; fi
  log "$name NOT refused as expected (exit=$c)"; tail -n 3 $L/$name.log; return 1; }

step emergency-policies-before $PY $TOOLS/actor-policies.py emergency-policies-before || exit 1
$R issuer usdt-blacklist-bridge --asset usdt --op blacklist-bridge --execute || exit 1
sleep 90
$R observe emergency-frozen-monitor --expect-alarm usdt:bridge_frozen || exit 1
# Buyer side: the T19 issuer reads refuse the frozen asset before any lock or burn.
expect_refusal buyer-lock-preview-refused "blacklisted" $TOOLS/token-lock-preview \
  --policy $TOOLS/conf/usdt-issuer-policy.json \
  --master 0:181e00fdfea5eeccb099b2ede160375e206de7d466a8bc6b4c79557781759591 \
  --actor $USDT_ACTOR --nominal $M --price $M --max-per-call 10000000 --max-window 10000000 || exit 1
expect_refusal redemption-refused-frozen "blacklisted" $R burn usdt-burn-during-freeze --asset usdt \
  --amount $M --receiver $RECEIVER || exit 1
# Provider side: the production auto-pause API pauses only the alarmed asset's actors.
step provider-auto-pause-usdt sudo -n python3 $TOOLS/with-env.py $BIN/provider-monitor-apply --execute --config $USDT_RAIL || exit 1
step provider-auto-pause-usdc sudo -n python3 $TOOLS/with-env.py $BIN/provider-monitor-apply --execute --config $USDC_RAIL || exit 1
sleep 20
step emergency-policies-paused $PY $TOOLS/actor-policies.py emergency-policies-paused || exit 1
# Source-side stop: the oracle quorum disables the token; USDC keeps locking.
$R disable usdt-disable-token --asset usdt --mode disable --execute || exit 1
$R probe usdt-disabled-probe --asset usdt --amount $M --expect disabled --execute || exit 1
$R lock usdc-during-usdt-freeze --asset usdc --amount $((10*M)) --execute || exit 1
# Recovery: unblacklist, re-enable by vote, resolve the latch, resume the actor.
$R issuer usdt-unblacklist-bridge --asset usdt --op unblacklist-bridge --execute || exit 1
$R disable usdt-enable-token --asset usdt --mode enable --execute || exit 1
sleep 90
$R observe emergency-recovered-latched || exit 1
sudo -n python3 -c "import json;d=json.load(open('/data/stablecoin-acceptance/evidence/emergency-recovered-latched.json'));r=d['report'];assert 'usdt:bridge_frozen' in r['latched_incidents'] and r['provider_pause_assets']==['usdt'] and not any(a['code']=='bridge_frozen' for a in r['alarms']), r" || { log "latch check failed"; exit 1; }
log "latch persists after recovery, alarm itself cleared"
echo "$(date -u +%FT%TZ) emergency drill reached resolution" | tee -a $L/steps.log
