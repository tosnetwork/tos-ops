#!/bin/bash
# Settle the admitted exact-amount request through its real deadlines: expire
# after the response deadline, the buyer claims the refund, a second resolver verifies.
set -u
T=/tos/stablecoin-acceptance-tools/t10-usdt.sh
L=/tos/stablecoin-acceptance-logs
log() { echo "$(date -u +%FT%TZ) $*" | tee -a $L/steps.log; }
t10() { name=$1; shift; $T "$@" > $L/$name.log 2>&1; c=$?; log "t10 $name exit=$c"; tail -n 2 $L/$name.log; return $c; }
ID=$(sudo -n python3 -c "import json;d=json.load(open('/data/service-token-usdt-t18/evidence/verify-fee-minted-1000000.json'));r=d['requests'];assert len(r)==1 and r[0]['state']=='pending';print(r[0]['request_id'])") || exit 1
BUYER=0:14eda362e0cb32fc910daa87ffd1f7840ae8a152275fe36451a4d51422484979
# The response window is 600 s from the call: wait it out (plus margin) so the
# guarded expire never refuses early under this one-shot case name.
CALLED=$(grep 't10 fee-minted-call exit=0' $L/steps.log | tail -n 1 | cut -d' ' -f1)
[ -n "$CALLED" ] || exit 1
until [ $(date -u +%s) -ge $(( $(date -u -d "$CALLED" +%s) + 700 )) ]; do sleep 10; done
t10 fee-minted-expire send --case fee-minted-expire --sender-wallet buyer --operation expire --request-id "$ID" || exit 1
sleep 20
t10 fee-minted-refund send --case fee-minted-refund --sender-wallet buyer --operation claim-refund --request-id "$ID" --destination "$BUYER" || exit 1
sleep 40
t10 fee-minted-verify-refunded verify --case fee-minted-1000000 --expect-state refunded --resolver-rpc http://127.0.0.1:19014/jsonRPC,http://127.0.0.1:19015/jsonRPC,http://127.0.0.1:19016/jsonRPC || exit 1
log "fee refund complete"
