#!/bin/bash
set -u
R=/tos/stablecoin-acceptance-tools/run.sh
T=/tos/stablecoin-acceptance-tools/t10-usdt.sh
L=/tos/stablecoin-acceptance-logs
RECEIVER=0x90f79bf6eb2c4f870365e785982e1f101e93b906
log() { echo "$(date -u +%FT%TZ) $*" | tee -a $L/steps.log; }
t10() { name=$1; shift; $T "$@" > $L/$name.log 2>&1; c=$?; log "t10 $name exit=$c"; tail -n 2 $L/$name.log; return $c; }
preview() {
  /tos/stablecoin-acceptance-tools/token-lock-preview --policy /tos/stablecoin-acceptance-tools/conf/usdt-issuer-policy.json \
    --master 0:181e00fdfea5eeccb099b2ede160375e206de7d466a8bc6b4c79557781759591 \
    --actor 0:dab3c57e833459f6b2481148009a8c0817540da8cfc1e64248be612f1fe06df3 \
    --nominal "$2" --price 1000000 --max-per-call 10000000 --max-window 10000000 > $L/$1.json 2> $L/$1.err
  c=$?; log "preview $1 exit=$c"; cat $L/$1.json; return $c
}
RT=http://127.0.0.1:19014/jsonRPC,http://127.0.0.1:19015/jsonRPC,http://127.0.0.1:19016/jsonRPC
t10 fee-minted-call call --case fee-minted-1000000 --funding-atomic 1000000 || exit 1
sleep 30
t10 fee-minted-verify verify --case fee-minted-1000000 --expect-state pending --resolver-rpc $RT || exit 1
$R burn usdt-burn-fee-on --asset usdt --amount 2000000 --receiver $RECEIVER --execute || exit 1
$R unlock usdt-unlock-fee-on --asset usdt --burn usdt-burn-fee-on --receiver $RECEIVER --execute || exit 1
$R issuer usdt-fee-off --asset usdt --op set-fee --basis-points 0 --max-fee 0 --execute || exit 1
preview t19-lock-preview-fee-off 1000000 || exit 1
$R burn usdt-burn-fee-off --asset usdt --amount 1000000 --receiver $RECEIVER --execute || exit 1
$R unlock usdt-unlock-fee-off --asset usdt --burn usdt-burn-fee-off --receiver $RECEIVER --execute || exit 1
log "fee drill complete"
