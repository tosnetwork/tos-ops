#!/usr/bin/env bash
# Rehearse the whole public testnet ceremony on one host, unprivileged, on
# loopback, and check that the resulting chain produces blocks.
#
#   TOS_ROOT=<tos checkout> TOS_BUILD=<its build dir> rehearse-loopback.sh WORKDIR [SECONDS]
#
# REHEARSAL_PROFILE names another network profile (default network/profile.json),
# such as network/profile-production-timing.json for a rehearsal of the bootstrap
# flow at production ConfigParam 15 timing; genesis, pool and the node copies all
# read it. A profile whose elections.external_validators is still null is
# planned for no external validators into WORKDIR/profile.json first
# (testnet-coordinator.py plan --write); the rehearsal runs the genesis set only.
#
# With REHEARSAL_HOLD_SECONDS=N the network stays up for N seconds after the
# check passes, for fault experiments: each validator's exact command is in
# WORKDIR/node-<i>.start and its PID in WORKDIR/node-<i>.pid, so one can be
# stopped and later restarted with `bash WORKDIR/node-<i>.start &`. Every
# process, restarted ones included, is stopped on exit.
#
# It runs the same scripts the operators and the coordinator run, in the same
# order, with one operator per genesis validator (genesis.validators), two DHT
# nodes and the testnet global id from network/profile.json:
#
#   operators   first start on a placeholder config, consensus seed generated
#               in the node directory
#   coordinator pool: the offline owner and the staking pool of each operator
#               wallet, whose id the operator's record names
#   operators   public record
#   coordinator manifest, genesis (run twice and compared, ConfigParam 48 read
#               back) with the profile's AUTH network tag in
#               TOS_AUTH_NETWORK_TAG, global config
#   operators   zero state placed, bind-node, console added, engine started
#   checker     check-testnet.py: one zero state, one full block id at the
#               common head, the testnet global id, ConfigParam 34 = the
#               genesis set's identities, live ConfigParam 48 = the genesis tag,
#               mandatory and critical
#
# Differences from a real ceremony, all forced by running on one host: the
# addresses are 127.0.0.1 (TESTNET_REHEARSAL_ALLOW_PRIVATE=1), each node gets
# its own port block through a per-node copy of the profile, and each
# operator wallet is a fixed placeholder address instead of the one
# init-operator.sh --wallet-only creates on a host (nothing is staked here).
# WORKDIR must not exist.
# Every process it starts is stopped on exit.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TESTNET="$(dirname "$HERE")"
: "${TOS_ROOT:?set TOS_ROOT to a tos checkout}"
: "${TOS_BUILD:=$TOS_ROOT/build}"
[ $# -ge 1 ] || { echo "usage: rehearse-loopback.sh WORKDIR [SECONDS]" >&2; exit 2; }
WORK=$1
RUN_SECONDS=${2:-300}
HOLD_SECONDS=${REHEARSAL_HOLD_SECONDS:-0}
BASE_PORT=${REHEARSAL_BASE_PORT:-42000}
PROFILE=${REHEARSAL_PROFILE:-$TESTNET/network/profile.json}
[ -f "$PROFILE" ] || { echo "no profile $PROFILE" >&2; exit 2; }
PROFILE="$(cd "$(dirname "$PROFILE")" && pwd)/$(basename "$PROFILE")"
[ -e "$WORK" ] && { echo "$WORK exists; use a new directory" >&2; exit 2; }
mkdir -m 0700 -p "$WORK"
WORK="$(cd "$WORK" && pwd)"

export TESTNET_REHEARSAL_ALLOW_PRIVATE=1
export TOS_BIN="$WORK/bin"
PIDS=()
cleanup() {
  local pid file
  # A validator restarted by hand during a hold is not a child of this shell;
  # its node-<i>.pid names it.
  for file in "$WORK"/node-*.pid; do
    [ -f "$file" ] && PIDS+=("$(cat "$file")")
  done
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || while kill -0 "$pid" 2>/dev/null; do sleep 1; done
  done
}
trap cleanup EXIT
log() { echo "== $*"; }

# Release binary names, taken from the build.
mkdir -m 0700 "$TOS_BIN"
ln -s "$TOS_BUILD/validator-engine/validator-engine" "$TOS_BIN/validator-engine"
ln -s "$TOS_BUILD/dht-server/dht-server" "$TOS_BIN/dht-server"
ln -s "$TOS_BUILD/utils/generate-random-id" "$TOS_BIN/generate-random-id"
ln -s "$TOS_BUILD/crypto/pq/tos-pq-consensus-key" "$TOS_BIN/tos-pq-consensus-key"
for tool in "$TOS_BIN"/*; do [ -x "$tool" ] || { echo "missing build output $(readlink "$tool")" >&2; exit 1; }; done

port() { echo $((BASE_PORT + 10 * $1 + $2)); }   # node, slot
node_profile() {
  # Node i's copy of the profile: same network, its own ports on this host.
  python3 - "$PROFILE" "$WORK/profile-$1.json" \
    "$(port "$1" 0)" "$(port "$1" 2)" "$(port "$1" 3)" "$(port "$1" 4)" "$(port "$1" 5)" <<'EOF'
import json, sys
src, out, adnl, console, lite, rpc, exporter = sys.argv[1], sys.argv[2], *map(int, sys.argv[3:])
p = json.load(open(src))
p["ports"].update(adnl_udp=adnl, console_tcp=console, liteserver_tcp=lite,
                  json_rpc_loopback=rpc, exporter_loopback=exporter)
json.dump(p, open(out, "w"), indent=2)
EOF
}

OP="$HERE/testnet-operator.py"
CO="$HERE/testnet-coordinator.py"
if python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["elections"]["external_validators"] is None else 1)' "$PROFILE"; then
  python3 "$CO" --profile "$PROFILE" plan --external-validators 0 \
    --write "$WORK/profile.json" >"$WORK/plan.json"
  PROFILE="$WORK/profile.json"
fi
NODES=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["genesis"]["validators"])' "$PROFILE")
python3 "$OP" pregenesis-config "$WORK/pregenesis.json"

log "operators: first start, consensus key; coordinator: pool; operators: record"
EL="$HERE/testnet-elections.py"
for i in $(seq 1 "$NODES"); do
  db="$WORK/node$i"
  node_profile "$i"
  "$TOS_BIN/validator-engine" -C "$WORK/pregenesis.json" -D "$db" -I "127.0.0.1:$(port "$i" 0)" \
    -l "$WORK/first-start-$i.log" >/dev/null 2>&1
  [ -f "$db/config.json" ] || { echo "first start $i did not write config.json" >&2; exit 1; }
  mkdir -m 0700 "$db/keys"
  (umask 077; "$TOS_BIN/tos-pq-consensus-key" generate "$db/keys/pq-consensus.seed" >"$WORK/consensus-$i.txt")
  key_id=$(awk '$1 == "key_id" {print $2}' "$WORK/consensus-$i.txt")
  operator_wallet="-1:$(printf 'rehearsal-operator-%s' "$i" | sha256sum | cut -d' ' -f1)"
  python3 "$EL" --profile "$PROFILE" pool --name "operator-$i" --operator="$operator_wallet" --ceremony "$WORK/ceremony" \
    --tos-root "$TOS_ROOT" --fift "$TOS_BUILD/crypto/fift" >"$WORK/pool-$i.json"
  validator_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validator_id"])' \
    "$WORK/pool-$i.json")
  python3 "$OP" --profile "$WORK/profile-$i.json" record --db "$db" --seed "$db/keys/pq-consensus.seed" \
    --validator-id "$validator_id" --operator "operator-$i" --address "127.0.0.1:$(port "$i" 0)" \
    --out "$WORK/record-$i.json" >/dev/null
  echo "operator-$i key_id $key_id validator id $validator_id"
done

log "DHT bootstrap nodes"
for d in 1 2; do
  python3 "$HERE/testnet-dht.py" prepare --db "$WORK/dht$d" --ip 127.0.0.1 --port "$(port $((8 + d)) 0)" \
    --out "$WORK/dht-node-$d.json"
done

log "coordinator: manifest, genesis, global config"
records=()
for i in $(seq 1 "$NODES"); do records+=("$WORK/record-$i.json"); done
python3 "$CO" --profile "$PROFILE" manifest --ceremony "$WORK/ceremony" --tos-root "$TOS_ROOT" \
  "${records[@]}"
EPOCH=$(($(date +%s) + 30))
# The coordinator exports the announced AUTH network tag by hand; here it is
# read from the profile, unless the caller set one (which genesis then checks).
: "${TOS_AUTH_NETWORK_TAG:=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["genesis"]["auth_network_tag"]["value"])' "$PROFILE")}"
export TOS_AUTH_NETWORK_TAG
python3 "$CO" --profile "$PROFILE" genesis --ceremony "$WORK/ceremony" --tos-root "$TOS_ROOT" --tos-build "$TOS_BUILD" \
  --epoch "$EPOCH" >"$WORK/genesis.out"
python3 "$CO" --profile "$PROFILE" global-config --ceremony "$WORK/ceremony" "$WORK/dht-node-1.json" "$WORK/dht-node-2.json"
GLOBAL="$WORK/ceremony/global-config.json"

log "DHT nodes start"
for d in 1 2; do
  "$TOS_BIN/dht-server" -C "$GLOBAL" -c "$WORK/dht$d/config.json" -D "$WORK/dht$d" \
    -l "$WORK/dht$d/dht.log" -t 2 &
  PIDS+=($!)
done

log "operators: zero state, bind-node, console, start"
for i in $(seq 1 "$NODES"); do
  db="$WORK/node$i"
  mkdir -m 0700 "$db/static"
  for name in zerostate basestate0; do
    hash=$(od -An -tx1 -v "$WORK/ceremony/$name.fhash" | tr -d ' \n' | tr 'a-f' 'A-F')
    cp "$WORK/ceremony/$name.boc" "$db/static/$hash"
  done
  validator_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validator_id"])' \
    "$WORK/record-$i.json")
  "$TOS_BIN/tos-pq-consensus-key" bind-node "$db" "$db/keys/pq-consensus.seed" "$validator_id" >/dev/null
  python3 "$OP" --profile "$WORK/profile-$i.json" configure --db "$db" --role validator \
    --client-dir "$WORK/console-$i" >/dev/null
  mkdir -m 0700 "$WORK/log$i"
  # The start script records its own PID and execs the engine, so the PID file
  # names the engine also after a restart by hand.
  {
    echo "#!/usr/bin/env bash"
    echo "echo \$\$ > $(printf '%q' "$WORK/node-$i.pid")"
    printf 'exec %q -C %q -D %q -l %q --session-logs %q -t 4 --state-ttl 86400 --archive-ttl 86400 --json-rpc-address %q --json-rpc-without-wallet-index --exporter-address %q\n' \
      "$TOS_BIN/validator-engine" "$GLOBAL" "$db" "$WORK/log$i/node.log" "$WORK/log$i/session-stats" \
      "127.0.0.1:$(port "$i" 4)" "127.0.0.1:$(port "$i" 5)"
  } > "$WORK/node-$i.start"
  bash "$WORK/node-$i.start" &
  PIDS+=($!)
done

log "waiting up to $RUN_SECONDS s for a common, fresh head"
args=(--genesis "$WORK/ceremony/genesis.json" --genesis-set "$WORK/ceremony/genesis-set.json" --max-age 30)
for i in $(seq 1 "$NODES"); do args+=(--rpc "http://127.0.0.1:$(port "$i" 4)"); done
# Decoding ConfigParam 34 needs the tos Python environment. A tos worktree has
# no .venv of its own; REHEARSAL_PYTHON names another checkout's.
CHECK_PY="${REHEARSAL_PYTHON:-$TOS_ROOT/.venv/bin/python}"
[ -x "$CHECK_PY" ] || CHECK_PY=python3
deadline=$(($(date +%s) + RUN_SECONDS))
result=1
while [ "$(date +%s)" -lt "$deadline" ]; do
  if TOS_ROOT="$TOS_ROOT" "$CHECK_PY" "$HERE/check-testnet.py" "${args[@]}" >"$WORK/check.json" 2>&1 \
    && python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["height"] >= 20 else 1)' "$WORK/check.json"; then
    result=0
    break
  fi
  sleep 10
done
cat "$WORK/check.json"
for i in $(seq 1 "$NODES"); do
  grep -m1 "post-quantum consensus custody" "$WORK/log$i/node.log"* 2>/dev/null | sed "s/^/node$i: /" || true
done
if [ "$result" = 0 ]; then log "REHEARSAL PASSED"; else log "REHEARSAL FAILED (evidence in $WORK)"; fi
if [ "$result" = 0 ] && [ "$HOLD_SECONDS" -gt 0 ]; then
  log "holding the network for $HOLD_SECONDS s; validator commands in $WORK/node-<i>.start, PIDs in $WORK/node-<i>.pid"
  sleep "$HOLD_SECONDS"
fi
exit "$result"
