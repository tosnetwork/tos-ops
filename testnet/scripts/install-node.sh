#!/usr/bin/env bash
# Install and bring up one public testnet node on this host. Run as root.
#
#   install-node.sh prepare  --role validator|fullnode|dht --public-ip IP [--release DIR --rev COMMIT]
#   install-node.sh activate --role validator|fullnode|dht --global-config FILE --sha256 HEX
#                            [--genesis DIR] [--validator-id HEX]
#   install-node.sh binaries --role validator|fullnode|dht --release DIR --rev COMMIT
#
# The release DIR is what build-node-binaries.sh wrote on this host: each host
# compiles its own binaries from the pinned tos commit. --rev is that pinned
# commit; check-release.sh refuses a release built from any other.
#
# prepare (before genesis for a genesis validator; any time for other roles):
#   installs release binaries verified against --rev and the release's SHA256SUMS,
#   creates the tos service account and the production layout
#   (/var/lib/tos/<role>, /var/log/tos/<role>), runs the engine's first start
#   with -I <public-ip>:<port> on a placeholder global config, and on a
#   validator generates the PQ consensus seed in place. The seed never leaves
#   this host; only `tos-pq-consensus-key show` output is printed.
#
# activate (after the coordinator publishes the global config):
#   installs the global config only if its SHA-256 matches the published one,
#   places the zero state and base state where the engine finds them (genesis
#   validators and early full nodes), binds the consensus key on a validator
#   to its staking account (--validator-id: the pool genesis names),
#   adds a loopback console (and a lite server on a full node), installs the
#   unit and starts it.
#
# Nothing here touches a wallet key.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TESTNET="$(dirname "$HERE")"
PROFILE="$TESTNET/network/profile.json"
BIN=/usr/local/bin
ETC=/etc/tos
DB_ROOT=/var/lib/tos
LOG_ROOT=/var/log/tos

die() { echo "install-node: $*" >&2; exit 1; }
profile() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [d:=d[k] for k in sys.argv[2:]]; print(d)' "$PROFILE" "$@"; }

[ "$(id -u)" = 0 ] || die "run as root"
[ $# -ge 1 ] || die "usage: install-node.sh prepare|activate|binaries --role ROLE ..."
STEP=$1; shift
ROLE="" PUBLIC_IP="" RELEASE="" REV="" GLOBAL_CONFIG="" SHA256="" GENESIS="" VALIDATOR_ID=""
while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE=$2; shift 2 ;;
    --public-ip) PUBLIC_IP=$2; shift 2 ;;
    --release) RELEASE=$2; shift 2 ;;
    --rev) REV=$2; shift 2 ;;
    --global-config) GLOBAL_CONFIG=$2; shift 2 ;;
    --sha256) SHA256=$2; shift 2 ;;
    --genesis) GENESIS=$2; shift 2 ;;
    --validator-id) VALIDATOR_ID=$2; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
case "$ROLE" in validator|fullnode|dht) ;; *) die "--role must be validator, fullnode or dht" ;; esac
DB="$DB_ROOT/$ROLE"
LOG="$LOG_ROOT/$ROLE"
UNIT="tos-testnet-$ROLE.service"
as_tos() { (cd / && runuser -u tos -- env TOS_BIN="$BIN" "$@"); }
has_console() {
  python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("control") else 1)' "$DB/config.json"
}

ALL_BINARIES=(validator-engine validator-engine-console dht-server lite-client generate-random-id tos-pq-consensus-key)
role_binaries() {
  case "$ROLE" in
    dht) echo dht-server generate-random-id ;;
    *) echo validator-engine validator-engine-console lite-client generate-random-id tos-pq-consensus-key ;;
  esac
}

install_release() {
  local dir=$1 name
  [ -n "$REV" ] || die "--rev COMMIT is required with --release"
  # shellcheck disable=SC2046 # one word per binary
  bash "$HERE/check-release.sh" "$dir" "$REV" $(role_binaries) || die "release $dir refused"
  # Install every binary the release carries, so a host running two roles
  # (a validator and a DHT node) keeps them from one build.
  for name in "${ALL_BINARIES[@]}"; do
    if [ -f "$dir/$name" ]; then
      install -m 0755 -o root -g root "$dir/$name" "$BIN/$name"
    fi
  done
  [ -f "$dir/BUILD-INFO" ] && install -D -m 0644 "$dir/BUILD-INFO" /etc/tos/BUILD-INFO
  return 0
}

# Replace the installed binaries with another verified release. The node must
# be stopped: a running engine keeps the old file open, and a restart picks up
# whatever is installed.
binaries() {
  [ -n "$RELEASE" ] || die "--release DIR is required"
  local unit
  for unit in tos-testnet-validator tos-testnet-fullnode tos-testnet-dht; do
    if systemctl is-active --quiet "$unit"; then die "$unit is running; stop it first"; fi
  done
  install_release "$RELEASE"
  "$BIN/$(role_binaries | cut -d' ' -f1)" -V | head -1
}

prepare() {
  [ -n "$PUBLIC_IP" ] || die "--public-ip is required"
  # Time first: consensus timeouts and consensus-key validity read the wall clock.
  bash "$HERE/setup-time.sh" || die "the clock is not following NTP; fix it before preparing a node"
  id tos >/dev/null 2>&1 || useradd --system --home-dir "$DB_ROOT" --shell /usr/sbin/nologin tos
  # The service account runs these scripts; a checkout under a private home is unreadable to it.
  runuser -u tos -- test -r "$HERE/testnet_lib.py" \
    || die "the tos account cannot read $HERE; copy testnet/ to a root-owned, world-readable path such as /opt/tos-testnet"
  if [ -n "$RELEASE" ]; then install_release "$RELEASE"; fi
  for name in $(role_binaries); do
    [ -x "$BIN/$name" ] || die "$BIN/$name is missing; pass --release DIR"
  done
  install -d -m 0755 -o root -g root "$ETC" "$DB_ROOT" "$LOG_ROOT"
  [ -e "$DB/config.json" ] && die "$DB/config.json exists: this node was already prepared"
  install -d -m 0700 -o tos -g tos "$DB"
  install -d -m 0750 -o tos -g tos "$LOG"

  if [ "$ROLE" = dht ]; then
    local port; port=$(profile ports dht_udp)
    as_tos python3 "$HERE/testnet-dht.py" prepare --db "$DB" --ip "$PUBLIC_IP" --port "$port" \
      --out "$DB/dht-node.json"
    echo "send $DB/dht-node.json to the coordinator"
    return
  fi

  [ -x "$BIN/validator-engine" ] || die "$BIN/validator-engine is missing; pass --release DIR"
  local pregenesis="$ETC/pregenesis-global-config.json"
  [ -e "$pregenesis" ] || python3 "$HERE/testnet-operator.py" pregenesis-config "$pregenesis"
  local port; port=$(profile ports adnl_udp)
  # The first start writes config.json and the transport keys, logs
  # "check it manually before continue", and exits 0.
  as_tos "$BIN/validator-engine" -C "$pregenesis" -D "$DB" -I "$PUBLIC_IP:$port" -l "$LOG/first-start.log" \
    || die "first start failed; see $LOG/first-start.log"
  [ -f "$DB/config.json" ] || die "first start did not create $DB/config.json"

  if [ "$ROLE" = validator ]; then
    install -d -m 0700 -o tos -g tos "$DB/keys"
    as_tos sh -c "umask 077; '$BIN/tos-pq-consensus-key' generate '$DB/keys/pq-consensus.seed'"
    echo "consensus key (public; the seed stays in $DB/keys):"
    as_tos "$BIN/tos-pq-consensus-key" show "$DB/keys/pq-consensus.seed"
    echo "next: init-operator.sh --wallet-only, the coordinator's pool step, then testnet-operator.py record"
  fi
}

place_static() {
  # The engine reads the zero state and base state from <db>/static/<FILE HASH HEX>.
  local genesis=$1 name hash
  [ -f "$genesis/genesis.json" ] || die "$genesis/genesis.json is missing"
  install -d -m 0700 -o tos -g tos "$DB/static"
  for name in zerostate basestate0; do
    hash=$(od -An -tx1 -v "$genesis/$name.fhash" | tr -d ' \n' | tr 'a-f' 'A-F')
    [ "$(sha256sum "$genesis/$name.boc" | cut -d' ' -f1 | tr 'a-f' 'A-F')" = "$hash" ] \
      || die "$name.boc does not match its file hash"
    install -m 0644 -o tos -g tos "$genesis/$name.boc" "$DB/static/$hash"
  done
}

install_unit() {
  install -m 0644 -o root -g root "$TESTNET/systemd/$UNIT" "/etc/systemd/system/$UNIT"
  systemctl daemon-reload
  systemd-analyze verify "/etc/systemd/system/$UNIT"
}

activate() {
  [ -n "$GLOBAL_CONFIG" ] && [ -n "$SHA256" ] || die "--global-config and --sha256 are required"
  [ "$(sha256sum "$GLOBAL_CONFIG" | cut -d' ' -f1)" = "$SHA256" ] || die "global config SHA-256 mismatch"
  python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import json, testnet_lib as l; c=json.load(open(sys.argv[2])); sys.exit("refused: placeholder config" if l.is_pregenesis(c) else 0)' \
    "$HERE" "$GLOBAL_CONFIG"
  if systemctl is-active --quiet "$UNIT"; then die "$UNIT is running; stop it first"; fi
  if [ -e "$ETC/global-config.json" ] && ! cmp -s "$GLOBAL_CONFIG" "$ETC/global-config.json"; then
    die "$ETC/global-config.json exists with different content; replace it deliberately"
  fi
  install -m 0644 -o root -g root "$GLOBAL_CONFIG" "$ETC/global-config.json"
  [ -f "$DB/config.json" ] || die "$DB/config.json is missing; run prepare first"

  if [ "$ROLE" != dht ]; then
    if [ -n "$GENESIS" ]; then place_static "$GENESIS"; fi
    if [ "$ROLE" = validator ]; then
      [ -n "$VALIDATOR_ID" ] || die "--validator-id (the staking pool's id) is required for a validator"
      as_tos "$BIN/tos-pq-consensus-key" bind-node "$DB" "$DB/keys/pq-consensus.seed" "$VALIDATOR_ID"
    fi
    if ! has_console; then
      install -d -m 0700 -o tos -g tos "$DB/console-client"
      as_tos python3 "$HERE/testnet-operator.py" configure --db "$DB" --role "$ROLE" \
        --client-dir "$DB/console-client"
    fi
  fi
  install_unit
  systemctl enable --now "$UNIT"
  systemctl --no-pager --lines=5 status "$UNIT" || true
}

case "$STEP" in
  prepare) prepare ;;
  activate) activate ;;
  binaries) binaries ;;
  *) die "unknown step $STEP" ;;
esac
