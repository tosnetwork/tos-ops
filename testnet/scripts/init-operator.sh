#!/usr/bin/env bash
# Set up the operator tool on a validator host. Run as root.
#
#   init-operator.sh --name NAME --wallet-only   # before genesis
#   init-operator.sh --name NAME                 # after the node is active
#
# NAME labels this validator in tosctl (node NAME, wallet op-NAME, pool
# pool-NAME). Creates the non-login system user tos-ctl, /var/lib/tos-ctl
# (owned by tos-ctl, 0700) and /etc/tos/tosctl.env (root, 0600) with a fresh
# vault master key, points tosctl at the validator's loopback JSON-RPC and
# creates the operator wallet (V3R2, masterchain). Without --wallet-only it
# also imports the engine console's client key and registers the node's
# console, which exist once install-node.sh activate has run. Prints the
# wallet's address on the last line as `op-NAME <address>`.
#
# The operator wallet exists before genesis because the validator's staking
# account, the pool the coordinator derives from it (testnet-elections.py
# pool), is the validator id genesis records. Creating the wallet needs no
# node: its address is a function of its key.
#
# Every tosctl call runs as tos-ctl, never as root, so nothing in
# /var/lib/tos-ctl is root-owned and the election task (which runs as tos-ctl)
# can rewrite all of it. Root reads the env file and hands its variables to
# tosctl through the environment; the master key never reaches a command line.
#
# Idempotent: every step checks for its result first and nothing existing is
# overwritten. The master key in /etc/tos/tosctl.env protects the operator
# wallet's key; it never leaves the host.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROFILE="$(dirname "$HERE")/network/profile.json"
USER_NAME=tos-ctl
DIR=/var/lib/tos-ctl
ENV=/etc/tos/tosctl.env
CC=/var/lib/tos/validator/console-client
NAME=""
WALLET_ONLY=0
die() { echo "init-operator: $*" >&2; exit 1; }
profile() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [d:=d[k] for k in sys.argv[2:]]; print(d)' "$PROFILE" "$@"; }
as_ctl() { runuser -u "$USER_NAME" -- "$@"; }

[ "$(id -u)" = 0 ] || die "run as root"
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift 2 ;;
    --wallet-only) WALLET_ONLY=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "--name must be lower-case letters, digits and dashes"
command -v tosctl >/dev/null || die "tosctl is missing; run build-tosctl.sh first"
if [ "$WALLET_ONLY" = 0 ]; then
  [ -f "$CC/client" ] && [ -f "$CC/server.pub" ] || die "$CC has no console keys; run install-node.sh activate first"
fi

if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "$DIR" --no-create-home \
    --shell /usr/sbin/nologin --comment "TOS operator tool" "$USER_NAME"
fi
# A host set up before the operator tool had its own user keeps root-owned
# state; tosctl as tos-ctl cannot rewrite it. That host migrates first.
if [ -d "$DIR" ]; then
  stray=$(find "$DIR" ! -user "$USER_NAME" -print -quit)
  [ -z "$stray" ] || die "$stray is not owned by $USER_NAME; run migrate-nonroot-services.sh --role validator first"
fi
install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$DIR"

if [ ! -f "$ENV" ]; then
  umask 077
  master_key=$(head -c 32 /dev/urandom | od -An -tx1 -v | tr -d ' \n')
  printf 'VAULT_URL=file://%s/vault.json?master_key=%s\nCONFIG_PATH=%s/tosctl-config.json\n' \
    "$DIR" "$master_key" "$DIR" > "$ENV"
fi
chown root:root "$ENV"
chmod 0600 "$ENV"
set -a
# shellcheck disable=SC1090
. "$ENV"
set +a
cd "$DIR"
[ -f "$CONFIG_PATH" ] || as_ctl tosctl config generate -o "$CONFIG_PATH" >/dev/null
as_ctl tosctl config chain-rpc set --url "http://127.0.0.1:$(profile ports json_rpc_loopback)/jsonRPC" >/dev/null

if [ "$WALLET_ONLY" = 0 ] && ! as_ctl tosctl key ls 2>/dev/null | grep -q 'console-client'; then
  # Root reads the validator's key file; tos-ctl writes the copy tosctl imports.
  # shellcheck disable=SC2016  # $1 expands in the inner shell, as tos-ctl
  tail -c 32 "$CC/client" | base64 -w0 \
    | as_ctl sh -c 'umask 077 && cat > "$1"' sh "$DIR/.console-client.b64"
  # tosctl reads this key to open the encrypted console channel, so it must be
  # importable as extractable; without --extractable every console call fails (E104).
  as_ctl tosctl key import --name console-client --extractable --private-key-file "$DIR/.console-client.b64" >/dev/null
  rm -f "$DIR/.console-client.b64"
fi
if [ "$WALLET_ONLY" = 0 ] && ! as_ctl tosctl config node ls 2>/dev/null | grep -q "$NAME "; then
  as_ctl tosctl config node add --name "$NAME" \
    --control-server-endpoint "127.0.0.1:$(profile ports console_tcp)" \
    --control-server-pubkey "$(tail -c 32 "$CC/server.pub" | base64 -w0)" \
    --control-client-secret-name console-client >/dev/null
fi
if [ "$WALLET_ONLY" = 0 ]; then
  as_ctl tosctl config node ls 2>&1 | grep "$NAME " | grep -q ' OK' || die "the console of node $NAME does not answer"
fi
# --offline: only the addresses are read, and before genesis there is no node to ask.
if ! as_ctl tosctl wallet ls --offline 2>/dev/null | awk -v w="op-$NAME" '$1 == w {f=1} END {exit !f}'; then
  # --workchain=-1, not "--workchain -1": the parser takes -1 for a flag.
  as_ctl tosctl wallet create --name "op-$NAME" --version V3R2 --workchain=-1 >/dev/null
fi
address=$(as_ctl tosctl wallet ls --offline 2>/dev/null | awk -v w="op-$NAME" '$1 == w {print $2}')
[ -n "$address" ] || die "wallet op-$NAME has no address"
echo "op-$NAME $address"
