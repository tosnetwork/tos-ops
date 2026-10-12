#!/usr/bin/env bash
# Set up the operator tool on a validator host. Run as root, after the node is active.
#
#   init-operator.sh --name NAME
#
# NAME labels this validator in tosctl (node NAME, wallet op-NAME, pool
# pool-NAME). Creates /var/lib/tos-ctl and /etc/tos/tosctl.env with a fresh
# vault master key, points tosctl at the validator's loopback JSON-RPC,
# imports the engine console's client key, registers the node's console, and
# creates the operator wallet (V3R2, masterchain). Prints the wallet's
# address on the last line as `op-NAME <address>`.
#
# Idempotent: every step checks for its result first and nothing existing is
# overwritten. The master key in /etc/tos/tosctl.env protects the operator
# wallet's key; it never leaves the host.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROFILE="$(dirname "$HERE")/network/profile.json"
DIR=/var/lib/tos-ctl
ENV=/etc/tos/tosctl.env
CC=/var/lib/tos/validator/console-client
NAME=""
die() { echo "init-operator: $*" >&2; exit 1; }
profile() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [d:=d[k] for k in sys.argv[2:]]; print(d)' "$PROFILE" "$@"; }

[ "$(id -u)" = 0 ] || die "run as root"
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "--name must be lower-case letters, digits and dashes"
command -v tosctl >/dev/null || die "tosctl is missing; run build-tosctl.sh first"
[ -f "$CC/client" ] && [ -f "$CC/server.pub" ] || die "$CC has no console keys; run install-node.sh activate first"

install -d -m 0700 -o root -g root "$DIR"
if [ ! -f "$ENV" ]; then
  umask 077
  master_key=$(head -c 32 /dev/urandom | od -An -tx1 -v | tr -d ' \n')
  printf 'VAULT_URL=file://%s/vault.json?master_key=%s\nCONFIG_PATH=%s/tosctl-config.json\n' \
    "$DIR" "$master_key" "$DIR" > "$ENV"
  chmod 0600 "$ENV"
fi
set -a
# shellcheck disable=SC1090
. "$ENV"
set +a
cd "$DIR"
[ -f "$CONFIG_PATH" ] || tosctl config generate -o "$CONFIG_PATH" >/dev/null
tosctl config chain-rpc set --url "http://127.0.0.1:$(profile ports json_rpc_loopback)/jsonRPC" >/dev/null

if ! tosctl key ls 2>/dev/null | grep -q 'console-client'; then
  umask 077
  tail -c 32 "$CC/client" | base64 -w0 > "$DIR/.console-client.b64"
  # tosctl reads this key to open the encrypted console channel, so it must be
  # importable as extractable; without --extractable every console call fails (E104).
  tosctl key import --name console-client --extractable --private-key-file "$DIR/.console-client.b64" >/dev/null
  rm -f "$DIR/.console-client.b64"
fi
if ! tosctl config node ls 2>/dev/null | grep -q "$NAME "; then
  tosctl config node add --name "$NAME" \
    --control-server-endpoint "127.0.0.1:$(profile ports console_tcp)" \
    --control-server-pubkey "$(tail -c 32 "$CC/server.pub" | base64 -w0)" \
    --control-client-secret-name console-client >/dev/null
fi
tosctl config node ls 2>&1 | grep "$NAME " | grep -q ' OK' || die "the console of node $NAME does not answer"
if ! tosctl wallet ls 2>/dev/null | awk -v w="op-$NAME" '$1 == w {f=1} END {exit !f}'; then
  # --workchain=-1, not "--workchain -1": the parser takes -1 for a flag.
  tosctl wallet create --name "op-$NAME" --version V3R2 --workchain=-1 >/dev/null
fi
address=$(tosctl wallet ls 2>/dev/null | awk -v w="op-$NAME" '$1 == w {print $2}')
[ -n "$address" ] || die "wallet op-$NAME has no address"
echo "op-$NAME $address"
