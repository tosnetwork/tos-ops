#!/usr/bin/env bash
# Local check of the rpc role's unit lifecycle with a real systemd, not a model.
# Not run by pytest or CI; run it by hand on a workstation with a user manager:
#
#   bash testnet/tests/check-rpc-units-lifecycle.sh
#
# It copies tos-testnet-fullnode, tos-testnet-wallet-index and tos-testnet-rpc
# into the user manager's runtime unit directory as tosrpctest-*.service, with
#   - every tos-testnet- unit name renamed to tosrpctest-;
#   - [Unit] and [Install] otherwise byte-identical (checked below);
#   - [Service] reduced to ExecStart=/bin/sleep infinity plus the directives
#     that shape the lifecycle (ExecStartPre, Restart, RestartSec,
#     RestartPreventExitStatus, KillMode, TimeoutStopSec). Accounts and
#     sandboxing need the system manager and are dropped; the ExecStartPre
#     guard asks the user manager (systemctl --user) about the renamed node.
# It enables the index and RPC copies with --runtime, as activate does on a
# host, and checks: node stop stops index and RPC; node start starts index,
# then RPC; node restart restarts both; an index restart restarts the RPC and
# not the node; a manual index start with the node inactive is refused by
# ExecStartPre and does not start the node. It also prints, as NOTE lines,
# what such a refused start does to the RPC and to the index's restart policy.
# States come from systemctl --user, start
# order from the units' monotonic activation timestamps and the user journal.
# The copies are removed on exit. The real units, the system manager and every
# host are untouched.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SYSTEMD="$(dirname "$HERE")/systemd"
P=tosrpctest
DIR="${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is not set; no user manager}/systemd/user"
NODE=$P-fullnode.service
INDEX=$P-wallet-index.service
RPC=$P-rpc.service
FAILED=0

die() { echo "lifecycle: $*" >&2; exit 2; }
sc() { systemctl --user "$@"; }

state=$(sc is-system-running 2>/dev/null || true)
case "$state" in running|degraded) ;; *) die "the user manager is not usable (state '$state')" ;; esac
mkdir -p "$DIR"
for unit in "$NODE" "$INDEX" "$RPC"; do
  [ ! -e "$DIR/$unit" ] || die "$DIR/$unit exists; remove a leftover test unit first"
done

# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  sc stop "$RPC" "$INDEX" "$NODE" >/dev/null 2>&1 || true
  sc disable --runtime "$INDEX" "$RPC" >/dev/null 2>&1 || true
  rm -f "$DIR/$NODE" "$DIR/$INDEX" "$DIR/$RPC"
  rmdir "$DIR/$NODE.wants" "$DIR/$INDEX.wants" 2>/dev/null || true
  sc daemon-reload || true
  sc reset-failed "$NODE" "$INDEX" "$RPC" >/dev/null 2>&1 || true
}
trap cleanup EXIT

copy_unit() {
  awk -v p="$P" '
    BEGIN { keep["ExecStartPre"]; keep["Restart"]; keep["RestartSec"]
            keep["RestartPreventExitStatus"]; keep["KillMode"]; keep["TimeoutStopSec"] }
    { gsub(/tos-testnet-/, p "-") }
    /^\[/ { section = $0; print; if (section == "[Service]") print "ExecStart=/bin/sleep infinity"; skip = 0; next }
    section != "[Service]" { print; next }
    skip { skip = ($0 ~ /\\$/); next }
    /^#/ || /^$/ { next }
    {
      key = $0; sub(/=.*/, "", key)
      if (!(key in keep)) { skip = ($0 ~ /\\$/); next }
      sub(/^ExecStartPre=\/bin\/systemctl is-active/, "ExecStartPre=/bin/systemctl --user is-active")
      print
    }' "$1"
}
copy_unit "$SYSTEMD/tos-testnet-fullnode.service" > "$DIR/$NODE"
copy_unit "$SYSTEMD/tos-testnet-wallet-index.service" > "$DIR/$INDEX"
copy_unit "$SYSTEMD/tos-testnet-rpc.service" > "$DIR/$RPC"

# The dependency directives must be the real ones, only renamed.
DEPS='^(After|Before|Wants|Requires|Requisite|BindsTo|PartOf|WantedBy|RequiredBy)='
for name in fullnode wallet-index rpc; do
  real=$(grep -E "$DEPS" "$SYSTEMD/tos-testnet-$name.service" | awk -v p="$P" '{ gsub(/tos-testnet-/, p "-"); print }')
  copy=$(grep -E "$DEPS" "$DIR/$P-$name.service")
  [ "$real" = "$copy" ] || die "the test copy of tos-testnet-$name changed a dependency directive"
done
echo "== test units (dependency directives identical to the real units, renamed)"
for unit in "$NODE" "$INDEX" "$RPC"; do
  echo "-- $unit"; grep -E "$DEPS|^ExecStart" "$DIR/$unit"
done

sc daemon-reload
sc enable --runtime "$INDEX" "$RPC" 2>&1 | sed 's/^/   /'

check() {  # check DESCRIPTION CONDITION...
  local what=$1; shift
  if "$@"; then echo "PASS $what"; else echo "FAIL $what"; FAILED=1; fi
}
# shellcheck disable=SC2329 # run through check
active() { [ "$(sc is-active "$1" 2>/dev/null)" = active ]; }
# shellcheck disable=SC2329 # run through check
inactive() { ! active "$1"; }
entered() { sc show -p ActiveEnterTimestampMonotonic --value "$1"; }
states() { for u in "$NODE" "$INDEX" "$RPC"; do printf '   %-30s %s\n' "$u" "$(sc is-active "$u" 2>/dev/null || true)"; done; }
settle() { sleep 1; }

echo "== start the node"
since=$(date '+%Y-%m-%d %H:%M:%S')
sc start "$NODE"; settle; states
check "node start starts the index" active "$INDEX"
check "node start starts the RPC" active "$RPC"
n=$(entered "$NODE") i=$(entered "$INDEX") r=$(entered "$RPC")
echo "   activation (monotonic us): node $n, index $i, rpc $r"
check "start order node <= index <= rpc" test "$n" -le "$i" -a "$i" -le "$r"

echo "== stop the node"
sc stop "$NODE"; settle; states
check "node stop stops the index" inactive "$INDEX"
check "node stop stops the RPC" inactive "$RPC"

echo "== start the node again"
sc start "$NODE"; settle; states
check "node start starts the index" active "$INDEX"
check "node start starts the RPC" active "$RPC"
n=$(entered "$NODE") i=$(entered "$INDEX") r=$(entered "$RPC")
check "start order node <= index <= rpc" test "$n" -le "$i" -a "$i" -le "$r"

echo "== restart the node"
sc restart "$NODE"; settle; states
n2=$(entered "$NODE") i2=$(entered "$INDEX") r2=$(entered "$RPC")
echo "   activation before: node $n, index $i, rpc $r; after: node $n2, index $i2, rpc $r2"
check "node restart restarts the index" test "$i2" -gt "$i"
check "node restart restarts the RPC" test "$r2" -gt "$r"
check "after the restart: order node <= index <= rpc" test "$n2" -le "$i2" -a "$i2" -le "$r2"

echo "== restart the index alone"
sc restart "$INDEX"; settle; states
n3=$(entered "$NODE") i3=$(entered "$INDEX") r3=$(entered "$RPC")
check "index restart restarts the RPC" test "$r3" -gt "$r2"
check "index restart leaves the node alone" test "$n3" -eq "$n2"
check "index restart restarted the index" test "$i3" -gt "$i2"
check "index restart: index active" active "$INDEX"

echo "== stop the node, then start the index by hand"
sc stop "$NODE"; settle
if sc start "$INDEX" 2>/dev/null; then started=1; else started=0; fi
sleep 12  # past RestartSec=10: an automatic restart of the failed start would show here
states
echo "   index result $(sc show -p Result --value "$INDEX"), restarts $(sc show -p NRestarts --value "$INDEX")"
check "manual index start with the node inactive is refused" test "$started" -eq 0
check "the refused index is not active" inactive "$INDEX"
check "the refused start did not start the node" inactive "$NODE"
# Observed, not asserted: behaviour outside the agreed unit design.
echo "NOTE rpc after the refused index start: $(sc is-active "$RPC" 2>/dev/null || true)" \
  "(Wants= from the index's start job does not depend on the index starting)"
echo "NOTE index after the refused start: $(sc is-active "$INDEX" 2>/dev/null || true)," \
  "automatic restarts $(sc show -p NRestarts --value "$INDEX") (Restart=on-failure retries a failed ExecStartPre)"

echo "== user journal (start/stop lines of the test units; they log their Description)"
journalctl --user --since "$since" -o short-monotonic --no-pager 2>/dev/null \
  | grep -E "$P-|TOS public testnet" | grep -E 'Start|Stop|Fail|control process' | sed 's/^/   /' \
  || echo "   (no user journal available)"

if [ "$FAILED" = 0 ]; then echo "lifecycle: all checks passed"; else echo "lifecycle: FAILED"; fi
exit "$FAILED"
