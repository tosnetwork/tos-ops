#!/usr/bin/env bash
# Read-only T3 pre-flight facts of one validator host (plan section 4), run on the host as
# root through `on NODE "bash -s -- NODE" < t3-host-check.sh`. Labeled sections; the
# coordinator judges them with `t3_lib.py check-pre`. Nothing here changes the host.
set -u
n=${1:?node}
units=(tos-testnet-validator tos-testnet-elections)
[ "$n" = node-1 ] && units+=(tos-testnet-dht)
L=/var/lib/tos/validator/consensus/signing-ledger
echo "== is-active"; systemctl is-active "${units[@]}"
echo "== version"; /usr/local/bin/validator-engine -V | head -1
echo "== restart"; systemctl show -p Restart,RestartUSec tos-testnet-validator
echo "== ledger"; stat -c '%d %i' "$L"
# A listing for the record, never parsed.
# shellcheck disable=SC2012
ls -l "$L" | tail -3
echo "== tools"; command -v nft systemd-run
echo "== tables"; nft list tables
echo "== udp"; ss -uln | grep -E ':(30001|31001) '
echo "== allegations"
grep -ahcE 'MISBEHAVIOR DETECTED|conflicts with a decision already recorded|is full|untrusted' \
  /var/log/tos/validator/node.log* | awk '{s += $1} END {print s + 0}'
echo "== end"
