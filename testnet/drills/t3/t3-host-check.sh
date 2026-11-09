#!/usr/bin/env bash
# Read-only T3 pre-flight facts of one validator host (plan v2 section 4), run on the host as
# root through `on NODE "bash -s -- NODE" < t3-host-check.sh`. Labeled sections; the
# coordinator judges them (t3_lib.pre_problems) and stores them only after redact_pre, which
# replaces every address-bearing section with families and ports. Nothing here changes the
# host. Every check prints its own result; none is hidden behind another's exit status.
set -u
n=${1:?node}
units=(tos-testnet-validator tos-testnet-elections)
[ "$n" = node-1 ] && units+=(tos-testnet-dht)
L=/var/lib/tos/validator/consensus/signing-ledger
echo "== units"
for u in "${units[@]}"; do systemctl is-active --quiet "$u"; echo "$u rc=$?"; done
echo "== version"; /usr/local/bin/validator-engine -V | head -1
echo "== restart"; systemctl show -p Restart -p RestartUSec tos-testnet-validator
echo "== ledger"; stat -c '%d %i' "$L"
# A listing for the record, never parsed.
# shellcheck disable=SC2012
ls -l "$L" | tail -3
echo "== tools"; command -v nft; command -v systemd-run
echo "== tables"; nft list tables
echo "== t3-units"; systemctl list-units --all --plain --no-legend 't3-*'
echo "== udp"; ss -ulnH | grep -E ':(30001|31001) '
echo "== sockets"; ss -tunapH | grep 'validator-engi'
echo "== v6"; ip -6 -o addr show scope global
echo "== config"
python3 - <<'PY'
import base64, json
try:
    c = json.load(open("/var/lib/tos/validator/config.json"))
except (OSError, ValueError) as e:
    print("unreadable", e.__class__.__name__)
    raise SystemExit
for a in c.get("adnl", []):
    try:
        print("adnlid", base64.b64decode(a["id"]).hex())
    except (KeyError, ValueError, TypeError):
        print("adnlid unreadable")
for a in c.get("addrs", []):
    t = str(a.get("@type", "?"))
    fam = "v6" if "6" in t or ":" in str(a.get("ip", "")) else "v4"
    print("listen", t, fam, a.get("port"))
PY
echo "== custody"; grep -ah 'custody of validator' /var/log/tos/validator/node.log* | tail -1
echo "== allegations"
grep -ahcE 'MISBEHAVIOR DETECTED|conflicts with a decision already recorded|is full|untrusted' \
  /var/log/tos/validator/node.log* | awk '{s += $1} END {print s + 0}'
echo "== end"
