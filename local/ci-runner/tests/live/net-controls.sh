#!/bin/bash
# Live controls for net-setup (run as root while tos-ci-net is active):
#   a. a failed resolution leaves the loaded rules and the address set unchanged;
#   b. "up" with no recorded address and a failed resolution refuses (exit 1)
#      before touching the loaded rules;
#   c. 50 back-to-back refreshes never let a 10 ms sampler see an empty set.
set -uo pipefail
[[ $EUID == 0 ]] || { echo "run as root" >&2; exit 2; }
fails=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }
NS=/usr/lib/tos-ci/net-setup
BAD=192.0.2.1  # TEST-NET-1: unroutable, so resolution fails
elements() { nft list set inet tos_ci host_public4 | grep -o 'elements = { [^}]* }'; }
# Stateless listing: without counters, which move with every packet.
ruleset() { nft -s list table inet tos_ci | sha256sum | cut -c1-16; }

before_set=$(elements); before_rules=$(ruleset)
sleep 1
[[ $(ruleset) == "$before_rules" ]] && pass "control: the ruleset digest is stable while nothing changes" \
  || fail "the ruleset digest moves by itself; the comparison below means nothing"
[[ -n $before_set ]] && pass "positive control: the set holds an address ($before_set)" || fail "set empty before the test"

echo "== a. failed refresh"
if TOS_CI_RESOLVER=$BAD $NS refresh > /dev/null 2>&1; then fail "refresh with a failed resolution exited 0"; else pass "refresh with a failed resolution exits non-zero"; fi
[[ $(elements) == "$before_set" ]] && pass "the address set is unchanged" || fail "the set changed: $(elements)"

echo "== b. up with no record and a failed resolution"
mv /var/lib/tos-ci-net/public4 /var/lib/tos-ci-net/public4.saved
if TOS_CI_RESOLVER=$BAD $NS up > /dev/null 2>&1; then rc=0; else rc=$?; fi
mv /var/lib/tos-ci-net/public4.saved /var/lib/tos-ci-net/public4
[[ $rc == 1 ]] && pass "up refuses with exit 1" || fail "up exited $rc"
[[ $(ruleset) == "$before_rules" ]] && pass "the loaded rules are untouched" || fail "the rules changed"
echo "== b'. positive control: up with the record and a failed resolution loads from the record"
if TOS_CI_RESOLVER=$BAD $NS up > /dev/null 2>&1; then pass "up falls back to the recorded address"; else fail "up failed with a record present"; fi
[[ $(elements) == "$before_set" ]] && pass "the recorded address is loaded" || fail "loaded $(elements)"

echo "== c. 50 refreshes under a 10 ms sampler"
sampler_out=$(mktemp)
( end=$((SECONDS + 600)); while (( SECONDS < end )); do
    [[ -f $sampler_out.stop ]] && break
    e=$(nft list set inet tos_ci host_public4 2> /dev/null | grep -c 'elements = {')
    echo "$e"; sleep 0.01
  done > "$sampler_out" ) &
sampler=$!
ok=0
for _ in $(seq 50); do $NS refresh > /dev/null 2>&1 && ok=$((ok + 1)); done
touch "$sampler_out.stop"; wait "$sampler"
samples=$(wc -l < "$sampler_out"); empty=$(grep -c '^0$' "$sampler_out")
echo "refreshes succeeded: $ok/50; samples: $samples; empty samples: $empty"
(( samples > 50 )) && pass "the sampler ran ($samples samples)" || fail "too few samples"
(( empty == 0 )) && pass "the set was never empty" || fail "the set was empty in $empty samples"
rm -f "$sampler_out" "$sampler_out.stop"

echo "== result: $fails failure(s)"
exit "$fails"
