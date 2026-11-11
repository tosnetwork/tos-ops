# Read-only current-term window assessment

`br1_window.py` replaces fixed-since timing assumptions for operator planning.
It has no signing, submission, funding, service-control or deployment path.
A quiet term is not permission to enable a Relayer: resource/upgrade soak,
historical acceptance, budget, custody, native preflight and review gates remain
separate. In particular it does not replace Epoch-6's12:35:22UTC resource bound.

The command first runs the existing bounded genesis-chain/three-source suffix
verifier with the pinned OpenSSL helper. From the most recent certified full
key-block ID it fetches two independent ConfigInfo proofs and verifies their
Merkle roots/full IDs. Config8 version16, Config19 global2 and Config34's four-PQ
validator set must match the fresh governing certificates on all three sources.
No old fixed term-since timestamp is accepted as a substitute.

It then observes `active_election_id` on two loopback RPCs. **Those getter replies
are corroboration, not an authenticated Elector account-state proof**; the output
labels that distinction. Unknown/malformed replies refuse. Both must report0.
The term must have aged905seconds and have strictly more than1800seconds left.
Signed target headers must be at most30seconds old (future tolerance5seconds).
Any quiet result expires by the oldest proved header's30-second freshness bound,
the completion time+30seconds, or the handover margin, whichever is earliest.
Every result carries `public_activation_approved: false`.

```sh
PYTHONPATH=production /usr/bin/python3 -B -m br1_window \
  --anchor testnet/tests/data/con01-history/genesis.json \
  --verifier /absolute/pinned/mldsa_verify --verifier-sha256 APPROVED_SHA256 \
  --rpc node1=http://127.0.0.1:48081/jsonRPC \
  --rpc node3=http://127.0.0.1:48083/jsonRPC \
  --rpc node5=http://127.0.0.1:48085/jsonRPC \
  --archive node5 --join-key 246589 --out /absolute/new-private-output
```

Exit0 means only a fresh quiet-term observation; exit3 is an ordinary timing or
active-election wait; other nonzero exits refuse unverified/malformed/stale data.
Each run requires a new output directory and retains raw read-only replies plus
WINDOW.json and the original proof collector's reports. No automatic waiting or
write retry is added. Use the same thermal/memory/runtime wrapper as the underlying
proof collector. Its fixed3sources,64proof-packet/64MiB-per-chain limits,512links,
2MiB RPC responses and per-call timeout remain; new config calls are fixed at2,
Elector getters fixed at2 with8192-byte/10-second caps. Global Cell caches clear
on completion and the sealed helper closes on failures as well as success.

Validation:17tests including a real public config proof and full root/file ID
negative;17guard removals each fail their designated runtime assertion, with a
complete green baseline/restoration. The test metadata fixture is explicitly
synthetic and is not a signature claim. The retained config fixture contains only
public consensus parameters/proofs, not transaction or custody data. Reproduce:

```sh
/usr/bin/python3 -m unittest discover -s testnet/tests -p test_br1_window.py -v
/usr/bin/python3 testnet/tests/br1_window_controls.py --out /absolute/new-controls
```

Live read-only probes before the09:25:46UTC handover correctly refused for the
handover margin (including a probe with no active election); the probe after the
successful handover identified the new term and correctly waited for settlement.
These do not claim completion of resource or historical gates. The bounded result
index in `evidence/br1-window.json` binds exact sources, control exits/logs and
retained raw artifact hashes/sizes through2027-02-01.

Upstream comparison: this TOS public-testnet operator timing/proof orchestration
is absent at fetched ton master857b8a57a178e6ae0fe7fa86e7d81c5233de8560.
No inherited validator, consensus or contract code changes.

A final live probe at09:51:56UTC, after settlement, observed a quiet term and returned0; its proved-header expiry was09:52:14UTC. This is a retained historical observation, already expired, not a reusable authorization. All three stages (handover-margin wait, post-handover settlement wait, then quiet observation) used only reads.

An additional runtime regression control restores the old fixed-since1793541840 guard; the dynamic-term test then fails its intended assertion. This directly exercises the original stale-window assumption rather than only testing the new margins.

The final getter decoder requires one two-field numeric stack row and integer exit0. Extra row fields, non-list stacks and boolean/float exit codes refuse. Its row-shape guard has a runtime removal control; the final live quiet probe reran after this decoder change. Earlier timing probes retain their original module-source hashes in the index.


## Fresh target after genesis verification

A long genesis/suffix collection may leave its originally selected target too
old to sign safely. Keep that verified collection as the same-run trust prefix,
then choose the newest common target and prove it independently on all three
sources from the prefix's latest certified full key-block identity. Compare the
new full target IDs and key chains, fetch configuration for the new certified key,
and apply the unchanged30s header freshness and validity checks. No previous-run
cache or standalone untrusted checkpoint can authorize the refresh.

The retained `chain/REPORT.json` remains genesis-authenticated historical evidence;
`fresh/REPORT.json` contains the fresh three-source suffixes and pins its same-run
prefix path/SHA. A fixed second three-source phase adds bounded head/header reads
and bounded suffix acquisition under the existing per-chain packet/byte/link
limits. This trades a few current proofs for a useful signing interval; it never
extends a header's expiry or skips final sign/broadcast fences.

Current validation25tests and24removed runtime guards is indexed separately in
`evidence/br1-window-refresh.json`. The older17/17 index remains historical for
its recorded source and must not be used as current-head evidence. No chain sends
are part of these tests; refresh tests use mocked RPCs and do not claim signature
verification. Upstream: this TOS ops orchestration is absent at857b8a57a178e6ae0fe7fa86e7d81c5233de8560.

Refresh header replies must also contain exactly the requested common head height; agreement on an older substituted reply does not satisfy the new-target invariant.
