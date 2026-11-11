# Epoch-6 fixed pilot initialization

`br1_fund.py` provides one fixed allocation per role, including canonical V3
StateInit, from approved PRI wallet0:5TOS to a fresh native provider funding
wallet, or separately authorized2TOS to an official CLI carrier wallet on public Epoch-6 (global ID2, global version16). It reuses the
frozen approved PRI driver/transport and existing private journal. This tool is
not an approval, faucet, refill mechanism, Bond bootstrap or client-proof driver.
No public transfer is part of its tests.

Before any signing, retain explicit operator authorization for that network,
source, destination and bounded allocation. The allocation is inside the existing
150 TOS PRI budget; validator fees and other identities have separate budgets.
Do not substitute disposable local keys or the legacy fixed-term batch wrapper.

## Inputs and execution

Use the wallet Python environment with `pytosiq_core` and PyNaCl. Run as a module
with `PYTHONPATH=production`; quiet-window proofs run separately with host
`/usr/bin/python3` and its sealed-descriptor support. There is no service installer.

The private policy is JSON, schema `tos.br1.public-pilot-policy.v1`. Supply its
SHA256 explicitly. Required fields:

| Field | Meaning |
| --- | --- |
| `source_pins` | Absolute source-file path to SHA256 mapping, covering the reviewed driver dependencies/local scripts and configured helpers; never seed/key paths |
| `driver`, `transport`, `funding_config` | Frozen PRI components; additional fixed expected hashes are embedded in the wrapper |
| `tos_root`, `local_scripts` | Existing approved PRI library roots |
| `funding_dir` | Existing approved PRI custody directory; no key copying |
| `run_dir` | Existing canonical PRI run with delivered anchor entry and locked private journal |
| `provider_state` | Operator policy only: fresh, independently generated public native state containing provider.json, funding-init.boc and funding.seed |
| `resource_gate`, `history_gate`, `upgrade_gate` | Objects `{path, sha256}` for independently reviewed qualification reports |
| `window` | Existing proof inputs: `anchor`, `verifier`, `verifier_sha256`, `archive`, `join_key`, and three `rpc` name=URL strings; see BR1-WINDOW.md |

Policy/source hashes bind operator-reviewed inputs; they do not authenticate an
arbitrary newly written PASS report. Resource report requires actual complete
24h measurements of four nodes on the original engine/CLI identities, measured
resource limits and identity checks. History input is independent qualification,
not a worker's provisional verdict. Upgrade report covers four nodes, reviewed
CLI395 SHA and unchanged engine PIDs. Preserve original reports and raw records.
No sample report supplied here should be used as operational acceptance.

Every invocation needs a new private output directory:

```sh
PYTHONPATH=production "$WALLET_PYTHON" -B -m br1_fund \
  --policy "$POLICY" --policy-sha256 "$POLICY_SHA" \
  --mode inspect --out "$NEW_INSPECT"
```

Inspect writes only UNSIGNED.json and does not load keys, sign or submit. Review
its source, destination, 5 TOS amount, nonce and StateInit hash. After all gates,
repeat with `--mode dry-run --out "$NEW_DRY"`. This wrapper's pinned legacy dry
path loads approved keys but does not sign or send; it journals planned-only.
Unlike generic `fund --dry-run`, this specific path has tested no-sign semantics.

Hash the resulting RESULT.json and pass it to one authorized fund invocation:

```sh
PYTHONPATH=production "$WALLET_PYTHON" -B -m br1_fund \
  --policy "$POLICY" --policy-sha256 "$POLICY_SHA" \
  --mode fund --plan "$DRY_RESULT" --plan-sha256 "$DRY_SHA" --out "$NEW_FUND"
```

The same plan must still match the two-peer nonce, address, amount and initialization,
be at most300s old, and obtain a new valid quiet-window proof. Checks precede
key loading/signing. A durable, fsynced one-attempt marker precedes signing;
legacy signed bytes are journaled before transport. Native StateInit code/data,
public-key derivation, fresh empty destination, peer balances and genesis are
checked independently. A signer nonce/window fence and separate pre-broadcast
window fence prevent an expired proof from authorizing transport.

Any refusal or unknown result stops value operations. Never remove the marker,
lock or journal, re-sign, change operation ID or generate a replacement identity
to retry this allocation. `--mode reconcile --out "$NEW_RECONCILE"` only checks
original journaled bytes using the existing readonly reconciliation path;
rebroadcast is hard-disabled. Even a terminal failed attempt consumes this tool's
allocation fence. A pre-sign crash may therefore need operator investigation;
availability is deliberately subordinate to preventing a second payment.

## Verification and limits

```sh
"$WALLET_PYTHON" -B -m unittest discover -s testnet/tests -p test_br1_fund.py -v
"$WALLET_PYTHON" -B testnet/tests/br1_fund_controls.py --out "$NEW_CONTROLS"
```

The original48 tests include real V3 cell serialization/Ed25519 public-key matching and mock
orchestration for fixed initialization, marker-before-keys, dry/no-sign,
post-sign expiry, and unknown reconciliation. Twenty individually removed guards
must cause assertion failures, with complete baseline/restoration passes.
Orchestration mocks are not live acceptance. The [client evidence index](evidence/br1-client-fund.json) records historical
48/20 source and raw hashes with retention. The [original operator index](evidence/br1-fund.json)
remains historical26/11 evidence for its recorded source, not the new head; no seeds, signed BOCs or journals are in Git.

Inputs are bounded (policy128KiB, normal JSON1MiB, StateInit64KiB, journal16MiB,
pinned source256MiB per file); subprocess quiet proof has180s timeout and each
control30s. Inherited PRI RPC semantics remain unchanged. No daemon, persistent
cache, consensus or C++ changes. Later native Bond operations and private client
proof/finality/fee-import/full-rescan evidence remain separate pilot requirements.

Upstream comparison: this deployment path is absent in upstream TON at
857b8a57a178e6ae0fe7fa86e7d81c5233de8560. No inherited implementation changed.


## Separate official-CLI client allocation

The original operator policy and fixed5TOS allocation are unchanged. A separate
`tos.br1.public-client-policy.v1` policy selects exactly2TOS for one fresh V3R2
carrier owned by the official CLI. This new allocation requires explicit operator
authorization; the original operator5TOS approval does not authorize it. There is
no custom amount option. Both roles use the same approved PRI journal and overall
budget, with distinct operation IDs and durable attempt markers. Changing a role
or policy is never a retry mechanism for an unknown attempt.

The client policy retains all original gate/source/window fields and adds
`client`: `manifest`, `manifest_sha256`, `state_init`, `state_init_sha256`, `cli`,
`cli_sha256`, `config`, `config_sha256` and `vault_env`. The public manifest schema
is `tos.br1.public-client.v1`, with `global_id`, `genesis_root`, `genesis_file`,
`wallet`, `wallet_address`, `wallet_version`, `subwallet_id`, `public_key_hex`.
Only the approved Epoch6 identity, canonical TOS V3 code, zero initial sequence,
subwallet3 and exact manifest public key are accepted. Neither manifest nor policy
contains a private key. The private mode0600 environment file contains only the
local file `VAULT_URL`; never hash or display it.

Before source-key loading, the pinned CLI's offline wallet/key lists must bind the
manifest to the configured carrier and Vault public key. No private export is
used. Inspect has no Vault/key access; dry-run verifies custody but never signs
or broadcasts. After reviewing the unsigned packet and receiving the separate
client authorization, fund also requires `--acknowledge-client-2-tos`. Absence of
this flag refuses before loading any wallet runtime. The acknowledgement flag
records intent; it cannot supply human authorization by itself.

Client operation ID is `br1-pilot-client-fund-v1`; its persistent marker is
`br1-public-client-funding-v1.marker.json`. Every signing/unknown/terminal attempt
consumes the client allocation. Reconcile checks the same original destination,
amount and StateInit without source keys or rebroadcast. Never remove a marker,
change identity, or reset a journal to retry. Mock orchestration tests cover both
fixed roles independently; they do not claim public-chain acceptance.

Upstream comparison: these TOS deployment and official-CLI paths are absent in
TON master857b8a57a178e6ae0fe7fa86e7d81c5233de8560; no inherited code changes.


## Once-only recovery of the reviewed legacy pre-sign incident

`resume-dry-run` and `resume-before-sign` are client2TOS-only modes. They require
`--recovery`, its explicit `--recovery-sha256`, and
`--acknowledge-reviewed-presign-refusal`; funding also retains the existing
client2TOS acknowledgement and fresh dry-plan requirements. They never remove,
replace or edit the original allocation marker.

The receipt schema `tos.br1.reviewed-presign-incident.v1` is a **trusted operator
incident attestation**, not cryptographic evidence that a signature cannot exist.
Under the operator's standing technical-decision authorization, the test lead
must accept and record that trust scope after reviewing the complete local
incident. It is limited to the exact pinned legacy wrapper source whose guard
at line416 raised before the underlying signature. The receipt pins the original
marker SHA, original policy, original source, complete failure-log SHA and
`trusted_operator_attestation: true`. Log provenance is trusted local evidence;
a copied/truncated log from an untrusted party must never authorize recovery.

Current policy, source/destination/2TOS/nonce/StateInit plan must equal the
original exactly. Both peers must still prove the same unchanged source nonce
and a fresh empty target. Any unresolved PRI action, any non-dry entry for that
wallet/nonce regardless of operation, or malformed source-sequence metadata
refuses. The canonical PRI lock covers inspection, fencing and submission.

A separate exclusive, fsynced `br1-public-client-presign-resume-v1.marker.json`
precedes source-key loading. A second exclusive, fsynced
`br1-public-client-presign-resume-v1.signing-started.json` precedes underlying
crypto. A signing-start fence or resume marker is irrevocable: failures after
either do not authorize another resume. Any signed/ambiguous state only permits
readonly reconciliation of original bytes. The ordinary fund path still
refuses the retained original marker. No repeated nonce/identity/amount route
is provided. The additional mode is not a generic timeout/rebroadcast recovery.

Current68tests/28removed guards, including marker/fence/sign/journal/send cuts,
no-sign dry-run, other-operation/nonce conflicts and concurrent exclusive marker
creation, are in `evidence/br1-presign-resume.json`. Original26/11 and48/20 indices
remain historical at their own source pins. Source hashes and raw receipts are
retained; no secrets or private journals are committed. Mock tests are not a
live transfer claim. No C++/persistent daemon changes; one bounded incident JSON
16KiB and existing1MiB inputs plus two small durable fences.

The resumed signer rechecks its deadline after signing-start fsync and before underlying crypto. A late fsync leaves both fences intact and cannot be retried.
