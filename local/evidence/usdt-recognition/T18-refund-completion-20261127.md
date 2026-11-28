# Local USDT refund and returned-path completion

This continues the dated [partial record](T18-local-20261127.md); its original
stops, late archival and pruned-history gaps remain recorded. No public network,
validator service, issuer production token or new recognition entry was changed.
The network and asset identities are those in the [adoption record](T15-local-20261127.md).

## Resume before the new purchase

The issuer had already been unpaused. Under the coordinator's authorization,
the completed `usdt:token_paused` incident was explicitly acknowledged after fresh
source reads; no other incident was removed and the monitor baseline was retained.
The next ordinary monitor tick had no alarms, incidents or pause hook, at finalized
block 382549. This was a deliberate operator resolution, not an automatic reset.
It predates `testnet/scripts/resolve-settlement-incident.py`: the latch was
removed by editing the monitor's `incidents.json` by hand, and
`t18-refund/incident-resolution/resolved.json` records no sha256 of that file
before or after the edit. Later resolutions use the command, whose record
carries both hashes ([runbook](../../../testnet/settlement-monitor.md#runbook-reviewed-incident-resolution)).

The production provider action then resumed the actor: owner source LT
`417256000001`, hash
`bdaa04e3b16460cd18c9ea56c8a4c1cec6d2a0776b88b877da3b2d484bcb2029`;
actor LT `417256000003`, hash
`55bd8c7c2c9f610d0dad7c3643e4a7328a0e8c2aa4e311fe77772186358cef64`.
The entire graph was archived before the next funding. The actor is active with
policy version 3. The provider and buyer used ai source
`73b5893f9a1cb5f3d37f75f139dccdfb90fb2cb3`, whose state-read fix was subsequently
merged. The first independent verifier used the original T18 binary; the
committed-build repeat below used the state-read binary as well. The native-rail
follow-up is a separate work item.

## Successful buyer-driven refund

A new quote, per-asset budget and explicit custody confirmation funded request
3, hash `3c600a97b352106eb525d3cf8c11e28b17945bc7b07740436decade8a1d7849c`,
for 1,000,000 atomic test USDT. The provider work loop was deliberately stopped
for this timeout/refund case.

| Step | Wallet source LT | Source transaction hash |
| --- | --- | --- |
| Fund | 417470000001 | `a1118c55f3ab838b3f851913bb8323246939a3adf35371d0c98190581d683c52` |
| Expire | 420000000001 | `922f298107c8f24b82f0bd3f6661d2d0302dfc4841db4f4d53288cca263e39ea` |
| Claim refund | 420099000001 | `0c75f3e15884a26c0f6fb170150c6c381a5369b60ac1a2113762c4b68dd47751` |

Admission was actor LT `417470000007`, hash
`20301205c80fc63223f8e8474745d2b3a7e23dac67c7e5a623284eb91440fc26`.
After each wallet send, the buyer app was stopped and its graph durably archived
before starting the next lifecycle action. Restart reconciled the original send;
it did not resend. The final SDK result was `refunded`, `sent: false`.

The second process, running `tos-service-verify`, reconstructed `refunded` at
finalized block **385758**, root
`c8acac21eec5dc49ceb88f23183bc2a2837321e4089d3ce623e2f18a377e106f`,
file `915404028bdeedbc20e8b605129fa358be5e43aa2d0654077f43473c9d759990`.
It used independent nodes 4–6 through the retained-history transport described
below. This is the same resolver code in a separate process, not an independent
implementation or independently operated node quorum.

A second read-only reconstruction with the committed transport and state-read
verifier also passed at block **388751**, root
`468ba54a664bf9fe617079a7b6f00452e50751baeab05347b4febb47c351ec7f`,
file `994c13f160d392b86323214903b1b93975711d6f94cdc0de613ef13ad485c4b9`.
The monitor was fresh with no alarms, incidents or pause hook at checkpoint
388788; the provider work service and buyer app were active again. The issuer
remained unpaused. This repeat sent no value.

At same-block supply checkpoint 385757, balances sum to **25,000,000** atomic:
actor 1,000,000; actor owner 1,000,000; original bridge buyer 21,000,000;
work buyer 2,000,000. Actor wallet plus in-flight payouts covers attributed value;
all request/payout liabilities for this refund were cleared.

[The refund archive](t18-refund/INDEX.json) includes original transaction BOCs,
block bindings, verifier outputs, operator resolution and final supply/actor
reads. Each public file records its original SHA-256 and removed fields (none).
No lost older transaction cell is recreated.

## Pruned history and the explicit archive requirement

The fixed quote now derives recognition and current terms from finalized state.
The business resolver legitimately still needs the complete actor event chain;
that includes old calls, payouts and receipts. The ordinary local observers keep
only two hours of block archives and had already pruned part of this actor's
prefix. A production deployment therefore needs an archive-capable history
endpoint, or an authenticated retained transaction archive. State-only recognition
does not remove that separate execution/evidence requirement.

For this run, retained **actual BOCs**, previously saved at each finalized step,
supplied that prefix. Current state, finality, config and live transaction replies
continued to come unchanged from each distinct node. Only an explicit
`getTransactions` / `lt not in db` refusal used the content-addressed archive.
The production decoder still checked the cell hash, account, logical time and
entire predecessor chain from the live quorum-authenticated account head down
to the actual first transaction. Missing cells refuse; they never create a fake
terminal transaction. This is a transaction archive, **not** a full archive engine
or a claim that the live nodes retained the old cells.

The [test transport](../../tests/helpers/retained_transactions_rpc.py) makes this
procedure reviewable. It requires on-chain global id 3 and the exact expected
genesis, binds only loopback, limits files/cells/bytes/requests/threads, and holds
no signing keys. Explicit source routes forward a submission once with no retry;
reference routes reject all submissions. It loads the specified archives at
startup; restart the transport after adding archived steps. Never retry a value
operation because a transport reply was lost: reconcile its journal first.

Example, with all paths supplied by the operator:

```sh
python local/tests/helpers/retained_transactions_rpc.py \
  --upstream http://127.0.0.1:8011/jsonRPC \
  --upstream http://127.0.0.1:8012/jsonRPC \
  --upstream http://127.0.0.1:8013/jsonRPC \
  --upstream http://127.0.0.1:8014/jsonRPC \
  --upstream http://127.0.0.1:8015/jsonRPC \
  --upstream http://127.0.0.1:8016/jsonRPC \
  --archive-root "$ACTOR_ARCHIVE" --archive-root "$BUYER_ARCHIVE" \
  --genesis-root "$GENESIS_ROOT" --genesis-file "$GENESIS_FILE" \
  --submission-sources 3
```

Routes 19011–19013 map one-to-one to sending nodes 1–3, and read-only routes
19014–19016 to references 4–6. The archive's explicit provenance supersedes the
old wrapper's automatic direct-node provenance; the verifier's actual
`reads.endpoints` names the archive routes. All endpoints share this local
operator. No validator retention policy was changed during this measurement.

## Returned coverage: shared live proof plus USDT sandbox

The coordinator accepted the [shared live returned record](../service-token-returned-local-20261126.json)
and its [public transaction cells and second-resolver results](../service-token-public-20261126/returned/independent-returned-0.json).
It proves a genuine recipient-wallet refusal at R, an actor returned entry, a
successful claim, and the separately expired returned entry's sweep. That local
refusal namespace was normally governed and visibly test-only.

The T3 actor's returned path is asset-independent: normal USDC and normal USDT
use the same standard bridge wallet code. An additional refusal-test USDT entry
would exercise identical actor logic while requiring a fourth governed asset;
none was created. **This is not a claim of a new live USDT-specific refusal.**

The [test-only sandbox change](https://github.com/tosnetwork/tos/pull/530),
source `aa5a879d41cf7af0fed5ee4b42a4a2e5b1ba0c70`, adds
`usdt_returned_and_claim_match_the_usdc_path`. It uses
two distinct bridge-derived six-decimal masters under the same bridge codes,
including a USDT-configured actor. For each, a real wallet refusal at R creates
a returned entry for the original buyer; claim to a distinct destination then
delivers exactly the amount. Backing/supply assertions run after each step.
Deleting only the USDT actor's returned-entry update makes this test assertion-red.
The 99-test actor suite and 106-test bridge fixture regression suite pass and exercise
the unchanged defaults as well. All **134** transaction records of the new test were also replayed in the C++
emulator built from the same source: **zero differences**.
[The verification summary](t18-refund/sandbox-verification.json) binds the tools
and local logs by SHA-256. Production contract source and release artifacts
are untouched by that sandbox change.

## Verification of this continuation

- Operations regression suite: **4,163 passed, 72 skipped, 34 subtests passed**;
  one failure, `testnet/tests/test_supply.py::test_the_epoch6_profile_schedule_reaches_the_zero_state`.
  The same failure reproduced on unchanged main
  `a8145d095bab681350e305ff1af89b7aca3e2789` with the same running-build
  `TOS_ROOT`. No golden zerostate was changed.
- Focused driver/observer/lifecycle/archive baseline: **128 passed**.
- Re-runnable `local/tests/usdt_driver_mutants.py`: **38/38 assertion-red**,
  with setup/collection failures excluded; eight new archive controls cover
  pruning-only lookup, HTTP refusal, source/reference separation, byte/entry
  caps and on-chain network/genesis binding.
- The 24 retained-transport tests, Ruff check/format, changed document links and
  all original/public evidence hashes pass.
- The existing local network health check is healthy, with no errors or warnings.

## Scope and remaining dated gaps

The successful refund and the accepted returned coverage close the two cases
requested here. The original response/recovery archive-ordering gap, incomplete
cross-run USDC wallet inventory and any previously pruned unarchived cell remain
explicit limitations in the earlier record. Nothing relabels the original missed
refund as a refund. Public-network testing and production issuer recognition
remain separately gated.

Upstream comparison: these application SDK, test transport and token-actor
sandbox paths are absent at upstream `99143587e6babb2e577eadea0fc741cb1b413fab`;
no inherited consensus, VM or networking implementation is changed.
