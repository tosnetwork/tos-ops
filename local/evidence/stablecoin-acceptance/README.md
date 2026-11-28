# Local stablecoin final acceptance (partial)

**Status: stopped at 02:04 UTC on 28 Nov, before the hour-2 canary steps.**
The running monitor unit failed (see [the stop](#the-stop)). The emergency
drill, the fee-on-transfer case, the no-`bool` case, the canary's hourly and
per-lock refusals and the hour-0/1 locks are complete. Not yet run:

- the daily-cap and total-cap refusals;
- the raise vote and the larger lock;
- the lock-switch drill.

This record covers the stablecoin final acceptance on the existing local PQ
network. The owner decided (2026-11-28, memo decision 32) that it replaces the
public-testnet stage. It covers:

- the canary and the cap raise;
- the emergency disable and the lock-switch drill;
- the fee-on-transfer and no-`bool` cases.

Both assets, test USDC and LocalUSDT, sit behind the same local bridge.

The run uses local global id 3 and the approved genesis of the
[T15 adoption record](../usdt-recognition/T15-local-20261127.md): root
`65735247…c366`, file `c3860fe1…8769`. The source chain is the loopback anvil
chain (id 1), and all value is local test value. During the run:

- no network was created or reset;
- no validator, election task or bridge was replaced;
- no recognition record was changed;
- no running unit's configuration, binary or path was modified.

Times are UTC. The run started on 2026-11-27 and finished on 2026-11-28.

## Identities

| Item | Value |
| --- | --- |
| Running engines | `b9a5a0406193d3577022b5c856bab9f77836f58b` (`TOS_ROOT=/tos/usdc-t5-tos`) |
| EVM bridge | `0xe7f1725e7734ce288f8367e1bb143e90bb3f0512` |
| Test USDC (TestFeeToken, fee 0) | `0x5fbdb2315678afecb367f032d93f642f64180aa3`, master `0:f366cb32…fb06` |
| LocalUSDT | `0x610178da211fef7d417bc0e6fed39f05609ad788`, master `0:181e00fd…9591` |
| TOS bridge | `-1:733b321a…a5b1` |
| Minted-token holder | bridge buyer `0:14eda362…4979` |
| USDT actor / USDC control actor | `0:dab3c57e…6df3` / `0:3d56b9e8…a8f2` (the T18 actors) |
| Monitor | the running `tos-local-usdt-monitor` collector and checker (T14b/T14c), state `/data/usdt-t15-monitor` |
| Provider and buyer tools | ai main `21061423d7aa43ebb975d15bda14d1f1db898c94`, except the provider's own actions (below) |

The second resolver is the same code running in a separate process. It reads
nodes 4–6 only, at one finalized masterchain checkpoint that matches on all
three. The sending endpoint is node 1. For the token actor, the independent
`tos-service-verify` reads nodes 4–6 through the running retained-history
transport (routes 19014–19016, which reject submissions). This is because the
actor's oldest transactions are pruned from the nodes (see the
[T18 completion record](../usdt-recognition/T18-refund-completion-20261127.md)).
Each verifier provenance file says which routes were used.

## How every value step was recorded

`local/scripts/local-pq-stablecoin-acceptance.py` journals each send before
signing it, through the shared send journals of `local-pq-usdc.py`.

- **EVM sends** are fixed to one nonce and one calldata. The canonical receipt
  and its source finality are archived before the next send.
- **TOS sends** are archived the same way: their transaction and every
  transitive internal delivery, with their block ancestry, as cells that match
  byte for byte on nodes 4–6 at one finalized checkpoint.

The next value step refuses while the previous one is unarchived. Lock
refusals were shown with `probe`, which works in three moves:

1. Approve exactly the probe amount, so that the token transfer itself
   succeeds and only the bridge's cap check decides.
2. Simulate `lock` at one pinned source block, and require the named revert.
3. Reset the allowance to zero.

No refused lock was mined. Lock tooling approves exactly and clears a non-zero
allowance first, as section 7.5 requires.

## 1. Canary for USDC, then USDT

The caps come from decision 12 (the task brief pointed to item 13, but the
caps are in item 12): total 1,000, per lock 100, hourly 200, daily 500 tokens.
They were adopted through the T16 oracle-quorum `voteForLockCap`, the bridge's
governed path for caps, which takes effect at once (nonce 2 for each token).
The ConfigParam 84 `max_liability_per_actor` values were not changed: 10,000
tUSDC and 10 tUSDT.

| Step | USDC | USDT |
| --- | --- | --- |
| Canary caps vote | `0xf94483b9…cbbf` | `0x136b271e…2070` |
| Lock 100 (27 Nov, hour 22) | n=2, minted 100, supply 125 at mc 456295 | n=4, minted 100, supply 125 at mc 458244 |
| Lock 100 (hour 22) | n=3, minted 100, supply 225 at mc 456716 | n=5, minted 100, supply 225 at mc 458605 |
| Probe 1 → `lock: over the hourly cap` | block 49465 | block 50227 |
| Probe 100.000001 → `lock: over the per-lock cap` | block 49600 | block 50371 |
| Locks 100 + 100 (28 Nov, hour 0) | n=9, 10; supply 435 at mc 470891 | n=11, 12; supply 433 at mc 471725 |
| Locks 100 + 100 (hour 1) | n=13, 14; supply 635 at mc 479341 | n=15, 16; supply 633 at mc 480210 |
| Lock 100 (hour 2) → day at 500 | not run | not run |
| Probe 1 → `lock: over the daily cap` | not run | not run |
| Total lowered to balance + 50, probe 100 → `lock: over the token cap` | not run | not run |
| Raise vote | not run | not run |
| Lock 150 (over the old per-lock cap) admitted | not run | not run |

**Planned total-cap probe (not run).** Under the decision-12 caps, the 1,000
total cannot be reached quickly. The daily cap of 500 means at most 725 tokens
of backing by the end of 28 Nov. The plan, in `commands/canary-1128-h2.sh`, is
to show the total-cap refusal under a cap vote that sets the total to the
current balance plus 50 (a lowering also takes effect at once), then to raise
the caps at once. The decided caps' hourly and per-lock refusals were shown
live under the decided values. The daily refusal needs a third lock in hour 2
of the same UTC day.

**Observation windows.** Each window was several consecutive monitor reports.
Every report had a distinct checkpoint, was fresh (at most 120 s old), named
the same checkpoint as its snapshot, and had no alarms, latched incidents or
pause hook (`observe --expect-clean`).

- **Hour 23 of 27 Nov:** `canary-window-1127h23-w2-1…5`, five clean reports.
- **Emergency recovery:** `emergency-resolved-window-1…3`, three clean
  reports.
- **Hour 2 and after the raise:** not run. The first hour-2 observation
  refused because the monitor report was stale (see below).

While a rate bucket was full, the monitor correctly reported `hourly_headroom`
and `lock_headroom` (`monitor-1127h22-cap-saturated`). Those alarms are not
emergencies and latch nothing.

Two refused observations are kept:

- `canary-window-1127h23-1` read a finalized source block that was still in
  hour 22.
- `…-run2` caught the collector's mid-tick stale marker. The observer now waits
  (bounded to 30 s) for a report that names its snapshot's checkpoint.

## 2. Emergency drill (LocalUSDT)

| Step | Evidence | Result |
| --- | --- | --- |
| Blacklist the bridge in LocalUSDT | `usdt-blacklist-bridge`, `0xe6704114…83ab` | finalized |
| Collector raises the emergency | `emergency-frozen-monitor`, mc 465612 | `usdt:bridge_frozen` alarm, latched; `provider_pause_assets: ["usdt"]` only |
| Buyer refuses USDT | `buyer-lock-preview-refused` (T19 preview, production `buyersdk.PreviewTokenLock`) | `issuer receiver is blacklisted` |
| Redemption refuses before any burn body | `redemption-refused-frozen` (T19 `prepare-token-redemption`) | `redemption source bridge is blacklisted` |
| Provider auto-pause, USDT | `provider-auto-pause-usdt`, then `…-reconcile` | one pause; actor active 1→0, policy v3→v4 |
| Provider auto-pause, USDC | `provider-auto-pause-usdc` | no action; USDC actor active, v1 |
| `voteForDisableToken(true, USDT)` | `usdt-disable-token`, `0x86a2edc3…3cc9` | disabled |
| New USDT lock refused | `usdt-disabled-probe` | `lock: disabled token` |
| USDC unaffected | `usdc-during-usdt-freeze` | 10 tUSDC locked and minted |
| Unblacklist | `usdt-unblacklist-bridge`, `0x3899e757…fc18` | finalized |
| Re-enable by vote | `usdt-enable-token`, `0x1f0915c2…2dbb` | enabled |
| Latch survives recovery | `emergency-recovered-latched`, mc 467411 | alarm gone; incident and pause hook still latched |
| Incident resolution | `usdt-incident-resolution` | only `usdt:bridge_frozen` archived; next report clean |
| Provider resume | `provider-resume-usdt`, `…-reconcile` | actor active again, v5; one resume |
| Actor and asset resume | `usdt-after-recovery`, `emergency-resolved-window-1…3` | 10 tUSDT locked and minted; three clean reports |
| Reconciliation | `after-emergency-reconcile`, mc 468859 / source 54175 | USDC 235 = 235, USDT 233 = 233 |

**Auto-pause outcome.** The first auto-pause call sent the pause, then returned
`the outcome of a sent message is not yet established`. One rerun of the same
production `CheckTokenSafety` call reconciled that journaled operation to
finalized. The provider journal holds exactly one pause record
(`3f22d7eb…`), and the policy version rose by one. The resume behaved the
same way: `submitted`, then `finalized` on the rerun with the same idempotency
key. It ran in transaction LT 502375000003, hash `b5efa259…98a7`.

**Incident resolution.**
`local-pq-stablecoin-acceptance.py resolve-incident` is the runbook's explicit
resolution, done under the checker's own `monitor.lock`. A concurrent tick
publishes STALE once and retries, so the running unit was not stopped. Before
it touches anything, it checks four things:

- the condition is gone at a finalized source block;
- the token is re-enabled and locks are open;
- the latch exists;
- a fresh report no longer raises the alarm.

It keeps a byte copy of the latch, baseline, report, policy and binding files.
It removes only the named latch and then requires the next published report to
be clean. Its records are under `incident-resolution/usdt-incident-resolution/`.

**Provider tools.** The provider's own actions used the binaries the running
provider service uses (`tos-service-provider-state`, `provider-monitor-apply`).
They were executed read-only from their existing location, so the running
provider's journal format was never mixed with another build.

## 3. LocalUSDT fee-on-transfer

The fee was turned on with `setParams(10, 49)`: 10 basis points, maximum fee 49
tUSDT (`usdt-fee-on`). The monitor raised `usdt:transfer_fee`
(`usdt-fee-on-monitor`). This alarm is not an emergency.

| Step | Result |
| --- | --- |
| T19 lock preview, nominal 1,001,001 (`t19-lock-preview-fee-on.json`) | issuer fee 1,001, minted 1,000,000, budget debit 1,000,000, with the exact-amount warning |
| Lock 1,001,001 (`usdt-fee-lock`, n=6) | bridge received 1,000,000; `Lock` event value 1,000,000; supply +1,000,000 = 226 at mc 462815 |
| Fund the actor with the nominal 1,001,001 | refused with reason 1902 and returned (payout 7); verifier `funding_returned` at mc 463016 |
| Fund the actor with the minted 1,000,000 | admitted as request 4 (`pending`); after its real response deadline the buyer expired it and claimed the refund; verifier `refunded` at mc 465030 |
| Unlock 2 tUSDT with the fee on (`usdt-burn-fee-on`, `usdt-unlock-fee-on`) | T19 redemption preview 1,998,000; receiver got 1,998,000; bridge fell by 2,000,000; supply 224 = backing 224 |
| Fee off with `setParams(0, 0)` | T19 preview shows fee 0 |

The first direct verification of the nominal funding (`fee-nominal-verify`)
refused. Its history read hit a pruned transaction, LT 420099000009. It was
retried read-only through the retained-history routes.

## 4. LocalUSDT `transfer` without a `bool`

LocalUSDT's `transfer` and `transferFrom` return nothing. Every LocalUSDT lock
above is a `safeTransferFrom` against it. Both unlocks are a `safeTransfer`.

- **The fee-on unlock:** described above.
- **The fee-off unlock** (`usdt-burn-fee-off`, `usdt-unlock-fee-off`):
  - burn of 1 tUSDT to `0x90f79bf6…b906`;
  - `LOG_BURN` decoded from the TOS bridge transaction cells, LT 498306000001;
  - oracle-signed `unlock`, `0x5619fcd4…dd28`;
  - the receiver got exactly 1,000,000, and the bridge balance fell from 224
    to 223, equal to the supply.

## 5. Bridge lock-switch drill

`Bridge.sol` has no pause of its own. Its stop is `voteForSwitchLock`, which
stops every lock.

Not run. Its script (`commands/canary-1128-h2.sh`) stopped at its first
observation, before any value step.

## Final state

Read at the stop (`stop-state-reconcile`, mc 488141, source block 61862, nodes
4–6):

| Asset | Wrapped supply | Bridge balance | Reconciled | Caps (total / per lock / hourly / daily) | Disabled | Locks open |
| --- | --- | --- | --- | --- | --- | --- |
| USDC | 635,000,000 | 635,000,000 | yes | 1,000 / 100 / 200 / 500 tokens (the canary values) | no | yes |
| USDT | 633,000,000 | 633,000,000 | yes | 1,000 / 100 / 200 / 500 tokens (the canary values) | no | yes |

At the stop:

- the caps are the decision-12 canary values, the documented value for now;
- the planned raise to 10,000 / 1,000 / 2,000 / 5,000 was not voted;
- the monitor's latch file is empty;
- the drill's only incident was resolved through the procedure;
- both actors are active (USDT v5, USDC v1).

The monitor's last published report predates the failure, so "clean reports at
the end" is not claimed after 23:57.

## The stop

At 23:57:18 the running `tos-local-usdt-monitor` unit exited with status 1.

- **What failed.** Node 4 answered its `getMasterchainInfo` with
  `RATE_LIMITED -32005`. The resulting `testnet_lib.RpcError` is not among the
  exceptions the monitor loop catches, so the process ended instead of
  publishing STALE and retrying.
- **What caused it.** The burst of reads came from this run's attempt to
  archive the provider's pause transaction on nodes 4–6. The attempt started
  at 23:57 and was stopped at 00:04.
- **Consequences.** The same burst refused one hour-0 lock start before any
  journal entry. With no unit refreshing it, the report stayed stale. This is
  fail-closed: the provider and buyer refuse paid work on a stale report.
- **Coverage.** The hour-0/1 canary locks ran while no monitor was running, and
  this record does not claim monitor coverage for them.
- **Exact exception.** The read raised `testnet_ops.Unknown` wrapping the
  `RpcError`; both are `testnet_lib.TestnetError`.

## Monitor recovery

The coordinator authorized the recovery on 28 Nov. It is in
`monitor-recovery/`.

1. **Fix.** [tos-ops #122](https://github.com/tosnetwork/tos-ops/pull/122)
   makes every `TestnetError` a STALE tick, with a back-off bounded at 60 s.
   Red controls show the crash without the fix. It also adds a one-shot
   `--gap-dir` to the local monitor (runbook step 4).
2. **Before.** The digests of every monitor state file were retained
   (`state-digests-before.txt`).
3. **Gap batches.** `reconcile-settlement-gap.py` ran in 260 bounded batches of
   32 blocks, from the original baseline at source block 54198 until
   `caught_up` at 62491 (`batches.log`, `gap-batches/`). No baseline was reset
   and no incident was cleared.
4. **Gap tick.** One `--once --gap-dir` tick evaluated the whole interval: exit
   0, no alarms. It advanced the baseline to source block 62501 (TOS mc 489742)
   (`gap-tick.log`).
5. **Restart.** `systemctl reset-failed`, then the same `systemd-run`
   launcher and limits. The launcher was a copy of `monitor.sh` that differs
   only in pointing to the fixed checkout. Every tick since has been fresh and
   clean.
6. **Execution admitted.** The provider's production `CheckTokenSafety`, run by
   the signing-disabled helper, then reported the monitor `fresh` with no asset
   alarm (`provider-admits-after-restart.json`).

From then on, the run kept its RPC load low and made no bulk archive reads.

## Dated limitations

- **Monitor coverage.** There was none from 23:57 on 27 Nov to 02:15 on 28 Nov.
  The gap reconciliation evaluated that interval afterwards and found no
  alarms.
- **Provider transaction cells (known gap).** The provider's pause and resume
  transactions are identified by its journal records and by the finalized
  actor-policy reads on nodes 4–6, which stand in for the cells; the cells are
  not in this archive. The bulk archive attempt walked block ancestry from those
  older transactions to a current checkpoint. It caused the rate limit that
  ended the monitor, and it was not repeated.
- **Interrupted start.** One hour-0 lock start refused at its startup read,
  because node 4 rate-limited it during that archive attempt. Nothing was
  journaled or sent, and the same label was rerun.
- **Buyer refusal.** It is shown through the buyer's T19 issuer read, the
  production preview API, rather than through the long-running buyer agent's
  socket.
- **Funding sources.** Mint fees were paid from 90 + 20 TOS of local test value,
  taken from the original governance payer's unused local allocation (T15).
  This avoided stopping the election service for the faucet. The canary USDT
  for the locker came from the LocalUSDT owner.

## Files

`INDEX.json` lists every committed file with its SHA-256. Every
`removed_fields` is empty. In `commands/`, the operator's home directory path
was replaced by `$HOME`; those entries carry both digests and a note. The private journal (`state.json`,
signed messages) and all keys stay on the host.

- **`evidence/`:** step results.
- **`archive/sends/`:** TOS transaction cells and ancestry.
- **`archive/monitor/`:** retained monitor observations.
- **`source-transactions/`, `source-finality/`:** EVM receipts and finality.
- **`incident-resolution/`:** the resolution's records.
- **`actor-usdt/`:** the actor driver's archived graphs and verifier outputs for
  the fee cases.
- **`provider-actions/`:** the provider actions' inputs, previews and results.
- **`commands/`:** the orchestration scripts that were run.
- **`logs/`:** each step's console output.

## Verification

- Full operations suite (`local/tests testnet/tests`, `TOS_ROOT` = the tos
  main checkout): **4,267 passed, 65 skipped, 34 subtests passed**.
- Driver and actor-driver tests: 127 passed.
- `local/tests/stablecoin_acceptance_mutants.py`: **31/31 assertion-red**, with
  a green baseline.
- Ruff check and format pass on every changed Python file.
- The driver refuses a non-loopback source endpoint. Every TOS read checks the
  approved genesis and global id 3 on nodes 4–6.

Upstream comparison: these local operations drivers have no upstream
counterpart at `99143587e6babb2e577eadea0fc741cb1b413fab`, and no inherited
consensus, VM, bridge or networking code changed.
