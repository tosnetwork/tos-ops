# Local second-asset recognition: review gate

Status: **PREPARATION ONLY; no USDT record proposed or adopted by this work.**
This document is the behavioural review input, not a production release pin or
an assertion that the live acceptance cases have passed. A non-author must review
this analysis before the second record is proposed. There is no external-audit
requirement for this local exercise.

## Source and network identity

The running local node release is
`b9a5a0406193d3577022b5c856bab9f77836f58b`, global id 3, version 16.
Its zero-state root is
`65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366`
and file hash is
`c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769`.
The bridge source was compared with tos
`74802d7a5ba56dbda17ee92feeeb0cb448098ff8`; the EVM contracts directory
has no differences between these revisions. File references below are to the
running release, under `crosschain/token-bridge/evm/` unless stated otherwise.
The pinned optional-return dependency is version 4.8.2 in `package-lock.json`.

Upstream comparison: the operations driver and the token-rail recognition
integration have no counterpart in the upstream core at
`99143587e6babb2e577eadea0fc741cb1b413fab`. This is local deployment work;
no inherited core path is changed.

### Bridge selection hold

Read-only inspection found normal test USDC on chain id **1**, ConfigParam
**79**, TOS bridge
`-1:733b321a0a2556eff5637d40d7e05724a69f8fa51c8ed7dfd22987ba6fe6a5b1`.
Its EVM bridge is `0xe7f1725e7734ce288f8367e1bb143e90bb3f0512`.
Its normal wallet code hash is
`753bdf1d7cefd68aff17db60dd87fd3652c126b6045c1410a39a8f48b95b92cb`.

ConfigParam **81** instead names the earlier local-only refusal namespace,
chain id 56, TOS bridge
`-1:907e0a0911d7c43a999c57385953157a698621b96fddf9b72cab180bb82311af`.
That bridge embeds the deliberately modified wallet code hash
`cf5c98a11cf3de09b1cf702fa1eba38d870c822abb866320bba2da59dac013df`.
It is not the normal bridge and has no corresponding deployed EVM bridge.

The instruction to share USDC's bridge and the instruction to use slot 81
therefore cannot both be applied to this network as it stands. No bridge
replacement, generation change or reuse of refusal code is implicit. Confirm
whether to share the existing normal slot-79 bridge; otherwise a separate
reviewed migration is needed. Preserve every existing ConfigParam 84 entry,
including the local refusal test entry.

## Behavioural analysis before recognition

This is an analysis of the pinned bridge and the requirements on a local test
USDT fixture. It does not establish the behaviour of any production token:
no production token address, code, proxy implementation or release pin is
provided. Production recognition remains absent until governance and its own
review. Tests with an issuer-like fixture do not prove issuer trustworthiness.

| Behaviour | Source fact and consequence | Required local evidence / operational rule |
| --- | --- | --- |
| Transfer-fee switch | `contracts/Bridge.sol:191-215` measures pre/post bridge balances, records and emits the **received delta**, then charges caps on that delta. A fee on unlock/refund can still reduce what the recipient receives: `:277-287`, `:312-320` use the nominal amount in the event. | Start the local fixture at zero fee; verify received delta, lock record and minted amount at one source block. Never infer a redemption credit from the nominal event amount alone. The public-testnet fee variant remains a later case. |
| Blacklist, pause and destroyed backing | `Bridge.sol:184-189` has an oracle-controlled disabled-token gate; transfers can also revert. Neither that gate nor caps undo an existing issuer freeze, burn or shortfall. Caps read the actual balance, so destruction may reduce apparent exposure while wrapped supply stays unchanged (`:67-95`). | The local fixture must have explicit blacklist and pause switches. Later freeze rehearsal observes the report, disables new business, pauses only the affected actors and keeps existing TOS requests settleable. Check both bridge and receiver restrictions before redemption. Never claim the bridge can recover issuer-destroyed backing. |
| No boolean return | `lock`, `unlock` and `refundLock` use optional-return transfer calls. The pinned helper's `token/ERC20/utils/SafeERC20.sol:99-114` requires a successful call, accepts empty return data and refuses a returned false. | A genuine no-return fixture is supported without a recognition bypass. Reverted, false and malformed returns are failures. The separate public-testnet no-return exercise remains pending. |
| Approval race | `Bridge.sol:193` consumes the user's allowance. It cannot make replacing one nonzero allowance with another atomic with respect to a spender. | Only approve the named bridge and the exact intended lock amount. If allowance is nonzero, first journal and finalize a zero approval, then the new approval. Reconcile nonce and receipt on interruption; do not blindly resend or issue an unlimited allowance. |
| Upgrade path | The bridge neither pins a source token's implementation nor vetoes its upgrades. Its disabled-token and cap votes are controls, not guarantees about an issuer's next implementation. | The local fixture is non-proxy, with runtime bytecode archived. That does not cover a production proxy. A production review must identify admin/implementation, upgrade authority and delay, supported getters, and monitoring/review triggers before a record is proposed. |
| Decimal width | `Bridge.sol:434-440` calls `decimals()` as `uint8`, returning zero on failure. An ABI `uint256` value of six has the same 32-byte word and is representable; this does not justify accepting arbitrary values. | The new fixture must expose `uint256 decimals()` returning exactly six. Archive the raw return word and the bridge getter result, and refuse any other value or malformed answer. |
| Caps and oracle admission | `Bridge.sol:223-268` enforces total/per-lock/fixed-hour/fixed-day caps on received amounts; an unset cap refuses locks. Fixed buckets allow two buckets' worth across a boundary. Caps do not govern refunds/unlocks. | Independently allowlist the exact test token in the oracle, vote test-sized caps, archive `getLockCapState` at the lock's block and verify headroom. Open its minter channel before unrelated locks can consume capacity. Do not change another asset's caps. |

The existing `contracts/TestFeeToken.sol` is insufficient for the full freeze
rehearsal: it has six decimals as **uint8**, no-return transfers and a fee switch,
but no blacklist, pause, destroy or upgrade mechanism. It also permits direct
nonzero-to-nonzero approvals. A local-only fixture with the stated interface must
be reviewed and its source/compiler/runtime hashes recorded; it is not a
production substitute.

## Execution and evidence checklist after both review gates

1. Re-check health, zero-state equality and on-chain global id 3 on both send
   references. Use only loopback RPC. Confirm the chosen bridge's deployed code,
   immutable namespace, generation, codes and channel room at one finalized
   checkpoint. Keep all existing services and CPU caps unchanged.
2. Deploy the reviewed six-decimal local fixture with a durable intent before
   signing. Archive the creation transaction, receipt, source and runtime hashes
   before any cap vote, approval or lock. Keep private material outside Git.
3. Configure the exact source token's caps/allowlist. Approve and lock a small
   amount, then mint to a fresh test buyer with the normal bridge flow. Bind every
   intent to its nonce/message hash; unknown outcomes stop later value actions.
   Archive each finalized source transaction and each transitive TOS message graph
   before the next step. No reset, direct mint, state override or recognition
   bypass is permitted.
4. Derive the new master from the chosen bridge's **on-chain** minter/wallet
   codes and the new source token. Record one canonical checkpoint and its block
   root/file hashes, bridge storage and code BOCs, master code/data and getters.
   Both validators must agree at that checkpoint. Source bytecode pins supplement,
   never replace, this on-chain re-derivation.
5. Append exactly one record to the current ConfigParam 84 value. Preserve every
   existing record byte-for-byte. Run the canonical builder and governance
   decoder: at most 16 entries and 1,024 validation cell visits; exercise both
   refusal boundaries in tests. Verify each normal asset's identity, six decimals,
   status, minter/wallet code hashes and its own max liability. The refused test
   namespace is not a normal client pin.
6. Use the existing critical proposal/vote procedure with fresh release evidence
   and one-entry change checks. Archive each registration/vote transaction as it
   finalizes, before signing the next. A proposal sent once is reconciled by its
   journal and hash, never blindly registered again.
7. After adoption, independently verify both normal records at the same finalized
   block from nodes 4-6, while sends use nodes 1-3. Archive the CP84 cell and all
   verifier inputs/outputs, raw BOCs and SHA-256 manifests. An evidence gap is a
   failure to complete this run, not a reason to claim historical reconstruction.
8. Only then deploy USDT-fixed actors and run the USDT lifecycles alongside USDC.
   Check `wallet balance + payouts in transit >= attributed` after every step;
   reconstruct every result using the independent verifier process/endpoints.
   Exercise the USDT-only alarm, leaving the USDC actor and budget unaffected.

No live acceptance result is asserted in this file. Fill a separate immutable
run record with the exact commits, commands, checkpoints, transaction identities,
per-step archive manifests and PASS/FAIL classifications when the gates open.
