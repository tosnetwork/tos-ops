# Local second-asset recognition: review gate

Status: **Analysis approved; local recognition adopted.**
See [the local execution record](T15-local-20261127.md) for adoption and the
[refund/returned continuation](T18-refund-completion-20261127.md) for later lifecycle evidence.
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

### Confirmed bridge selection

Test USDT shares the normal USDC bridge: source chain id **1**, ConfigParam
**79**, TOS bridge
`-1:733b321a0a2556eff5637d40d7e05724a69f8fa51c8ed7dfd22987ba6fe6a5b1`,
EVM bridge `0xe7f1725e7734ce288f8367e1bb143e90bb3f0512`.
Its normal wallet code hash is
`753bdf1d7cefd68aff17db60dd87fd3652c126b6045c1410a39a8f48b95b92cb`.
ConfigParam **81** remains the local refusal-test namespace only. No bridge or
code is replaced. ConfigParam 84 will contain **three** records: normal USDC,
the existing refusal test, and normal USDT. Every existing entry's actual cell
content must be preserved, not merely a decoded approximation or overall hash.

## Behavioural analysis before recognition

This is an analysis of the pinned bridge and the requirements on a local test
USDT fixture. It does not establish the behaviour of any production token:
no production token address, code, proxy implementation or release pin is
provided. Production recognition remains absent until governance and its own
review. Tests with an issuer-like fixture do not prove issuer trustworthiness.

### Verified issuer source and limits of the check

The read-only verified-source response for EVM chain 1 contract
`0xdAC17F958D2ee523a2206206994597C13D831ec7` was retrieved on 2026-11-27:
[verification metadata and source](https://sourcify.dev/server/v2/contract/1/0xdAC17F958D2ee523a2206206994597C13D831ec7?fields=all).
It reports creation and runtime `match`; the source is `TetherToken.sol`, UTF-8
SHA-256 `36bf0b5747dfe7f79a03c9bc09af63e93e352d3c61199fbf025fd2c962b485f8`
(including its CRLF line endings). The source and verification response are
retained outside Git as review evidence. This checks the published matching
source, **not current issuer settings**, backing, control of admin keys, a future
upgrade, or deployment approval. No transaction was sent to that contract.
References to `issuer:n` below name that exact source and line.

For bridge references, `B:n` means `contracts/Bridge.sol:n` at the running release.
`A:n` means `crypto/smartcont/service-actor-token-code.fc:n` in tools commit
`58015fcdfe3d3ea23ff23c1bfc6aec377361b38e`.
Actor citations describe that T3 tools commit, not the running `b9a5a0406` node release.
`M:n` means this repository's `testnet/scripts/check-settlement.py:n` at
`a841db9`; `P:n` means ai `provider/pkg/servicebridge/token_monitor.go:n` at
`9a35bd893f2cb0dfba47be258c6e7c1d41f13705`.

The actor has no EVM issuer oracle. TOS wallet transfers remain exact. An EVM
lock of the quoted price with a fee produces fewer wrapped tokens: funding an
actor with that price-minus-fee amount is refused by `A:1630-1631`, and the
funding return is created/sent by `A:1693-1715` when return capacity and funding
permit. If no return can be recorded, the tokens are surplus, explicitly logged;
this is not an accepted request. Existing TOS requests can still settle even
when their EVM backing is frozen; that is not a promise of EVM redeemability.
This actor behaviour applies to every row below.

| Behaviour and exact source semantics | Bridge handling | T3 actor handling | Control and present/absent status |
| --- | --- | --- | --- |
| **Fee switch:** `issuer:122-134,167-187,425-433`: `basisPointsRate < 20`, `maxFee < 50` whole tokens, `maximumFee = maxFee * 10^decimals`. Fee = min(value * rate / 10000, maximumFee); sender loses full value, owner receives fee; supply is not burned. | `B:191-215` locks/records/mints received balance delta; caps use that delta (`B:223-232`). `B:277-287,312-320` pay nominal unlock/refund amounts; recipients may receive less. | Exact-price rule above. Price-minus-fee funding is refused and returned, not silently accepted as full price. | **PRESENT checker:** `M:349-353` transfer_fee alarm; caps/headroom `M:295-314`. **ABSENT until T14b:** live issuer collection. **ABSENT until T19:** received-amount previews and budgeting from minted amount; current previews must not be described as fee-adjusted. |
| **Blacklist:** `issuer:336-352` checks only sender (`msg.sender` / `_from`), never recipient. Blacklisting the bridge leaves balance unchanged and still permits user-to-bridge locks and minting; bridge-to-user unlock/refund reverts. | `B:193` succeeds with a blacklisted bridge recipient; `B:286,318` fail when the bridge sends. Backing balance equality alone cannot detect this freeze. | No issuer blacklist read; exact TOS admission/settlement still applies. | **PRESENT checker:** `M:337-338` bridge_blacklisted -> bridge_frozen. **PRESENT manual runbook / immediate response required:** oracles vote `voteForDisableToken`, or `voteForSwitchLock` (the latter stops both assets); do not wait for status 2. The observer does not cast these votes. `M:345-348` receiver alarm exists but is conservative: issuer recipient blacklisting alone does not reject receipt. **ABSENT until T14b:** issuer collection. **ABSENT until T19:** redemption-tool prechecks. |
| **destroyBlackFunds:** `issuer:287-295` zeros the blacklisted account, decreases supply and emits **DestroyedBlackFunds without Transfer**. | No bridge compensation; balanceOf can fall without an unlock/refund, while wrapped supply is unchanged (`B:67-95`). | Existing TOS liability remains; no automatic balance haircut or fabricated repayment. | **PRESENT checker:** `M:341-342` destroyed_funds; `M:315-336` unexplained_decrease; `M:298-300` backing_shortfall. These latch the emergency hook. **ABSENT until T14b:** issuer-event and complete balance-interval collection; Transfer logs alone are insufficient. |
| **Pause:** `issuer:336,346` transfers are guarded by whenNotPaused. `approve` at `:365-370` is not pause-guarded. | TransferFrom/transfer revert, so lock/unlock/refund fail without crediting a successful lock. | Issuer pause does not alter TOS transfer semantics; existing requests still reconcile. | **PRESENT checker:** `M:339-344` current paused or any interval Pause event -> token_paused. **ABSENT until T14b:** current flag and event interval collection, including pause then unpause between observations. **ABSENT until T19:** burn-build pause check. |
| **No boolean return:** `issuer:336-370,195-204`: transfer, transferFrom **and approve** return no bool. | The pinned optional-return helper (`token/ERC20/utils/SafeERC20.sol:99-114`) accepts empty successful transfer returns, refuses false/revert; approval tooling must accept empty success too. | The EVM ABI is not used by the actor; ordinary exact TOS transfers apply. | **PRESENT:** bridge optional-return handling. Test fixture uses no-return calls. Public-testnet lock/unlock evidence remains a later case; it is not supplied by source inspection. |
| **Approval race:** `issuer:195-204` requires zero before changing a nonzero allowance to nonzero; approve is no-return and not paused. | TransferFrom consumes allowance. The bridge cannot make a user's allowance replacement atomic. | No EVM allowance handling in T3. | **ABSENT until T15 driver:** journal/finalize zero approval first when needed, then exact lock allowance; reconcile each nonce/receipt before proceeding. The original source-token driver is not a USDT zero-first implementation. No unlimited approval. Test and archive this before the local lock is claimed complete. |
| **deprecate/upgradedAddress:** `issuer:336-394` forwards transfers, approval, balances, allowance and totalSupply to `*ByLegacy`/getters after owner `deprecate` sets flag and target; **not a proxy upgrade**. | Bridge does not pin/veto the forwarding target. Its successful ABI calls may now have different behaviour or balances. | No source-upgrade detector; route remains its fixed TOS master, not a promise about upgraded backing. | **PRESENT checker:** `M:354-355` deprecated or changed implementation identity -> token_upgrade. **ABSENT until T14b:** flag, target and code-identity reads. Local fixture **includes deprecate and forwarding** to exercise it. A production review must re-pin the exact target code and behaviour before resuming. |

For all emergency rows, `M:27-33,364` emits the asset-scoped
`provider_pause_assets` hook (freeze, pause, destroy, unexplained decrease,
backing shortfall). Provider filtering is `P:63-71,103-124`; its own signed
`update_policy` clears active only for its actors of that asset. Fee and upgrade
alarms are **not** latched emergency execution stops. A stale or missing report
refuses paid execution via ai `provider/pkg/servicebridge/token_execution.go:16-36`.
Without T14b, the source inputs are missing: the checker and provider integration
are real, but there is no genuine live issuer observation to feed them.
**T14b is now a hard gate before the local USDT proposal and before production.**
T19 redemption/previews is a local follow-up and a hard production gate.

`B:434-442` uses a `uint8` decimals return type. An ABI `uint256` word containing
six is representable and decodes identically. A malformed or out-of-range return
can fail decoding in the caller: the `try/catch` must **not** be described as
converting every such failure to zero. Reverted calls may take the fallback;
a local decimal test must verify the actual raw 32-byte return and reject wrong
or malformed values.

The local fixture source is
[LocalUSDT.sol](../../contracts/test-usdt/LocalUSDT.sol). It models sender-only
blacklist, pause, capped owner-paid fee, no-return approve/transfers, zero-first
approval, DestroyedBlackFunds without Transfer, uint256 decimals and
legacy-forwarding deprecation. It is not a production clone or a complete
issuer-security proof; in particular it does not reproduce the old compiler's
short-payload modifier. Canonical clients must send full ABI arguments.
Do not combine deprecation and destruction in one rehearsal; the fixture
refuses `destroyBlackFunds` once deprecated.
It is not installed by any node or public profile. Build artifacts and keys stay
outside Git. Test both fields and behaviour against the actual compiled fixture.

## Execution and evidence checklist after the review and collector gates

1. Re-check health, zero-state equality and on-chain global id 3 on both send
   references. Use only loopback RPC. Confirm the slot-79 bridge's deployed code,
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
4. Derive the new master from the slot-79 bridge's **on-chain** minter/wallet
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
