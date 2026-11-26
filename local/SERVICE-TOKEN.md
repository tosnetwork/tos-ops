# Local test-token actor lifecycle checks

Local development only. This procedure uses the **existing** network and the
minted balance from [the bridge run](OPERATIONS.md#test-usdc-through-the-token-bridge).
It never resets the chain, changes a validator service or uses the Genesis wallet.
No public-network acceptance is implied.

## Prerequisites

- An approved existing global-id-3, version-16 network, with its matching
  `TOS_ROOT`, `/data/network.json` and healthy `testnet-ctl.sh check`.
- Completed bridge run in `/data/usdc`, with test USDC in its buyer's wallet.
- A separate clean `TOKEN_TOOLS_ROOT` checkout containing the token actor,
  and its built `tosctl` in `TOKEN_TOSCTL`. Building client/contract tools does
  not require replacing the running validators.
- An ai checkout in `AI_ROOT`, built `service-actor-token-e2e-fixture`,
  `tos-service-verify` and `tos-service-provider`, and explicit authorization
  to spend local test funds. Apply this host's thermal/build limits.

Build the Go tools from the ai module root:

```sh
go build -o "$TOKEN_BIN/" ./protocol/cmd/service-actor-token-e2e-fixture \
  ./protocol/cmd/tos-service-verify ./provider/cmd/tos-service-provider
```

Set `TOKEN_STATE` to a new private directory outside either repository. Preserve
it for the whole run. The driver holds an exclusive lock, fsyncs every signed
intent before broadcast, and reconciles exact external hashes on rerun.
An expired or ambiguous send refuses; it is never re-signed automatically.
Do not delete an intent or reuse a step name with new parameters.

From the tos-ops root define the command once:

```sh
t10() {
  sudo -n env TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" \
    local/scripts/local-pq-service-token.py "$@" \
    --state "$TOKEN_STATE" --running-tos "$TOS_ROOT" \
    --tools-tos "$TOKEN_TOOLS_ROOT" --tosctl "$TOKEN_TOSCTL" \
    --fixture "$TOKEN_BIN/service-actor-token-e2e-fixture" \
    --verifier "$TOKEN_BIN/tos-service-verify"
}
t10 prepare
t10 fund
t10 deploy
t10 configure
```

`prepare` builds the unsigned test-profile actor with a 1 tUSDC price and
600-second response/refund windows, using the shared Go builder. It generates
only local test-owner keys in the private state directory. `fund` journals
20 TOS from the bridge run's deployer to this owner and activates it; it does
not stop the election task or access the Genesis wallet. `deploy` journals
5 TOS from that owner with the exact prepared StateInit. Repeating them checks
and reuses their receipts. Keep the deployer's remaining allocation intact.

`configure` writes independent bridge/asset pins and the owner-private client
configuration. Its default capability selector is **unpublished**: this is
sufficient for state inspection, not an offer or a buyer purchase. A real
published token Capability and its canonical manifest must be provided before
claiming offer/buyer acceptance. The separate publication step below binds the existing actor to a real offer.

## Contract lifecycles

Each `call` uses the bridge buyer and persists the CLI's unsigned document
before the signed wallet intent. Calls and follow-up operations are distinct
steps. Read the actual assigned request IDs from the independent verifier;
do not assume them on an actor with earlier calls.

```sh
t10 call --case responded
t10 call --case refunded
t10 call --case swept
t10 call --case funding-refused
t10 call --case surplus
```

The last two deliberately build an incorrect-terms call and a below-budget
funding notification through the shared SDK. They must respectively return the
tokens and classify them as surplus; a pre-sign CLI refusal is not that test.

Use `send --case <unique-step>` with the documented `service-token send`
arguments for `respond`, `expire`, `claim-refund`, `sweep-expired-request` and
`recover-surplus`. Use `--sender-wallet buyer` for caller-authorized claims.
For example, after looking up the assigned request ID:

```sh
t10 send --case expire-request --operation expire --request-id "$REQUEST_ID"
t10 send --case refund-request --sender-wallet buyer --operation claim-refund \
  --request-id "$REQUEST_ID" --destination "$BUYER_WALLET"
t10 send --case sweep-request --operation sweep-expired-request --request-id "$SWEEP_ID"
t10 send --case recover-surplus --operation recover-surplus --token-amount 1000000
```

Expire/sweep refuse until the finalized chain time reaches the respective
request deadline. The CLI may otherwise warn and let an operator submit early;
this runner deliberately does not. Never shorten or bypass those guards.
A wallet send receipt alone does not prove an actor operation succeeded.

`topup` accepts `service-token top-up` arguments, for example `--target wallet
--amount-nanotos 1000000000`, and journals the owner's send. Provider management
uses its own preview/digest/custody journal; keep those receipts as well.

After every transition the runner records a three-reference, common-block
snapshot and checks:

```text
token wallet balance + in-flight payouts >=
  pending + refundable + returned + in-flight + token revenue
```

Independently reconstruct request outcomes:

```sh
t10 verify --case responded
t10 verify --case refunded
t10 verify --case swept
t10 verify --case funding-refused
t10 verify --case surplus
```

`verify` invokes `tos-service-verify` with strict-majority finalized reads and
independent release pins. It requires the named terminal state, not merely a
successful resolver invocation. Keep the returned JSON and common-block
snapshots. Owner payout delivery also needs its authenticated outcome evidence;
the funding's original `surplus` classification alone is not proof of recovery.

## Published offer and buyer-driven work

The buyer requires `wallet send --valid-until` and
`tosctl.wallet-prepared-send.v2`. Pin the exact rebuilt binary, installed with
trusted ownership and without group/world write permission. Do not change the
running validators. Run custody commands in their private vault environment;
never put a vault URL containing credentials in an argument or a log.

1. Run `tos-service-provider init` in its established custody environment,
   first without `--yes`, then with it. Use the local global config,
   `--network-label tos:global-id:3`, three matching RPC endpoints, the owner's
   wallet/configuration, the token actor code hash, registry BOC and pinned
   tosctl. Give it a separate `--rail-config` and `--state-dir`. Keep its JSON
   result as `$TOKEN_STATE/publication-init.json`; the result names the
   registered Agent and address, not a key. Registration attaches 2 TOS.
2. With that provider stopped, run:

   ```sh
   t10 publish --provider-runtime "$TOKEN_BIN/tos-service-provider" \
     --published-config "$PROVIDER_CONFIG"
   ```

   This derives the token manifest through the shared builder, journals its
   Agent, digest and nonces before signing the Capability registration, and
   sends the registration, attestor rotation and metadata update as distinct
   immutable steps. It verifies the Capability's code on three references.
   Reuse the same private state after interruption. Never delete a saved
   nonce, signed document or unresolved intent. The publication lock refuses
   an already running provider.
3. Configure the existing provider's relay and real software-work executor
   using the provider runbook in the ai repository. The written provider
   section initially names a private executor socket; replace that with the
   installed executor's socket or the documented pinned subprocess executor
   configuration before serving. Use `token --inspect offer` to check the
   finalized binding. `serve` publishes the signed relay card in the configured
   offer file. The native `offer` deployment command is not a token deployer.
4. Establish a separate non-root buyer custody account and vault using
   `tos-service-buyer init plan`, then `init apply --yes`, with a distinct
   developer uid and a shared-group socket directory in mode 2750. Keep its
   state and keys in mode 0700/0600. The buyer wallet must have an expiring
   envelope; do not import the bridge run's non-expiring wallet as the buyer.
   `fund-work-buyer --destination "$WORK_BUYER"` journals exactly 6 TOS and
   3,000,000 atomic token units to this new local wallet, retaining at least
   1 TOS at the original native source. It refuses a changed destination and
   never repeats completed funding after the buyer has spent its balance.
5. Add the independently checked asset pins and per-call/window atomic limits
   to the buyer's `token_assets` configuration. Keep its native-fee budget
   separate. Start the buyer agent. Obtain the canonical source archive with
   the ai buyer's source packer or MCP source tool; arbitrary tar serialization
   is deliberately refused.
6. From the developer account, use the non-signing client:

   ```sh
   python3 local/scripts/local-pq-service-token-buyer.py prepare \
     --socket "$BUYER_SOCKET" --state "$BUYER_CLIENT_STATE" --case purchase-one \
     --offer "$TOKEN_OFFER" --archive "$SOURCE_ARCHIVE"
   python3 local/scripts/local-pq-service-token-buyer.py request-payment \
     --socket "$BUYER_SOCKET" --state "$BUYER_CLIENT_STATE" --case purchase-one
   ```

   The client persists the offer/archive/socket identity before the request;
   retries reuse the quote and idempotency key. It cannot confirm or sign.
   Inspect the buyer custody confirmer's exact token and native budgets, then
   confirm there. Use the client's `status`, `result` and `refund` steps with
   the same socket, state and case. Refund respects the real chain deadlines;
   it does not manufacture expiry. A third preparation above the asset window
   cap must be refused before signing.
7. Export from the buyer custody account with `tos-service-buyer evidence
   --config "$BUYER_CONFIG" --request-hash "$REQUEST_HASH" --out-dir
   "$NEW_EXPORT_DIR"`. Run `tos-service-verify` against a separate reference
   endpoint set, with independent network, registry, actor and asset pins,
   the exported evidence, receipt and artifact. Record each common-block
   backing snapshot separately from the wallet send receipt. Run `t10 audit-supply`
   to reconcile the original supply across the bridge buyer, owner, actor and
   work buyer at one checkpoint on three references. `audit-owner` follows
   short history pages up to its fixed 64-transaction receipt window; it never
   assumes a short page is the end of history.

For a live execution-safety test, inject an explicitly labelled local monitor
report with the asset alarm, then a stale report, while the second funded task
is pending. Record both refusals and that no execution slot was created. Keep
execution refused until its real refund completes; restore the normal report
only afterward. This is a monitor fault injection, not an on-chain asset freeze
and not a substitute for the production monitor's own acceptance tests.

## Remaining returned-case gate

The actual receiver checks the sender's deterministic wallet identity and its
supply bound (`token-wallet.fc`, `receive_reported_tokens`); the dispatcher
requires the receiver compute budget before entering it. The recognized wallet
has no owner-configurable incoming-transfer refusal. Its terminal/burn flags do
not create such a refusal. Correctly funded transfers within the existing small
supply therefore offer no honest deterministic refusal at the receiver.

The proposed smallest test-only build adds a deliberate receiver refusal for
one test recipient to the reported-transfer handler. Its changed code hash
requires an isolated, correctly derived and explicitly pinned bridge/minter/
wallet namespace and an ordinary recognition entry. It must not replace code
or state at an existing address, impersonate the recognized asset, or bypass
recognition. Deployment of that test setup requires a separate coordinator
choice. It has not been deployed. Record `returned` as blocked until that
choice and a real authenticated refusal outcome. The second asset remains a
later acceptance run.

The current client also requires the latest transactions of pinned bridge and
minter accounts to remain retrievable. A local stale-history refusal was
resolved by two real 0.01-TOS storage donations, using their documented empty-body
paths; recognition, code and configuration were unchanged. This does not fix
long-term historical availability and is recorded as a follow-up.

## Evidence and tests

The original contract-path run is indexed in
[evidence/service-token-usdc-20261126.json](evidence/service-token-usdc-20261126.json).
The subsequent buyer/provider run is indexed in
[evidence/service-token-buyer-usdc-20261126.json](evidence/service-token-buyer-usdc-20261126.json).
The latter records the two independent verdicts, export hashes, monitor fault
injections, funding receipts and four-wallet conservation check.

The private state contains keys and signed BOCs: never commit or print it.
Retain raw public transaction/verifier receipts outside the repository and
commit only a bounded, sanitized result index with hashes and source pins.
Record every early refusal and interrupted attempt, even if a later attempt
succeeds. Leave the original network and election task running.

```sh
TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" -m pytest \
  local/tests/test_local_pq_service_token.py local/tests/test_local_pq_service_token_buyer.py -q
uv run ruff check local/scripts/local-pq-service-token.py local/tests/test_local_pq_service_token.py
uv run ruff format --check local/scripts/local-pq-service-token.py local/tests/test_local_pq_service_token.py
```

Upstream comparison: these local operations and client adapters have no upstream
counterpart; inherited validator and VM code is unchanged.
