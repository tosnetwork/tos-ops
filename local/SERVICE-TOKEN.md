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
claiming offer/buyer acceptance. This helper is not an offer publisher.

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

## Remaining end-to-end gates

The contract-driven cases do not replace a buyer purchase. A published token
offer, provider paid-work execution and the buyer's confirmed custody path
must run before claiming all layers passed. The buyer additionally requires
`wallet send --valid-until` and its v2 prepared-send document. Never substitute
another envelope or bypass a refusal to make that gate pass.

A genuine recipient refusal requires the design's separately pinned test-only
wallet build. Do not replace the real recognized wallet code or alter the
existing bridge/configuration to fake this outcome. Without that test setup,
record `returned` as blocked, not passed. USDT is a later acceptance run.

## Evidence and tests

The private state contains keys and signed BOCs: never commit or print it.
Retain raw public transaction/verifier receipts outside the repository and
commit only a bounded, sanitized result index with hashes and source pins.
Record every early refusal and interrupted attempt, even if a later attempt
succeeds. Leave the original network and election task running.

```sh
TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" -m pytest \
  local/tests/test_local_pq_service_token.py -q
uv run ruff check local/scripts/local-pq-service-token.py local/tests/test_local_pq_service_token.py
uv run ruff format --check local/scripts/local-pq-service-token.py local/tests/test_local_pq_service_token.py
```
