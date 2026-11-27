# Persistent local PQ network

**Local development only; no public funds or production privacy claim.**
Get explicit approval under [AGENTS.md](../AGENTS.md) before reset, funding or
service changes. Read [prerequisites](README.md#prerequisites) first. Stop and
retain receipts on any refusal; do not clear journals to force a retry.

`sudo TOS_ROOT="$TOS_ROOT" local/scripts/setup-testnet.sh --clean` creates a fresh development network:
four PQ validators, two non-validator observers, a DHT, an independent
lite-client and the development shielded pool. `--build` rebuilds its binaries.
`--clean` deletes the existing `/data` network, keys, state and node file logs.

## Ten-minute elections

Add `--rotate` to enable real Elector elections with Config15
`600 / 300 / 60 / 180` (elected period / election lead / election close lead /
stake holding period, in seconds). The initial set also expires after 600
seconds. This mode uses deterministic development consensus keys and a
disposable staking wallet key per candidate.
It must never initialize a production chain.

The initial active set is nodes `1,2,3,4`. Node `7` is a fifth candidate process,
not an additional Genesis validator. The `tos-pq-elections` service submits
node-authorized stakes for `1,2,3,7`, then `1,2,3,4`, alternating each
round. Exactly four candidates enter each election. Nodes `5,6` remain ordinary
observers. All five candidate processes stay online, including the retired
member, so absence of its first-hop traffic is evidence of relay selection
rather than a disconnected destination.

Each candidate stakes directly from its own masterchain wallet, which is also
its validator id; all wallet transactions use local test funds. The service
checks each Elector acceptance and retains the submitted roster; acceptance is
not an activation verdict. The chain itself selects and activates the next set.
The development faucet tops each wallet up to the next stake, and the service
recovers returned stakes into the same wallet; it is not a production
staking/recovery manager. An ambiguous transaction outcome is kept in its
journal for reconciliation and is never paid again
([README.md](README.md#staking-wallets-and-continuous-elections)).

## Inspect and verify

```sh
local/scripts/testnet-ctl.sh status
local/scripts/testnet-ctl.sh check
sudo journalctl -u tos-pq-elections -n 30 --no-pager
sudo env TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" \
  local/scripts/check-local-pq-relays.py --output /data/elections/relay-verification.json
```

Evidence lives under `/data/elections`: Config15 bytes, candidate public
identities, actual node authorizations, Elector acceptance and recovery events,
per-candidate wallet observations (`wallet-<i>.json`), agreed
Config34 bytes at one common height on seven full nodes, and raw two-step
broadcast trace lines. Console credential files and the staking wallet keys
are private; do not publish them.

The relay checker requires a real one-member replacement, a 600-second elected
interval, and every current validator's broadcast to target exactly the other
three current validators. The same broadcast ID/content hash must finish on
all three receivers. It excludes 20 seconds of in-flight work after observing
activation. Retired members may still receive second-hop broadcasts; that is
separate from eligibility as a first-hop relay. Four active validators exercise
the simple two-step path, not the five-relay FEC threshold.

Tests: see [README.md](README.md#tests).

## Random transfer verification

`local-pq-transfers.py` uses three independent, randomly generated development
wallets. It alternates the submission endpoint across all seven full nodes,
sends 0.01–1 TOS at random 2–8 second intervals after each completed check,
and checks sender seqno, send/receive message binding, compute/action success,
recipient balance delta including fees, agreement of the two accounts across
seven nodes and a common masterchain block ID. Raw transaction BOCs and results
are retained under `/data/transfers`; logs rotate at 16 MiB with four backups.
These ordinary test wallets use Ed25519, while validator consensus remains PQ.
This tests public transfers, not shielded transfers or every protocol invariant.

Bootstrap funds each wallet with 200 local TOS. Stop the election service only
in a quiet interval after its submissions have completed; it exclusively owns
the Genesis wallet. Always restore it after bootstrap, including on failure.
Bootstrap refuses an active election service and already deployed wallets.

```sh
sudo systemctl stop tos-pq-elections
sudo env TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" \
  local/scripts/local-pq-transfers.py --bootstrap
sudo systemctl start tos-pq-elections
sudo systemctl enable --now tos-pq-transfers
sudo journalctl -u tos-pq-transfers -n 10 --no-pager
sudo cat /data/transfers/status.json
```

The service is installed by setup but starts only after bootstrap. `--count 5`
runs a finite sample, `--seed` reproduces the random selection sequence and
`--min-interval`, `--max-interval`, `--min-amount`, `--max-amount` tune the load.
The interval excludes transaction/check latency. A failure stops the service;
it does not automatically resubmit an ambiguous transaction. Inspect receipts
before restarting an unresolved run. Keep `/data/transfers/*.seed` private.

## Random shielded-pool traffic

`tos-pq-privacy` runs alongside `tos-pq-transfers`, using three separate test
wallets and `/data/privacy-transfers` (0700). It randomly chooses deposits,
private note transfers, and withdrawals, waiting 20–60 seconds between completed
operations. Deposits and withdrawals use the pool's fixed denominations;
private transfers choose a random positive amount. When too little private
value remains for a withdrawal, the next operation is a deposit.

Build the development message generator before enabling the service:

```sh
cd "$TOS_ROOT/tools/shielded-pool-circuit/crosscheck"
TOS_ROOT="$(git rev-parse --show-toplevel)" cargo build --release --locked -j4 --bin local_pool_traffic
```

During a quiet election interval, bootstrap once (the Genesis wallet must have
one owner at a time):

```sh
sudo systemctl stop tos-pq-elections
sudo env TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" local/scripts/local-pq-privacy.py --bootstrap
sudo systemctl start tos-pq-elections
sudo systemctl enable --now tos-pq-privacy
```

Bootstrap writes `configs/privacy-test.json`; it never overwrites the ordinary
transfer wallet config. `setup-testnet.sh --build` also builds the generator;
`--clean` stops both traffic services before clearing their old keys and receipts.

Every operation checks the real pool transaction's compute and action success,
commitment/nullifier roots and indices, native liability and backing. Withdrawals
also require a matching payout message and recipient balance delta including its
fee. Pool data, funding-wallet and recipient account snapshots must agree across
all seven full nodes. Confirmed counters are in `status.json`; transaction BOCs
are in the private rotating JSONL log. Note secrets, pending plans and test keys
are private and must not be published. The prover caches the development proving
key in memory; its child process is stopped with the service.

This exercises the deployed **development-key** pool; it is not a production
privacy or ceremony claim. Output payloads are random test bytes, not a wallet
encryption implementation, and proving uses the library's development randomness.
The local witness model is bounded to 4096 commitment leaves and the wallets have
finite test funding. A limit, timeout, refusal or state mismatch stops the service
without automatically resubmitting. Inspect the retained pending plan and receipts
before restarting; do not clear a failure just to restart traffic. The first live
smoke test exposed an arbitrary-withdrawal-amount bug (exit 202), fixed by requiring
configured denominations. Its failed receipt is retained separately and not counted
as a successful withdrawal.

## Test USDC through the token bridge

`local-pq-usdc.py` brings a six-decimal test token across the token bridge onto
this network: a loopback EVM chain (chain id 1, the chain ConfigParam 79 serves)
with the test token and `Bridge.sol`, the TOS oracle multisig and bridge,
ConfigParams 79 and 84 adopted through `testnet/scripts/testnet-governance.py`
(`--local-network /data/network.json`, which signs each round's votes on the local
consoles), a `voteForLockCap` before the token's first lock, and a mint to a buyer
wallet. A stand-in oracle signs the v5 votes; its keys, and the test wallets', are
generated under `/data/usdc/keys` (0700) at the first run and never leave the host.
`fund` pays the test wallets from the Genesis wallet, so it needs the same
quiet-interval stop of `tos-pq-elections` as the bootstrap above.

The steps, their order, the commands and the expected outputs are in
[testnet/CEREMONY.md 8.3](../testnet/CEREMONY.md#83-test-usdc-through-the-token-bridge-usdc-settlement-t5).
Evidence is written to `/data/usdc/evidence/`, one JSON file per step; `status`
prints the recorded facts and the live token balance and ConfigParams.
Tests: `local/tests/test_local_pq_usdc.py` and
`testnet/tests/test_governance_settlement_assets.py`.

## Token actor lifecycle checks

The journaled [local token actor procedure](SERVICE-TOKEN.md) reuses the bridge
run and its minted test balance without resetting this network. Its evidence
distinguishes contract-driven checks from the complete buyer/provider run.
