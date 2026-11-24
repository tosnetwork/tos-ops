# TOS Public Testnet Genesis Validator Invitation · December 5, 2026

We invite external operators to run a validator from genesis in the next TOS public testnet. You can apply even if you are new to TOS and have no wallet or tokens. You will need a Linux VPS you administer and time to prepare it before launch and be available for the first election.

## Official schedule (JST / UTC+9)

| Date | Activity |
| --- | --- |
| November 23, 2026 | Registration opens |
| November 30, 2026 | Registration deadline |
| December 1–4, 2026 | Preparation and coordination |
| December 5, 2026 | Public testnet starts |
| December 19, 2026 | Public testnet ends |

**Testing duration: 14 days. Reward: 1,000 TOS per qualified participant.** The team will communicate qualification and claim details. The coordinator will confirm the exact launch time and first election window during preparation.

## Start here

Finish registration by November 30. During December 1–4, work through the VPS setup, wallet creation and public record steps below with your coordinator. Before launch, confirm the exact time, your genesis seat and your availability for the first election. After launch, use the [election-cycle test plan](#test-plan-for-each-election-cycle) and send your results to the coordinator.

## What you will run

A validator is a server that synchronizes the chain and uses a consensus key to participate in block validation during its assigned term. An operator wallet pays the transaction fees for election and stake recovery messages. A separate staking pool holds the principal and is your validator's on-chain identity.

You can start with a zero-balance wallet. The coordinator allocates testnet TOS for operator fees and provides the stake principal through the pool owner. You create and control your operator wallet and consensus key on your own VPS. The coordinator manages the pool-owner wallet. Participation requires no token purchase or mainnet deposit.

## Register and prepare your VPS

1. Apply through the original recruitment channel or contact the team member who invited you. Share your operator name, time zone, availability during preparation and launch, and your VPS's operating system, CPU architecture, CPU count, memory and free disk space. Ask for help if you have never prepared a Linux server. The coordinator will confirm your seat before genesis.
2. Use a dedicated VPS with Ubuntu 24.04, sudo access, access to the provider console, and a public IPv4 address or approved UDP forwarding. The current validator preflight requires at least **4 vCPUs, 11 GiB of OS-visible memory and 60 GiB of free disk space**. Check the hardware SHA-256 requirements. If you use arm64, confirm the supported build or release artifact with the coordinator before proceeding. [CPU requirements](https://github.com/tosnetwork/tos/blob/main/doc/Validator.md#cpu-instruction-set)
3. During December 1–4, get your node name, operator label, pinned `tos` and `tos-ops` commits, and preflight instructions from the coordinator. Install the pinned operations bundle, synchronize the system clock, and prepare the validator and `tosctl` using the operator guide. Allow inbound UDP 30001 and 31001 in both the provider and host firewalls. Keep console TCP 30002 closed to public traffic, and keep RPC 8081 and metrics 9100 on loopback. Arrange any required SSH access directly with the coordinator. Share public keys and access details through the agreed channel, and keep private keys and passwords private. [Host preparation and installation commands](OPERATOR.md#2-host-requirements-clock-and-preflight)

## Create your first operator wallet

After installing `tosctl`, run this on your VPS. Replace the placeholder with the node name assigned by the coordinator.

```bash
NODE_NAME='<YOUR_NODE_NAME>'
sudo /opt/tos-testnet/scripts/init-operator.sh --name "$NODE_NAME" --wallet-only
```

Wait for the command to finish. The final line prints `op-<YOUR_NODE_NAME> <WALLET_ADDRESS>`. Send the **public wallet address** to the coordinator over the agreed channel. The wallet key stays in the operator vault on your VPS. Keep the vault, `/etc/tos/tosctl.env`, wallet keys and consensus seed private.

The coordinator derives a staking pool using your public wallet address and sends you the pool address as your **validator ID**. Confirm that the coordinator used your wallet address, then create your public validator record on the same VPS. Replace the three placeholders before running the commands.

```bash
VALIDATOR_ID='<POOL_ADDRESS_FROM_COORDINATOR>'
OPERATOR_LABEL='<YOUR_OPERATOR_LABEL>'
PUBLIC_IPV4='<YOUR_VPS_PUBLIC_IPV4>'
sudo -u tos python3 /opt/tos-testnet/scripts/testnet-operator.py record \
  --db /var/lib/tos/validator \
  --seed /var/lib/tos/validator/keys/pq-consensus.seed \
  --validator-id "$VALIDATOR_ID" --operator "$OPERATOR_LABEL" \
  --address "$PUBLIC_IPV4:30001" --out /tmp/record.json
```

Send **`/tmp/record.json`** to the coordinator and confirm receipt and validation before genesis. If you need to view the public record first, run `sudo -u tos cat /tmp/record.json`. If a command fails, send the error and stop at that step until the coordinator helps you resolve it. It contains your public identity and network address. Run this consensus identity on only one host. [Wallet, staking pool and validator record instructions](OPERATOR.md#4-staking-account-and-public-record)

## Activate and join the first election

1. **Verify the genesis packet.** The coordinator supplies the global config, public genesis files, expected zero-state identity and a SHA-256 checksum for the config over a separate authenticated channel. Verify the checksum and activate the validator during the agreed window. [Activation commands](OPERATOR.md#5-activate-and-verify-custody-and-synchronization)
2. **Confirm synchronization.** Check that the node service is active, the custody log names your pool, and your local chain head advances after launch. Ask the coordinator to compare your node against a reference node for network identity and agreement on a recent block.
3. **Check election setup.** The coordinator funds the operator wallet and pool, configures the election service and reconciles the receipts. Check that the service is active and that your operator wallet has enough for elections. The election service submits the pool's stake during the window. [Election onboarding and wallet balance check](OPERATOR.md#6-onboard-for-elections)
4. **Confirm your term.** Ask the coordinator to verify that the Elector accepted your pool's stake for the intended election and that your pool appears in the active validator set once the new term starts.

If the previous election schedule is retained, the first election opens **five hours after genesis**, accepts stakes for **45 minutes**, and hands over to the elected set **six hours after genesis** if the election succeeds. Plan your availability using the final times confirmed by the coordinator.

## Monitor your validator during the test

- Check node and election service status, chain progress, restarts, free disk space and operator wallet fee balance.
- At each election, confirm stake acceptance and active-set membership. Check stake recovery when it is due. Report an expired term even if blocks are still advancing.
- If chain progress stalls, an election fails, fees run low or disk usage grows unexpectedly, report the UTC time, node name, public pool address, last chain head and relevant sanitized log lines. If the outcome of a transaction is unclear, ask the coordinator to reconcile the original attempt before retrying.
- Tell the coordinator before scheduled maintenance or leaving so they can check your active duties and outstanding stakes.

[Daily checks, log commands and fee monitoring](OPERATOR.md#7-daily-checks-and-fee-top-ups)

If you contact the team after genesis, ask about running an observer node. The current automated onboarding tool requires the pool to be listed in the genesis records. The team will communicate a separate process for admitting new validators to a running network once that process has been verified.

## External participation milestone

To declare the external validator test successful, at least **five independent
external operators**, excluding the TOS organizer, must each run their own
validator, synchronize it, have their stake accepted, and take up duties in
an elected validator set. Count distinct operators, with one count per
operator across all their nodes. The coordinator will verify each operator's
pool against the election records and the active set for the relevant term.

## Test plan for each election cycle

The coordinator posts the election ID and the open, close and handover times with their time zone. Use the live schedule for each cycle. Pick a cycle you can observe in full. Keep the node running between checks and coordinate maintenance in advance. If you miss a checkpoint, mark it as missed and record what you can still verify.

| When | What you do | What counts as a pass |
| --- | --- | --- |
| Before the window opens | Record UTC time, node and election service state, current head, free disk, restart count and operator wallet balance. Ask the coordinator to confirm the current term and fee runway. | Both services are active after onboarding. Your head advances and agrees with a reference node. The balance covers the upcoming election and the coordinator's reserve. |
| While the window is open | Read the election log. Note the election ID, your pool address, any submission result and when it appeared. Ask the coordinator to confirm your pool's accepted stake for that election. | The Elector records the stake for the intended election and pool. Any refusal or uncertainty has a recorded outcome before another attempt. |
| After the window closes | Ask the coordinator for the elected-set result and expected handover time. Record whether your pool was selected. | The election result accounts for the submitted stake. If selected, your pool is listed for the new term. A documented selection outcome is evidence even if you were not selected. |
| After the scheduled handover | Check head progress and service status again. Ask the coordinator for the key-block ID, active-set term and your pool's status. | The new set takes effect at the expected handover, observers agree on the key block, and your pool's active membership matches the election result. |
| When an earlier stake becomes recoverable | Check the election log for recovery activity and confirm the outcome with the coordinator. | The coordinator accounts for the earlier stake in the pool, records the recovery receipt or gives the on-chain reason it is still held. Mark recovery as pending until verified. |
| In a quiet part of the term | Run the short local read check below. Compare it with your own baseline and record the time and any concurrent event. | All requests return a valid head, heights do not go backward, and the head advances across the sample. Record latency and resources for comparison. |

For the first cycle, focus on onboarding, stake acceptance and the first handover. In the next cycle, repeat the checks without reconfiguring the wallet and look for the first due stake recovery. During later cycles, repeat the read check before and after a handover, as separate runs, and compare results. One normal cycle gives a baseline. Repeated checks can reveal growing disk use, declining fee balances or a node that falls behind only around handovers.

### Take a local snapshot

Run these commands on your validator VPS before and after the checkpoints. Copy only public identifiers and relevant, sanitized output into your report.

```bash
date -u '+%Y-%m-%dT%H:%M:%SZ'
systemctl is-active tos-testnet-validator tos-testnet-elections
systemctl show tos-testnet-validator -p NRestarts -p MemoryCurrent
df -h /var/lib/tos
sudo journalctl -u tos-testnet-elections --since '-30 minutes' --no-pager
```

Use the wallet balance command in the election guide. If a service is inactive or you cannot verify an election step, record the result and contact the coordinator with the UTC time and election ID. During initial synchronization, an advancing head still needs to be checked against the reference node. [Operator wallet balance command](OPERATOR.md#6-onboard-for-elections)

### Run a short read performance check

Once synchronized, run this on the VPS. It sends one read-only request at a time to localhost, with one second between requests. It uses Python 3 from the setup procedure and requires no wallet balance. Establish a quiet baseline before making comparisons. If you get an error, keep the summary and report it with your snapshot.

```bash
python3 - <<'PYTHON'
import json
import math
import statistics
import time
import urllib.request

url = "http://127.0.0.1:8081/"
body = json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "getMasterchainInfo", "params": {}
}).encode()
request = urllib.request.Request(
    url, data=body, headers={"Content-Type": "application/json"}
)
latencies = []
heads = []
for sample in range(20):
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.load(response)
        if "error" in payload:
            raise ValueError(f"RPC error: {payload['error'].get('code', 'unknown')}")
        heads.append(int(payload["result"]["last"]["seqno"]))
        latencies.append((time.monotonic() - start) * 1000)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Sample {sample + 1} failed ({error})")
    if sample < 19:
        time.sleep(1)

print(f"Successful reads: {len(latencies)}/20")
if latencies:
    ordered = sorted(latencies)
    p95 = ordered[math.ceil(0.95 * len(ordered)) - 1]
    print(f"Local RPC latency: median {statistics.median(ordered):.1f} ms, p95 {p95:.1f} ms")
    print(f"Masterchain head: {heads[0]} -> {heads[-1]}")
    print(f"Head ever moved backward: {any(b < a for a, b in zip(heads, heads[1:]))}")
PYTHON
```

Keep the success count, median and p95, first and last heights, and whether the head moved backward. This is a small sample of local RPC responsiveness and chain progress. Network transaction throughput and finality latency are measured in the coordinated workload below.

### Participate in the coordinated performance window

The coordinator publishes a UTC window, workload, rates, pass criteria and stop conditions. The coordinator operates the transaction generator and funds the designated load wallets. As a validator operator, keep your node online, take the local snapshot just before and after the window, and run the short read check when requested. Record head progress, read errors, memory, restarts and disk change. Report lag, sustained errors, a restart or an election delay immediately.

For the first public load window, use the same workload at **50, 100 and 200 transfers per second**, advancing only after the previous step passes. Start after normal handovers are verified and schedule the initial run away from election and handover checkpoints. For a comparable short ramp, the coordinator records the offered and completed transfers, backlog change, verified inclusion/finality latency, and failures and duplicates. At 100 transfers per second, use the previous ramp's comparison criteria of at least 99% completion within the measurement window and backlog growth of at most 100 transfers, followed by full reconciliation. The coordinator publishes the exact measurement window and gates before the run. Keep a separate result for any later workload that overlaps a handover.

Leave the workload rate and stop decision to the coordinator. Keep the operator wallet available for elections. Schedule restart or recovery exercises separately, after the coordinator verifies which validators can be taken offline while preserving quorum.

### Send one report per observed cycle

Copy this template and send it through the agreed channel. Use `PASS`, `FAIL`, `PENDING` or `NOT RUN` for each result. Include the reason for pending or skipped checks.

```text
Epoch and node name:
Public pool address:
Election ID and observed UTC interval:
Pre-election head, wallet balance, free disk, memory and restarts:
Stake acceptance (result and public receipt or coordinator reference):
Handover (result, key-block ID, active term and membership):
Previous stake recovery (result and receipt, if due):
Read check (UTC, successes/20, median/p95, first and last heads):
Coordinated load window (if any, host observations before and after):
Incident or unresolved item:
```
