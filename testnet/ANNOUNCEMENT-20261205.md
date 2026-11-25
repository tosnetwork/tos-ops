# TOS Public Testnet Validator Invitation · December 5, 2026

We invite external operators to run a validator in the next TOS public testnet. You register before genesis and join the validator set from the first election, about six hours after launch. You can apply even if you are new to TOS and have no wallet or tokens. You will need a Linux VPS you administer, time to prepare it before launch, and to be available for the first election. This is a new network with its own genesis; it does not continue any earlier TOS testnet.

## Official schedule (JST / UTC+9)

| Date | Activity |
| --- | --- |
| November 23, 2026 | Registration opens |
| November 30, 2026, 23:59 JST | Registration deadline |
| December 1–4, 2026 | Preparation and coordination |
| December 5, 2026 | Public testnet starts |
| December 19, 2026 | Public testnet ends |

**Testing duration: 14 days (December 5–19, 2026).** The coordinator will confirm the precise start/end times and first election window during December 1–4. The dates above are Japan Standard Time (JST, UTC+9); election times and your reports use UTC.

## Registration, launch and reward conditions

**Pre-launch recruitment threshold (November 30).** At least **five distinct independent external validator applicants** must register by the November 30 deadline and be confirmed as credible candidates. The TOS organizer, team-controlled nodes and duplicate accounts operated by the same person do not count. **If fewer than five qualify by the deadline, this public test campaign will not proceed, and no validator-participation or recruitment rewards will be paid under this campaign.** Five applications are a minimum recruitment gate, not proof of test success or a guarantee of launch; technical and safety readiness must also be confirmed.

**External-participation success threshold.** The technical milestone requires **at least five independent external operators** to successfully synchronize nodes, have their stakes accepted by the Elector, enter an elected validator set, and actually perform validation duties during an elected term. One operator counts once regardless of how many VPS instances, wallets, pools, or validators they operate. The coordinator verifies the results against chain records and supporting operational evidence. See the [external participation milestone](#external-participation-milestone).

**Individual reward is a separate determination.** The announced reward is **1,000 mainnet TOS per qualified individual**, paid **after the mainnet launch**, and not paid in testnet tokens. Registering, preparing hardware, or appearing in an election does not automatically qualify anyone. Individual eligibility requires approved onboarding, participation during the assigned **14-day test**, acceptable node uptime and synchronization, completion of requested tests, and supporting evidence/feedback. The team will publish the exact uptime threshold, acceptance method, exceptions and claim instructions **before testing begins on December 5**. Until those rules and the individual's results are verified, individual reward qualification is pending. A person running multiple nodes cannot claim more than one participation reward. The collective success threshold does not by itself determine anyone's individual reward outcome.

**Where the reward comes from.** The reward is funded from the staking rewards that validators operated by the TOS team earn on mainnet. It is not a new issuance or an allocation from the genesis supply, and it does not change the token economics. It is paid out as those rewards accrue, so payment starts after mainnet launch and may arrive in instalments; mainnet has no fixed launch date. **At most 21 individuals can receive the reward in this campaign.** If more than 21 qualify, the team will publish how the 21 are chosen together with the rules before December 5.

**Eligibility, tax and terms.** One set of rules applies to every participant in every country: the [Validator Reward Terms and Eligibility Policy](VALIDATOR-REWARD-TERMS.md). It is a draft under legal review and will be final before December 5. If it and this invitation differ on any matter the policy covers, the policy wins.

- **U.S. persons are not excluded.** U.S. citizens and U.S. tax residents must meet the same eligibility conditions as everyone else, and before payment they provide IRS Form W-9.
- **Who cannot take part:**
  - sanctioned persons, and people resident in comprehensively sanctioned countries or regions;
  - the team's own members and contractors.
- **Before payment:**
  - identity verification, which enforces one reward per person and sanctions screening;
  - tax documentation, for example Form W-9 or W-8BEN;
  - a mainnet address you control.

  These are collected only after mainnet launch, through an announced channel. Nobody will ever ask you for a key, a seed or a payment.
- **Tax is your responsibility.** Many tax authorities, the U.S. IRS among them, treat tokens received for services as income at their market value when received. The paying entity may report payments to tax authorities and withhold tax where the law requires. Nothing here is legal or tax advice.
- **No legal conclusion yet.** No conclusion has been reached that the reward complies with the law of any particular jurisdiction. The token's classification, the reward source, the paying entity and the services terms are still under review, and the policy may change for a jurisdiction if that review requires it.
- **Changes to the campaign.** The team may change or cancel this campaign before December 5 by announcing it in the official channels. After that, published rules change only to correct errors, to follow the law, or as the legal review requires, and every change is announced.

**Costs and key safety.** No TOS purchase or mainnet deposit is required. Testnet TOS has no value, and the testnet may be paused, reset or ended early. Participants cover their own VPS and networking costs unless separately agreed. Never send the coordinator, support staff, or other participants your mnemonic, consensus seed, wallet private key or vault credentials.

**Your data.** The team keeps your operator name, contact handle, time zone, VPS public IP address and the public records you send, only for the purposes in section 9 of the [policy](VALIDATOR-REWARD-TERMS.md): running this test, verifying results, one reward per person, sanctions screening, tax compliance and paying rewards. Public chain data stays public. Ask the coordinator to delete the rest after the campaign ends.

## Start here

Finish registration by November 30. During December 1–4, work through the VPS setup, wallet creation and public record steps below with your coordinator. Before launch, confirm the exact time, your validator seat and your availability for the first election. After launch, use the [election-cycle test plan](#test-plan-for-each-election-cycle) and send your results to the coordinator.

## What you will run

A validator is a server that synchronizes the chain and uses a consensus key to participate in block validation during its assigned term. An operator wallet pays the transaction fees for election and stake recovery messages. A separate staking pool holds the principal and is your validator's on-chain identity.

You can start with a zero-balance wallet. The coordinator allocates testnet TOS for operator fees and provides the stake principal through the pool owner. You create and control your operator wallet and consensus key on your own VPS. The coordinator manages the pool-owner wallet. Participation requires no token purchase or mainnet deposit.

## Register and prepare your VPS

1. Apply through the original recruitment channel or contact the team member who invited you. The official Discord entry is https://discord.tos.network. Share your operator name, time zone, availability during preparation and launch, and your VPS's operating system, CPU architecture, CPU count, memory and free disk space. Never submit passwords or private keys. Ask for help if you have never prepared a Linux server. The coordinator will confirm your seat before genesis.
2. Use a dedicated VPS with Ubuntu 24.04, sudo access, provider console access, and a public IPv4 address or approved UDP forwarding. **Recruitment requirement: 8 vCPUs or more, 12 GB RAM or more (at least 11 GiB OS-visible memory), and an SSD/NVMe with at least 60 GiB free.** Allow capacity for database growth, logs and snapshots (100 GB or larger total storage recommended), with at least 10 Mbps symmetric bandwidth. If elections stall, the database grows quickly; see [If elections or block production stall](#if-elections-or-block-production-stall). The current automated CPU preflight floor is still **4 vCPUs**, but passing it alone does **not** meet this campaign's 8 vCPU recruitment minimum. Hardware SHA-256 acceleration is required. If you use arm64, confirm the supported build or release artifact with the coordinator before proceeding. [CPU requirements](https://github.com/tosnetwork/tos/blob/main/doc/Validator.md#cpu-instruction-set)
3. During December 1–4, get your node name, operator label and the pinned `tos` and `tos-ops` commits from the coordinator. Install the pinned operations bundle, synchronize the system clock, and prepare the validator and `tosctl` using the operator guide. You build the node and `tosctl` from source on your VPS; allow an hour or more for the build, and keep the build directory under `/var/lib/tos-build` until the coordinator has compared your release checksums. Allow inbound UDP 30001 and 31001 in both the provider and host firewalls. Keep console TCP 30002 closed to public traffic, and keep RPC 8081 and metrics 9100 on loopback. **The TOS team never logs in to, or runs commands on, your VPS.** You build, configure and run your node yourself, by hand or with the tos-ops scripts, and send the coordinator only the outputs and public records each step asks for. Do not give the team SSH or any other access, and do not run a command someone sends you unless it is in the operator guide or you understand what it does. Keep private keys and passwords private. Then check the host yourself and send the report to the coordinator:

   ```bash
   sudo python3 /opt/tos-testnet/scripts/preflight.py --local --name <YOUR_NODE_NAME> \
     --role validator --public-ip <YOUR_VPS_PUBLIC_IPV4> --out /tmp/preflight-<YOUR_NODE_NAME>.json
   ```

   Fix every FAIL and rerun with a new `--out` file. The UDP line stays a warning until a probe from outside proves your ports are reachable; the coordinator can send probes from its own machine to your public address, which needs no access to your VPS. [Host preparation, preflight and the UDP probe test](OPERATOR.md#2-host-requirements-clock-and-preflight)

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
  --validator-id="$VALIDATOR_ID" --operator "$OPERATOR_LABEL" \
  --address "$PUBLIC_IPV4:30001" --out /tmp/record.json
```

Send **`/tmp/record.json`** to the coordinator and confirm receipt and validation before genesis. If you need to view the public record first, run `sudo -u tos cat /tmp/record.json`. If a command fails, send the error and stop at that step until the coordinator helps you resolve it. It contains your public identity and network address. Run this consensus identity on only one host. [Wallet, staking pool and validator record instructions](OPERATOR.md#4-staking-account-and-public-record)

## Activate and join the first election

1. **Verify the genesis packet.** The coordinator supplies the global config, public genesis files, expected zero-state identity and a SHA-256 checksum for the config over a separate authenticated channel. Verify the checksum and activate the validator during the agreed window. [Activation commands](OPERATOR.md#5-activate-and-verify-custody-and-synchronization)
2. **Confirm synchronization.** Check that the node service is active, the custody log names your pool, and your local chain head advances after launch. Ask the coordinator to compare your node against a reference node for network identity and agreement on a recent block.
3. **Onboard for elections.** The coordinator funds your operator wallet, deploys and funds your pool from the pool owner, and then sends you the pool and owner addresses. You then run the onboarding on your own VPS. It checks the pool on chain, configures `tosctl` for it, confirms that your node's custody names the pool, and starts the election service. It is safe to rerun.

   ```bash
   sudo python3 /opt/tos-testnet/scripts/testnet-operator.py onboard --name <YOUR_NODE_NAME> \
     --pool=<POOL_ADDRESS> --owner=<POOL_OWNER_ADDRESS> --out /tmp/onboard-<YOUR_NODE_NAME>.json
   ```

   Send `/tmp/onboard-<YOUR_NODE_NAME>.json` to the coordinator, who checks the result on chain. The election service submits the pool's stake during the window. [Election onboarding and wallet balance check](OPERATOR.md#6-onboard-for-elections)
4. **Confirm your term.** Ask the coordinator to verify that the Elector accepted your pool's stake for the first election and that your pool appears in the active validator set once the new term starts.

If the previous election schedule is retained, the first election opens **five hours after genesis**, accepts stakes for **45 minutes**, and hands over to the elected set **six hours after genesis** if the election succeeds. Plan your availability using the final times confirmed by the coordinator.

### How the network depends on you

The launch set is the team's two validators, so the chain starts without waiting for anyone. From the first election on, the team's validators together hold a little over half of the voting weight and external validators the rest. A block is final only with at least two thirds of the weight. **External validators can never finalize blocks without the team. Once enough external validators are elected, the team cannot finalize alone either, and the network moves forward only while enough of them are online.** A validator that goes offline is left out of the next election, two hours later.

### If elections or block production stall

Two things can stop the network. If too much weight is offline at once, blocks stop. If an election does not conclude, blocks continue but no key block is made, old state is not cleaned up, and the database grows much faster than usual. In either case:

- Keep the node and election service running. Do not delete the database, reinstall or rotate keys.
- Watch free disk space every few hours and tell the coordinator before it falls below 20 GiB.
- The coordinator announces in the official channel, within 12 hours of the missed handover, whether the network continues, restarts from a new genesis or ends. A restart means a new seat confirmation and a new public record; the coordinator will tell you which steps to repeat.

## Monitor your validator during the test

- Check node and election service status, chain progress, restarts, free disk space and operator wallet fee balance.
- At each election, confirm stake acceptance and active-set membership. Check stake recovery when it is due. Report an expired term even if blocks are still advancing.
- If chain progress stalls, an election fails, fees run low or disk usage grows unexpectedly, report the UTC time, node name, public pool address, last chain head and relevant sanitized log lines. If the outcome of a transaction is unclear, ask the coordinator to reconcile the original attempt before retrying.
- Tell the coordinator before scheduled maintenance or leaving so they can check your active duties and outstanding stakes.
- Upgrades are announced in the official channel with the new pinned commit, the deadline and whether the upgrade is mandatory. Upgrade one validator at a time as the coordinator schedules it, following the [upgrade steps](OPERATOR.md#8-upgrade-rollback-and-key-rotation).
- For an urgent problem (your node is down, a stake looks wrong, a key may be exposed), post in the official channel and contact your coordinator directly. If you suspect a key is exposed, stop the validator first.

[Daily checks, log commands and fee monitoring](OPERATOR.md#7-daily-checks-and-fee-top-ups)

If you contact the team after genesis, ask about running an observer node. The current automated onboarding tool requires the pool to be listed in the genesis records. The team will communicate a separate process for admitting new validators to a running network once that process has been verified.

## External participation milestone

**This is a collective technical acceptance gate, distinct from the individual 1,000 TOS reward decision.** A successful external-validator test requires **at least five independent external operators**. The TOS organizer and core-team-controlled validators do not count. Different accounts, machines, public IPs and pools do not necessarily represent different operators; one person controlling multiple nodes counts once. The coordinator must also confirm genuine operational independence through an appropriate operator-side check, since chain records alone cannot prove who controls a machine.

For **each counted operator**, the coordinator must retain evidence of all five steps:

1. **Independent onboarding:** one distinct external operator controls the validator host and consensus key, with a verified public staking pool and validator ID; the team never had access to that host. No private keys are collected.
2. **Node synchronization:** the validator joined the correct testnet and its recent block identity agrees with independently checked reference nodes.
3. **Accepted stake:** the Elector accepted that pool's stake in an identified election. Mere funding or submission is not sufficient.
4. **Election and actual duties:** the pool entered the active elected validator set and the validator actually performed duties during that elected term. Being a candidate or merely appearing in a proposed set is not sufficient.
5. **Recorded verification:** the coordinator cross-checks the election and active-set/key-block records with available term-participation evidence, timestamps the outcome, and marks it PASS, FAIL or PENDING. Missing evidence stays PENDING, not PASS.

The team may declare this external-participation milestone **successful only when at least five different external operators have verified PASS results**. The team publishes the count and verification basis without disclosing private keys or unrelated private operator information. There are at most 19 seats for external validators; the coordinator confirms each seat before genesis.

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

## When the test ends

After the coordinator announces the end of the test on December 19:

1. Send your last cycle report and any unresolved items.
2. Keep the node and election service running until the coordinator confirms that your validator has no current or pending duties and that your pool's held stakes have been recovered. Stopping a validator whose key is still in a set can halt the network.
3. Then retire the host as the coordinator instructs, with the retirement script described in [leaving and retirement](OPERATOR.md#9-incidents-leaving-and-retirement). It archives the evidence first and then removes the node and operator state; do not delete the database, keys or vault by hand.
4. Keep the evidence archive for 7 days in case the coordinator asks for it, then delete it. Testnet keys must never be reused on mainnet.
