# T3 drills: planned validator outage and network partition

Scripts for the public-testnet T3 plan (`public-testnet/T3-PLAN-20261109.md` in the team
notes; sections 4, 5 and 8). Five scenarios, one per quiet window:

| | Scenario | Target | Hard abort |
|---|---|---|---|
| S1 | clean stop, 1 down | node-4 | t0+20 min |
| S2 | unclean kill (SIGKILL through systemd), 1 down | node-3 | t0+20 min |
| S3 | 2 down: halt, then resume | node-4, then node-3 | t0+25 min |
| S4 | 2-2 partition {1,2} \| {3,4}, then heal | all four | t0+25 min (self-heal t0+12) |
| S5 | optional 1-3 partition, node-4 isolated | all four | t0+20 min (self-heal t0+12) |

## Who runs it

The **remote lane** runs `t3-run.sh` through its existing root-ssh helper, after the
coordinator has reviewed this tree and the remote lane has read the scenario's dry run.
Every host action goes through `on NODE CMD` and `put` from the sourced epoch helpers
(`$T3_DEPLOY/helpers.sh`); nothing else opens a connection.

## Usage

```bash
testnet/drills/t3/t3-run.sh S1              # dry run (the default): prints, executes nothing
testnet/drills/t3/t3-run.sh all --dry-run   # every scenario
testnet/drills/t3/t3-run.sh S1 --execute    # the real run, one scenario
```

**The dry run is the default.** It prints every host and local command in order with its
planned offset from t0, followed by the abort ladder. It does not source the helpers, resolve
an address, take the lock or create a directory. Partition rules show `$(addr node-N)`
references. The runner resolves them in memory only when it executes the command; they are
never written to a file.

`--execute`:

1. It refuses when this directory has uncommitted changes, and records the tos-ops commit.
2. It holds `$T3_DEPLOY/u76af/upgrade.lock` (flock, fd 9) for the whole run.
3. It creates `${T3_EVIDENCE:-/datax/t3}/t3-<YYYYMMDDTHHMMZ>-<S>/`.
4. It runs `t3-preflight.sh`. Any STOP line there means nothing was changed.
5. It runs `t3_run.py`: the sampler, then the mute, the timed actions, the resume deadlines
   and the hard abort, then the log pulls and `verdict.json` and `SHA256SUMS`.

Exit codes: 0 PASS with the next handover pending, 1 FAIL, 2 INCONCLUSIVE, 3/4 a pre-flight
STOP.

## Files

| File | Runs on | Purpose |
|---|---|---|
| `t3-run.sh` | coordinator | entry point: dry run or execute |
| `t3-preflight.sh` | coordinator | section 4. Every check fails closed. Host facts come from `t3-host-check.sh` (read-only, sent over `bash -s`) |
| `t3_run.py` | coordinator | the scenario timelines, the abort ladder, the evidence |
| `t3_lib.py` | coordinator | gates, pre-check parser, partition and heal commands, log classification, the section-5.1 verdict |
| `t3-sample.py` | coordinator | 2 s sampler of `getMasterchainInfo` and `getConsensusBlock` on 18081/38081/28081/48084. Each node gets 1 request a second, and a run is capped at 3600 s |
| `t3-node.py` | host, as root (`/root/t3-node.py`, sha256 checked after `put`) | `--stop`, `--kill`, `--start --binding DEV:INO`, `--after-kill T0 --binding DEV:INO`. Never touches `tos-testnet-dht`, never deletes or recreates a ledger or database |
| `pins.sha256` | | sha256 of the outside scripts it calls (`helpers.sh`, `current-term.py`, `block-rate.py`, the shared checker). The run refuses if one changed |

## Gates (beyond the plan's section 4)

- The current term's own handover verdict must be present and PASS, with four sources and
  its boundary, and at least 9 min old. The run refuses while that verdict is pending.
- The hard abort must end before the election opens (even hour :18:07). It must also end
  before the next odd-hour :12 handover collection.
- The routine handover checks are armed by the remote lane, not by T3. The verdict records
  the next handover's `CLASSIFY.json` path as pending.

## Abort ladder

The runner starts the ladder on any missed deadline, refused step, unexpected error, a 60 s
stall with 3 of 4 up, or the hard abort.

1. Heal the partition on all 4 hosts. The command is idempotent, and the self-heal timer is
   the backstop.
2. Start every validator that is not active with `t3-node.py --start`. An untrusted ledger
   stays fenced, with elections stopped, and the ledger is not touched.
3. If no block arrives within 5 min, capture `getConsensusBlock` and the log pulls, then
   print the one-at-a-time restarts (node-4 first, 3 min apart, never the DHT). **They are
   not run automatically.**
4. Stop and leave the network for the owner. The mute expires by itself.

## Evidence

Everything goes under `/datax/t3/<run>/`, **never a `build/` directory**. The directory holds:

- from the pre-flight: `preflight.txt`, `term.json`, `R0.json`, `heads.json`,
  `pre-node-N.txt` and `pre-notes.txt`;
- from the run: `samples.jsonl`, `rate-*.json`, `actions.jsonl` (the UTC of every per-host
  stop, kill, start, partition apply and heal), `node-N-cycle.txt`, `log-node-N.txt`,
  `nft-node-N.txt`, `partition-verify.json`, `commands.log` and `run.log`;
- the results: `verdict.json` and `SHA256SUMS`.

Logs and command records hold `$(addr X)` references, never addresses.

## Tests

`testnet/tests/test_t3_drills.py`. Its red controls are in `testnet/tests/t3_drill_mutants.py`;
commit before running them.
