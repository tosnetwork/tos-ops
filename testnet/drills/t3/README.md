# T3 drills: planned validator outage and network partition

Scripts for the public-testnet T3 plan v2 (`public-testnet/T3-PLAN-20261109.md` in the team
notes; sections 4, 5 and 8). One scenario per quiet window:

| | Scenario | Target | Hard abort |
|---|---|---|---|
| S1 | clean stop, 1 down | node-4 | t0+20 min |
| S2 | unclean restart (SIGKILL through systemd), 1 down | node-3 | t0+20 min |
| S3 | 2 down: halt, then resume | node-4, then node-3 | t0+25 min (host restore timers t0+15) |
| S4 | 2-2 partition {1,2} \| {3,4}, then heal | all four | t0+25 min (self-heal t0+12) |

The old S5 (1-3 partition) is dropped.

## Who runs it

The **remote lane** runs `t3-run.sh` through its existing root-ssh helper. It does so only
after the coordinator has reviewed this tree and the remote lane has read the scenario's dry
run. Every host action goes through `on NODE CMD`, `put` and `get` from the sourced epoch
helpers (`$T3_DEPLOY/helpers.sh`); nothing else opens a connection. T3 never arms handover
checks: its gates read the remote lane's handover files.

## Usage

```bash
testnet/drills/t3/t3-run.sh S1              # dry run (the default): prints, executes nothing
testnet/drills/t3/t3-run.sh all --dry-run   # every scenario
testnet/drills/t3/t3-run.sh S1 --execute    # the real run, one scenario
```

**The dry run is the default.** It prints the following, in order, with each step's planned
offset from t0:

- every host and local command, gates included;
- the availability abort ladder;
- the safety abort.

It does not source the helpers, resolve an address, take the lock or create a directory.
Addresses appear only as `$(addr node-N)` and `$(addr6 node-N)` references. The runner
resolves them in memory at execution time and never writes them to a file. Pre-check
records keep address families and ports only.

`--execute`:

1. It refuses while any `QUARANTINE-node-N` under the evidence root lacks a
   `CLEARED-node-N`.
2. It refuses when this directory has uncommitted changes, and records the commit.
3. It holds `$T3_DEPLOY/u76af/upgrade.lock` (flock, fd 9) for the whole run.
4. It creates `${T3_EVIDENCE:-/datax/t3}/t3-<YYYYMMDDTHHMMZ>-<S>/`.
5. It runs `t3-preflight.sh`, which writes `gates-pre.json`.
6. It starts the sampler.
7. It re-runs the fast gates immediately before the fault (`gates-t0.json`).
8. It mutes the alerts and runs the scenario.

Exit codes:

| Exit | Meaning |
|---|---|
| 0 | PASS (next handover pending) |
| 1 | FAIL |
| 2 | INCONCLUSIVE |
| 3/4 | a gate STOP before any fault |
| 5 | SAFETY_FAIL |

The coordinator finalizes the "next handover" criterion by hand, from the `CLASSIFY.json`
path recorded in `verdict.json`.

## Gates (each recorded with its result)

- Pinned outside scripts, the lock, no rollout unit running, rollout accepted, and the two
  acceptance handovers.
- The current term's handover PASS: verify PASS, 0 failures, final agree, no alert, all four
  sources. The run refuses while that verdict is pending.
- The full hard-abort budget fits before the recovery deadline (even-hour :05:07) and before
  the next odd-hour :12 handover collection. Term left is re-checked right before the fault.
- 4 equal weights in ConfigParam 34, read from two sources.
- ConfigParam 36 absent and `active_election_id` 0.
- Fresh, advancing heads within 5 blocks on all four ports.
- Each unit's own exit code, `Restart=on-failure` with 10 s, the revision, the ledger
  binding, tools and endpoints, and no leftover `t3part` table or `t3-*` unit.
- Clock offset per host, measured with `date +%s.%N` over ssh. It must be within 0.5 s once
  half the round trip is subtracted. The verdict's windows have a 2 s sample period and a
  30 s settling interval, so that skew cannot move a block across a window edge by more than
  one sample. The halt's settling interval is 30 s plus the worst measured skew.

## Safety: heal before fault, restore without the coordinator

- **S4.** Each host arms its own 12-minute self-heal (`t3-heal-RUN`), and it is verified
  before any rule loads: the unit is active, its deadline is about 720 s, it runs
  `/usr/sbin/nft delete table inet t3part`, and nft is executable.
  - Any failure, in arming or in loading, heals all four hosts unconditionally.
  - Rules carry a counter per peer and direction. IPv4 is always cut. IPv6 is cut as well if
    any validator-engine socket can use it.
  - Every cross-cut pair must show drops in both directions, or the verdict is INCOMPLETE
    (INCONCLUSIVE).
- **S3.** Each stopped host first arms and verifies a host-local timer (`t3-restore-RUN`,
  t0+15 min) that starts `tos-testnet-validator`, so both hosts come back even without
  toserver.
  - Engine start and signing wait are separate steps. Both hosts' starts are always
    attempted: one host's refusal, timeout or untrusted ledger never skips the other.
  - Elections start only from `--await-signing`, after `trusted, ` plus an own masterchain
    signature.
  - An untrusted node stays fenced through the fence block's catchain plus two, so it may
    not sign within 180 s. That blocks nothing else.
- **Safety abort.** It runs on a double-sign allegation of a double-sign kind or on a "conflicts
  with a decision already recorded" refusal. It:
  1. heals connectivity;
  2. quarantines the implicated identity (`t3-node.py --quarantine`: its restore timer is
     cancelled, its validator and elections are stopped, and `/root/t3-quarantine-RUN` is
     written);
  3. copies that host's `node.log*` and its ledger listing into evidence;
  4. records SAFETY_FAIL;
  5. stops every automatic restore.

  Before any restart, the coordinator writes `CLEARED-node-N` in the run directory and
  removes the host marker by hand. If the implicated host cannot be resolved, nothing is
  quarantined and nothing is restarted.
- **Availability ladder.** It runs for missed deadlines, refused steps, a 60 s stall with 3
  of 4 up, or the hard abort:
  1. heal;
  2. start every inactive engine, then await each one's signing;
  3. if no new block arrives within 5 min, capture evidence and print the one-at-a-time
     restarts (not run);
  4. stop and leave the network.

## Measures

- Rate and progress come only from the sampler's timestamped samples, over the declared
  intervals:
  - R0 over the sampler lead;
  - the outage rate from t0+30 s to the restore;
  - the post rate over 5 min after rejoin.

  Seqnos must advance inside the interval, with head age at most 30 s. No block history is
  used.
- A rejoin requires all of the following:
  - heads within 5 blocks;
  - progress past the head at the restore;
  - one block hash at the common height across the compared nodes.

  Four frozen heads do not pass.
- During the halt, progress inside the settling interval is recorded only. Any progress after
  it is FAIL.
- S2 is an unclean restart test. The engine does not log a torn-tail truncation, so
  `verdict.json` never claims one was exercised. Per-session load lines are judged: fenced
  sessions are FAIL, and a missing masterchain admission is INCONCLUSIVE.
- `verdict.json` states its scope. T3 observes availability plus the safety refusals the
  engines log. The next handover's verify does not authenticate the fault interval.

## Files

| File | Runs on | Purpose |
|---|---|---|
| `t3-run.sh` | coordinator | entry point: dry run or execute |
| `t3-preflight.sh` | coordinator | section 4 shell gates, then `t3_run.py --gates` |
| `t3-host-check.sh` | host (read-only, `bash -s`) | the host facts, one labeled section each |
| `t3_run.py` | coordinator | gates, timelines, both abort paths, evidence, verdict |
| `t3_lib.py` | coordinator | pure logic: gates, parsers, redaction, rules, counters, verdict |
| `t3-sample.py` | coordinator | 2 s sampler, 1 request a second per node, capped at 3600 s |
| `t3-node.py` | host, as root (`/root/t3-node.py`, sha256 checked) | stop (optional restore timer), kill, start-engine, await-signing, after-kill, quarantine |
| `pins.sha256` | | sha256 of the outside scripts it calls |

## Evidence

Everything goes under `/datax/t3/<run>/`, **never a `build/` directory**:

- gates and pre-flight: `preflight.txt`, `gates-pre.json`, `gates-t0.json`, `term.json`,
  `pre-node-N.txt` (redacted), `identities.json`, `clock-*.json`;
- the run: `samples.jsonl`, `actions.jsonl` (the UTC of every stop, kill, start, self-heal
  arm, partition apply and heal), `node-N-cycle.txt`, `log-node-N*.txt`, `self-heal.json`,
  `partition-verify.json`, `partition-counters.json`, `nft-node-N.txt`, `commands.log` and
  `run.log`;
- after a safety abort: `QUARANTINE-node-N` and `quarantine-node-N/`;
- the results: `verdict.json` and `SHA256SUMS`.

## Tests

`testnet/tests/test_t3_drills.py`. Its red controls are in `testnet/tests/t3_drill_mutants.py`;
commit before running them.
