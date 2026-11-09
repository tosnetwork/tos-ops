"""T3 scenario runner (plan v2), called by t3-run.sh and t3-preflight.sh.

  t3_run.py --dry-run S1|S2|S3|S4|all
  t3_run.py --gates S RUN       (from t3-preflight.sh: the recorded pre-flight gates)
  t3_run.py --execute S RUN     (only from t3-run.sh --execute)

The dry run prints every host and local command a scenario would issue, in order, with its
planned time offset, then the availability abort ladder and the safety abort, and executes
none of them: it does not source the host helpers, resolve an address, take a lock or create
a directory.

Execution: sampler, fast gates again right before the fault, mute, the timed actions, the
resume deadlines and the hard abort, the log pulls and the verdict with the next handover
pending. Two abort paths: availability failures run the ladder (steps 1-2 automatic; step 3
captures evidence and prints its restarts; step 4 stops); a safety failure (a double-sign
allegation or a ledger conflict refusal) heals connectivity, quarantines the implicated
identity, preserves its logs and ledger listing and stops every automatic restore. Every
host action is `on NODE CMD` (or `put`/`get`) through the sourced epoch helpers. Addresses
are `$(addr X)`/`$(addr6 X)` references resolved in memory at execution time only.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import t3_lib as lib  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ALERT_STATE = "$HOME/.local/state/tos-alert"
MC_SHARD = "-9223372036854775808"


class Abort(Exception):
    """An availability failure: a missed deadline, a refused step or the hard abort.

    fail=True: the scenario's own criterion failed (stall, no resume, hard abort).
    fail=False: a step was refused for an outside reason, which is INCONCLUSIVE."""

    def __init__(self, msg: str, fail: bool = True):
        super().__init__(msg)
        self.fail = fail


class SafetyAbort(Exception):
    """A double-sign allegation of a double-sign kind or a ledger conflict refusal."""

    def __init__(self, events: list[dict]):
        super().__init__(f"{len(events)} safety event(s)")
        self.events = events


class GateStop(Exception):
    pass


def rpc_raw(port: int, rpc_method: str, timeout: float = 10, /, **params) -> dict:
    # Positional-only: runGetMethod takes its own `method` parameter.
    body = json.dumps(dict(jsonrpc="2.0", id=1, method=rpc_method, params=params)).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/jsonRPC", body, {"Content-Type": "application/json"}
    )
    return json.load(OPENER.open(req, timeout=timeout))


def rpc(port: int, rpc_method: str, timeout: float = 10, /, **params):
    d = rpc_raw(port, rpc_method, timeout, **params)
    if "error" in d:
        raise RuntimeError(d["error"])
    return d["result"]


def head(port: int) -> int:
    return int(rpc(port, "getMasterchainInfo")["last"]["seqno"])


def head_fact(port: int) -> dict:
    seq = head(port)
    c = rpc(port, "getConsensusBlock")
    return dict(seqno=seq, utime=int(c["last_block_utime"]), t=time.time())


def block_hash(port: int, seqno: int) -> str:
    r = rpc(port, "getBlockHeader", workchain=-1, shard=MC_SHARD, seqno=seqno)
    return r["id"]["root_hash"]


def shown(arg: str) -> str:
    """Quote for display only when needed; `$NAME` references stay visible as written."""
    return arg if re.fullmatch(r"[\w$./:+=,<>-]+", arg) else f'"{arg}"'


def quote(cmd: str) -> str:
    """Display form of a host command: the plan's double quotes when it holds single quotes;
    a multi-line command is shown verbatim between >>> and <<< lines."""
    if "\n" in cmd:
        return ">>>\n" + cmd + "\n<<<"
    return f'"{cmd}"' if "'" in cmd and '"' not in cmd else shlex.quote(cmd)


def redact(text: str) -> str:
    """Host addresses never reach evidence files (an ssh error names the host)."""
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<addr>", text)
    return re.sub(r"\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b", "<addr6>", text)


class Runner:
    def __init__(
        self,
        scenario: str,
        run: str,
        execute: bool,
        out_dir: Path | None = None,
        printer=print,
        clock=time.time,
        sleep=time.sleep,
    ):
        self.s = scenario
        self.sc = lib.SCENARIOS[scenario]
        self.run = run
        self.execute = execute
        self.out = out_dir
        self.print = printer
        self._clock = clock
        self._sleep = sleep
        self.vnow = 0.0  # dry-run virtual clock, seconds from t0
        self.t0: float | None = None
        self.hard_abort: float | None = None
        self.ev: dict = dict(deadlines={}, restarted=[], ladder=[], safety=[], quarantined=[])
        self.node_results: dict = {}
        self.bindings: dict = {}
        self.ids: dict = {}
        self.v6: dict = {n: [] for n in lib.VALIDATORS}
        self.use_v6 = False
        self.settle = lib.SETTLE_BASE
        self.logs: dict = {}
        self.deploy = os.environ.get(
            "T3_DEPLOY", str(Path.home() / "tos-testnet-deploy/epoch-6/run")
        )
        self.helpers = str(Path(self.deploy) / "helpers.sh")
        self.handovers = Path(self.deploy) / "remote-reval-20261105"
        self.alert = os.environ.get(
            "T3_ALERT_RELAY", "$HOME/tos-ops/testnet/scripts/alert-relay.py"
        )

    # ------------------------------------------------------------ clock and output

    def now(self) -> float:
        return self._clock() if self.execute else self.vnow

    def rel(self) -> str:
        if self.t0 is None:
            return "pre   "
        d = self.now() - self.t0
        return f"t0{'+' if d >= 0 else '-'}{abs(d):4.0f}s"

    def say(self, msg: str) -> None:
        stamp = lib.utc(self._clock()) + " " if self.execute else ""
        self.print(f"{stamp}[{self.rel()}] {msg}")
        if self.execute and self.out:
            with open(self.out / "run.log", "a") as f:
                f.write(f"{lib.utc(self._clock())} [{self.rel()}] {msg}\n")

    def sleep_until(self, t: float, why: str) -> None:
        if not self.execute:
            self.vnow = max(self.vnow, t)
            self.say(f"wait until {why}")
            return
        while self.now() < t:
            self.check_abort()
            self._sleep(min(2.0, max(0.0, t - self.now())))

    def check_abort(self) -> None:
        if self.hard_abort is not None and self.now() >= self.hard_abort:
            raise Abort("hard abort reached")

    def action(self, node: str, kind: str, **kw) -> None:
        row = dict(
            utc=lib.utc(self._clock()), t=round(self._clock(), 3), node=node, action=kind, **kw
        )
        if self.execute and self.out:
            with open(self.out / "actions.jsonl", "a") as f:
                f.write(json.dumps(row) + "\n")

    def write(self, name: str, data) -> None:
        if self.execute and self.out:
            (self.out / name).write_text(
                data if isinstance(data, str) else json.dumps(data, indent=1, default=str) + "\n"
            )

    # ------------------------------------------------------------ commands

    def on(
        self,
        node: str,
        cmd: str,
        why: str,
        timeout: int = 600,
        stdin: str | None = None,
        quiet: bool = False,
    ):
        shown_cmd = f"on {node} {quote(cmd)}" + (f" < {stdin}" if stdin else "")
        if not quiet:
            self.say(f"HOST  {shown_cmd}    # {why}")
        if not self.execute:
            return 0, ""
        real = lib.resolve(cmd, self.addr, lambda n: self.v6.get(n, []))
        fin = open(HERE / stdin) if stdin else subprocess.DEVNULL
        try:
            r = subprocess.run(
                ["bash", "-c", '. "$1"; shift; on "$@"', "t3-on", self.helpers, node, real],
                stdin=fin,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return 124, "timeout"
        finally:
            if stdin:
                fin.close()
        with open(self.out / "commands.log", "a") as f:
            f.write(
                json.dumps(dict(utc=lib.utc(self._clock()), cmd=shown_cmd, rc=r.returncode)) + "\n"
            )
        return r.returncode, r.stdout + r.stderr

    def helper(self, fn: str, *args: str, timeout: int = 300) -> int:
        """put/get through the sourced helpers."""
        self.say(f"HOST  {fn} {' '.join(args)}")
        if not self.execute:
            return 0
        r = subprocess.run(
            ["bash", "-c", f'. "$1"; shift; {fn} "$@"', "t3-" + fn, self.helpers, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return r.returncode

    def addr(self, node: str) -> str:
        r = subprocess.run(
            ["bash", "-c", '. "$1"; addr "$2"', "t3-addr", self.helpers, node],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode != 0:
            raise Abort(f"addr {node} failed", fail=False)
        return r.stdout

    def local(self, argv: list[str], why: str, timeout: int = 120):
        self.say(f"LOCAL {' '.join(shown(a) for a in argv)}    # {why}")
        if not self.execute:
            return 0, ""
        argv = [os.path.expandvars(a.replace("$DEPLOY", self.deploy)) for a in argv]
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, ""
        return r.returncode, r.stdout

    def parallel(self, cmds: dict[str, str], why: str, timeout: int = 60) -> dict:
        """{node: (rc, out, sent, done)}; the dry run prints them in order."""
        if not self.execute:
            return {n: (*self.on(n, c, why + " (parallel)"), 0.0, 0.0) for n, c in cmds.items()}
        for n, c in cmds.items():
            self.say(f"HOST  on {n} {quote(c)}    # {why} (parallel)")
        with concurrent.futures.ThreadPoolExecutor(len(cmds)) as pool:
            futs = {n: pool.submit(self._quiet_on, n, c, timeout) for n, c in cmds.items()}
            return {n: f.result() for n, f in futs.items()}

    def _quiet_on(self, node, cmd, timeout):
        sent = self._clock()
        rc, out = self.on(node, cmd, "parallel", timeout, quiet=True)
        return rc, out, sent, self._clock()

    def node(self, node: str, mode: str, *extra: str, why: str) -> dict:
        sent = self._clock()
        rc, out = self.on(node, lib.node_cmd(node, mode, *extra, "--run", self.run), why)
        if not self.execute:
            return dict(result="DRY", t0=self.now())
        try:
            res = json.loads([x for x in out.splitlines() if x.startswith("{")][-1])
        except (ValueError, IndexError):
            res = dict(result="NO-JSON", tail=redact(out[-500:]))
        res["rc"] = rc
        with open(self.out / f"{node}-cycle.txt", "a") as f:
            f.write(json.dumps(dict(mode=mode, sent_utc=lib.utc(sent), **res)) + "\n")
        self.action(
            node,
            mode.lstrip("-"),
            sent=round(sent, 3),
            done=round(self._clock(), 3),
            rc=rc,
            result=res.get("result"),
            host_t0=res.get("t0"),
        )
        return res

    # ------------------------------------------------------------ gates

    def gate(self, results: list, name: str, problems: list[str]) -> None:
        results.append(
            dict(name=name, ok=not problems, problems=problems, utc=lib.utc(self._clock()))
        )
        self.say(f"GATE  {name}: {'ok' if not problems else 'FAIL ' + '; '.join(problems)}")

    def gates(self, stage: str) -> None:
        """Every gate is an assertion with a recorded result (gates-<stage>.json)."""
        res: list = []
        self.say(
            f"GATES ({stage}): window, handover, set, election, heads, units, clocks"
            + (", host facts and identities" if stage == "pre" else "")
            + (", IPv6 inventory" if self.sc["partition"] else "")
        )
        if not self.execute:
            for n in lib.VALIDATORS:
                if stage == "pre":
                    self.on(
                        n, f"bash -s -- {n}", "host facts (read-only)", stdin="t3-host-check.sh"
                    )
                else:
                    self.on(n, self.units_cmd(n), "each unit active, rc per unit")
                self.on(n, "date +%s.%N", "clock offset against local time, RTT accounted")
                if self.sc["partition"] and stage == "t0":
                    self.on(n, "ip -6 -o addr show scope global", "IPv6 inventory (memory only)")
            self.say(
                "LOCAL JSON-RPC 18081 getConfigParam 36 (must be absent), runGetMethod "
                "active_election_id (must be 0); 4 ports getMasterchainInfo and "
                "getConsensusBlock twice, 5 s apart (advancing, age <= 30 s, within 5)"
            )
            return
        term = json.loads((self.out / "term.json").read_text())
        lead = lib.SAMPLER_LEAD if stage == "pre" else 0
        self.gate(res, "window and term left", lib.window_problems(term, self.s, self.now(), lead))
        self.gate(
            res,
            "current handover PASS (4 sources)",
            lib.handover_problems(self.handovers, int(term["since"])),
        )
        self.gate(res, "4 equal weights", lib.set_problems(term))
        try:
            cp36 = rpc_raw(18081, "getConfigParam", 15, param=36)
            el = rpc_raw(
                18081,
                "runGetMethod",
                15,
                address="-1:" + "3" * 64,
                method="active_election_id",
                stack=[],
            )
            self.gate(
                res, "ConfigParam 36 absent, active_election_id 0", lib.election_problems(cp36, el)
            )
        except Exception as e:
            self.gate(res, "ConfigParam 36 absent, active_election_id 0", [f"not read: {e!r}"])
        first = self.facts()
        self._sleep(5)
        self.gate(res, "fresh advancing heads", lib.heads_problems(first, self.facts()))
        offsets = {}
        texts = {}
        for n in lib.VALIDATORS:
            if stage == "pre":
                rc, out = self.on(n, f"bash -s -- {n}", "host facts", stdin="t3-host-check.sh")
                texts[n] = out
                self.write(f"pre-{n}.txt", lib.redact_pre(out))
                self.gate(
                    res,
                    f"{n} host facts",
                    ([f"rc {rc}"] if rc else []) + lib.pre_problems(self.s, n, out),
                )
            else:
                rc, out = self.on(n, self.units_cmd(n), "units")
                want = [f"{u} rc=0" for u in lib.units_of(n)]
                self.gate(
                    res,
                    f"{n} each unit active",
                    [] if rc == 0 and out.split("\n")[: len(want)] == want else [out[-200:]],
                )
            b = self._clock()
            rc, out = self.on(n, "date +%s.%N", "clock", quiet=True)
            a = self._clock()
            try:
                offsets[n] = lib.clock_offset(b, float(out.strip().split()[-1]), a)
            except (ValueError, IndexError):
                offsets[n] = (99.0, 0.0)
            if self.sc["partition"] and stage == "t0":
                rc, out = self.on(
                    n, "ip -6 -o addr show scope global", "IPv6 inventory", quiet=True
                )
                self.v6[n] = lib.v6_globals(out.splitlines()) if rc == 0 else []
        self.gate(res, f"clock offsets within {lib.MAX_CLOCK_SKEW}s", lib.clock_problems(offsets))
        self.settle = lib.settle_seconds(offsets)
        self.write(
            f"clock-{stage}.json", {n: dict(offset=o, half_rtt=h) for n, (o, h) in offsets.items()}
        )
        if stage == "pre":
            self.ids = lib.identities(texts, term)
            self.write("identities.json", self.ids)
        self.write(f"gates-{stage}.json", res)
        bad = [g["name"] for g in res if not g["ok"]]
        if bad:
            raise GateStop(f"gates failed ({stage}): {bad}")

    @staticmethod
    def units_cmd(node: str) -> str:
        return "; ".join(
            f'systemctl is-active --quiet {u}; echo "{u} rc=$?"' for u in lib.units_of(node)
        )

    def facts(self) -> dict:
        out = {}
        for p in lib.ALL_PORTS:
            try:
                out[p] = head_fact(p)
            except Exception:
                out[p] = None
        return out

    # ------------------------------------------------------------ observations

    def heads(self, ports) -> dict:
        out = {}
        for p in ports:
            try:
                out[p] = head(p)
            except Exception:
                out[p] = None
        return out

    def wait(self, pred, deadline: float, why: str, step: float = 5.0) -> bool:
        """Poll a read-only condition until deadline; never past the hard abort."""
        self.say(f"CHECK {why} (deadline {self._rel(deadline)})")
        if not self.execute:
            return True
        while True:
            try:
                if pred():
                    self.say(f"  met: {why}")
                    return True
            except Exception:
                pass
            if self.now() >= deadline:
                self.say(f"  NOT met: {why}")
                return False
            self.check_abort()
            self._sleep(step)

    def _rel(self, t: float) -> str:
        return f"t0+{t - self.t0:.0f}s" if self.t0 is not None else f"{t:.0f}"

    def rejoin(self, ports, base: int | None):
        """Within 5 blocks, progress past `base`, and one block hash at the common height."""

        def pred():
            h = {p: head(p) for p in ports}
            if max(h.values()) - min(h.values()) > 5:
                return False
            if base is None or max(h.values()) <= base:
                return False
            common = min(h.values())
            return len({block_hash(p, common) for p in ports}) == 1

        return pred

    def new_block_after(self, ports, base: int | None):
        def pred():
            return base is not None and max(head(p) for p in ports) > base

        return pred

    def base_head(self, ports) -> int | None:
        if not self.execute:
            return 0
        h = [x for x in self.heads(ports).values() if x is not None]
        return max(h) if h else None

    # ------------------------------------------------------------ shared steps

    def put_node_script(self) -> None:
        src = HERE / "t3-node.py"
        want = hashlib.sha256(src.read_bytes()).hexdigest()
        for n in lib.VALIDATORS:
            rc_put = (
                self.helper("put", n, str(src.name), "/root/t3-node.py")
                if not self.execute
                else self.helper("put", n, str(src), "/root/t3-node.py")
            )
            rc, out = self.on(n, "sha256sum /root/t3-node.py", f"must equal {want[:16]}...")
            if self.execute and (rc_put != 0 or rc != 0 or out.split()[:1] != [want]):
                raise GateStop(f"t3-node.py copy on {n} differs or failed")

    def load_bindings(self) -> None:
        for n in lib.VALIDATORS:
            if self.execute:
                self.bindings[n] = lib.ledger_binding((self.out / f"pre-{n}.txt").read_text())
            else:
                self.bindings[n] = f"<DEV:INO from pre-{n}.txt>"
        if self.execute:
            ids = self.out / "identities.json"
            self.ids = json.loads(ids.read_text()) if ids.exists() else {}
            for n in lib.VALIDATORS:
                sock = lib.sections((self.out / f"pre-{n}.txt").read_text()).get("sockets", [])
                rows = [json.loads(x) for x in sock if x.startswith("{")]
                self.use_v6 = self.use_v6 or lib.needs_v6(rows)

    def mute(self) -> None:
        argv = [
            "python3",
            self.alert,
            "silence",
            "--until",
            f"+{self.sc['mute_min']}",
            "--reason",
            f"T3 {self.s} {self.run}",
            "--state-dir",
            ALERT_STATE,
        ]
        for h in self.sc["mute"]:
            argv += ["--host", h]
        rc, _ = self.local(argv, "mute alerts until the hard abort")
        if rc != 0:
            raise GateStop("the alert silence was not written")

    def stop(self, n: str, restore_after: int | None = None) -> None:
        extra = ("--restore-after", str(restore_after)) if restore_after else ()
        r = self.node(
            n,
            "--stop",
            *extra,
            why=f"clean stop of {n}"
            + (f"; its own restore timer fires in {restore_after}s" if restore_after else ""),
        )
        if self.execute and r.get("result") != "STOPPED":
            raise Abort(f"{n} stop refused: {r.get('result')}", fail=False)

    def start_engine(self, n: str) -> dict:
        r = self.node(
            n, "--start-engine", "--binding", self.bindings[n], why=f"start {n}'s engine only"
        )
        self.node_results[n] = r
        return r

    def await_signing(self, n: str, started: dict) -> dict:
        t0 = str(int(started.get("t0") or self.now())) if self.execute else "<engine t0>"
        r = self.node(
            n,
            "--await-signing",
            t0,
            "--binding",
            self.bindings[n],
            why=f"{n} markers; elections only after trusted + own signature",
        )
        self.node_results[n] = r
        return r

    def start(self, n: str) -> float:
        """Engine first, then the signing wait; a refusal is recorded, never raised."""
        t = self.now()
        e = self.start_engine(n)
        if not self.execute or e.get("result") == "ENGINE-STARTED":
            self.await_signing(n, e)
        return t

    def arm_heal(self) -> bool:
        res = self.parallel(
            {n: lib.arm_heal_cmd(self.run) for n in lib.VALIDATORS},
            "arm the 12 min self-heal BEFORE any rule, and report it",
        )
        if not self.execute:
            self.say(
                "CHECK each host: timer active, deadline about 720 s, ExecStart "
                f"{lib.HEAL_ARGV!r}, nft executable; any failure: heal all 4, INCONCLUSIVE"
            )
            return True
        report = {}
        for n, (rc, out, sent, done) in res.items():
            p = lib.timer_problems(out, lib.HEAL_ARGV, lib.SELF_HEAL_S)
            report[n] = dict(rc=rc, problems=p)
            self.action(
                n, "self-heal-armed", sent=round(sent, 3), done=round(done, 3), rc=rc, problems=p
            )
        self.write("self-heal.json", report)
        return all(v["rc"] == 0 and not v["problems"] for v in report.values())

    def apply_partition(self) -> bool:
        sides = self.sc["partition"]
        self.ev["partition_confirmed"] = False
        if not self.arm_heal():
            self.say("self-heal not verified on all 4: heal all 4 unconditionally, no rule loaded")
            self.heal()
            return False
        load_t = self.now()
        cmds = {
            n: lib.load_cmd(n, sides[n], self.use_v6 or not self.execute) for n in lib.VALIDATORS
        }
        res = self.parallel(cmds, "load the counted partition rules")
        if self.execute:
            for n, (rc, _o, sent, done) in res.items():
                self.action(n, "partition-apply", sent=round(sent, 3), done=round(done, 3), rc=rc)
        ver = self.parallel(
            {n: lib.verify_cmd() for n in lib.VALIDATORS},
            "verify the rules and counters are loaded",
            timeout=15,
        )
        ok = True
        if self.execute:
            self.write(
                "partition-verify.json",
                {
                    n: dict(rc=rc, loaded=lib.partition_loaded(out, sides[n]), done=round(d, 3))
                    for n, (rc, out, _s, d) in ver.items()
                },
            )
            ok = (
                all(r[0] == 0 for r in res.values())
                and max(d for *_x, d in ver.values()) <= load_t + 15
                and all(
                    rc == 0 and lib.partition_loaded(out, sides[n])
                    for n, (rc, out, _s, _d) in ver.items()
                )
            )
        self.ev["partition_confirmed"] = ok
        if not ok:
            self.say("partition NOT confirmed on all 4 within 15 s: heal all 4 now, INCONCLUSIVE")
            self.heal()
        return ok

    def read_counters(self) -> None:
        res = self.parallel(
            {n: lib.verify_cmd() for n in lib.VALIDATORS},
            "read the drop counters before the heal (addresses not kept)",
        )
        if self.execute:
            c = {n: lib.counters(out) for n, (rc, out, _s, _d) in res.items() if rc == 0}
            self.ev["partition_counters"] = c
            self.write("partition-counters.json", c)

    def heal(self) -> float:
        t = self.now()
        res = self.parallel(
            {n: lib.heal_cmd(self.run) for n in lib.VALIDATORS},
            "heal: delete the table, stop the self-heal timer (idempotent)",
        )
        if self.execute:
            for n, (rc, _out, sent, done) in res.items():
                self.action(n, "heal", sent=round(sent, 3), done=round(done, 3), rc=rc)
            for n in [n for n, r in res.items() if r[0] != 0]:
                rc, _ = self.on(n, lib.heal_cmd(self.run), "heal retry (self-heal is the backstop)")
                self.action(n, "heal-retry", rc=rc)
        self.ev["healed"] = t
        return t

    def tables_gone(self) -> None:
        res = self.parallel({n: "nft list tables" for n in lib.VALIDATORS}, "no t3part left")
        if self.execute:
            gone = True
            for n, (rc, out, _s, _d) in res.items():
                self.write(f"nft-{n}.txt", out)
                gone = gone and rc == 0 and lib.TABLE not in out
            self.ev["deadlines"]["no t3part table on all 4 after heal"] = gone

    def post(self) -> None:
        self.ev["end"] = self.ev["post_from"] = self.now()
        self.sleep_until(self.ev["end"] + 300, "rejoin + 5 min (post rate from the samples)")

    def watch_until(self, t: float, why: str) -> None:
        """Sleep until t; with 3 of 4 up, a 60 s stall restores the target early."""
        if not self.execute:
            return self.sleep_until(t, why)
        last, since = None, self.now()
        while self.now() < t:
            self.check_abort()
            h = self.base_head(lib.RATE_PORTS)
            if h is not None and h != last:
                last, since = h, self.now()
            if self.now() - since >= 60:
                self.ev["early_restore"] = f"no block for 60 s with 3 of 4 up at {self.rel()}"
                raise Abort(self.ev["early_restore"])
            self._sleep(5)

    # ------------------------------------------------------------ scenarios

    def s1(self) -> None:
        self.stop("node-4")
        self.ev["restarted"] = ["node-4"]
        self.ev["outage_from"] = self.t0 + 30
        self.watch_until(self.t0 + 300, "t0+300s (3 of 4 must continue; rate from samples)")
        self.ev["outage_to"] = self.now()
        base = self.base_head(lib.REJOIN_PEERS["node-4"])
        t = self.start("node-4")
        self.safety_check("after node-4's start")
        ports = (lib.PORT["node-4"], *lib.REJOIN_PEERS["node-4"])
        self.ev["deadlines"]["node-4 rejoin <= 10 min after start"] = self.wait(
            self.rejoin(ports, base),
            t + 600,
            "node-4 within 5 of 18081/28081, progress, one hash at the common height",
        )
        self.post()

    def s2(self) -> None:
        r = self.node("node-3", "--kill", why="SIGKILL through systemd; Restart=on-failure")
        self.ev["restarted"] = ["node-3"]
        self.ev["outage_from"] = self.t0
        if self.execute and r.get("result") not in (
            "RESTARTED-BY-SYSTEMD",
            "STARTED-AFTER-FALLBACK",
        ):
            raise Abort(f"node-3 kill refused: {r.get('result')}", fail=False)
        base = self.base_head(lib.REJOIN_PEERS["node-3"])
        self.await_after_kill(r)
        self.safety_check("after node-3's markers")
        ports = (lib.PORT["node-3"], *lib.REJOIN_PEERS["node-3"])
        ok = self.wait(
            self.rejoin(ports, base),
            self.t0 + 600,
            "node-3 within 5 of 18081/38081, progress, one hash at the common height",
        )
        self.ev["deadlines"]["node-3 rejoin <= 10 min after kill"] = ok
        self.ev["outage_to"] = self.now()
        self.post()

    def await_after_kill(self, killed: dict) -> None:
        t0 = str(int(killed.get("t0") or self.t0)) if self.execute else "<kill t0>"
        self.node_results["node-3"] = self.node(
            "node-3",
            "--after-kill",
            t0,
            "--binding",
            self.bindings["node-3"],
            why="markers after the kill (per-session load lines are judged too)",
        )

    def s3(self) -> None:
        self.stop("node-4", restore_after=int(self.t0 + lib.RESTORE_AT - self.now()))
        self.ev["restarted"] = ["node-4"]
        base = self.base_head(lib.RATE_PORTS)
        self.sleep_until(self.t0 + 30, "t0+30s")
        adv = self.wait(
            self.new_block_after(lib.RATE_PORTS, base),
            self.t0 + 40,
            "the head advances with 3 of 4 (18081/38081)",
            step=2,
        )
        self.ev["deadlines"]["head advances with 3 of 4 at t0+30s"] = adv
        if not adv:
            raise Abort("no block with 3 of 4 up")
        self.sleep_until(self.t0 + 60, "t0+60s")
        self.stop("node-3", restore_after=int(self.t0 + lib.RESTORE_AT - self.now()))
        self.ev["restarted"] = ["node-3", "node-4"]
        self.ev["halt_from"] = self.now()
        self.ev["settle"] = self.settle
        self.sleep_until(
            self.t0 + 360,
            f"t0+6 min (halt: no progress after the {self.settle:.0f}"
            " s settling interval, from the samples)",
        )
        self.ev["halt_to"] = self.now()
        self.restore_both()
        self.post()

    def restore_both(self) -> None:
        """Both starts are always attempted; one host's refusal, timeout or untrusted ledger
        never skips the other. Their own restore timers are the backstop."""
        base = self.base_head(lib.RATE_PORTS)
        t3 = self.now()
        e3 = self.start_engine("node-3")
        a3 = (
            self.await_signing("node-3", e3)
            if (not self.execute or e3.get("result") == "ENGINE-STARTED")
            else e3
        )
        resumed = False
        if not self.execute or a3.get("result") == "TRUSTED-RESIGNED":
            resumed = self.wait(
                self.new_block_after(lib.RATE_PORTS, base),
                t3 + 300,
                "a new masterchain block after node-3's start",
            )
            self.ev["deadlines"]["new block <= 5 min after node-3 start"] = resumed
        else:
            self.say(f"  node-3: {a3.get('result')}; node-4 starts now, not at t0+11 min")
        t4 = self.now()
        e4 = self.start_engine("node-4")
        if not self.execute or e4.get("result") == "ENGINE-STARTED":
            self.await_signing("node-4", e4)
        self.safety_check("after both starts")
        self.ev["deadlines"]["all 4 rejoined <= 10 min after node-4 start"] = self.wait(
            self.rejoin(lib.ALL_PORTS, base),
            t4 + 600,
            "all four within 5, progress, one hash at the common height",
        )
        if self.execute and not (
            resumed or self.ev["deadlines"]["all 4 rejoined <= 10 min after node-4 start"]
        ):
            raise Abort("no resume after both starts")

    def s4(self) -> None:
        if self.apply_partition():
            self.ev["halt_from"] = self.now()
            self.ev["settle"] = self.settle
            self.sleep_until(
                self.t0 + 300,
                f"t0+5 min (both sides: no progress after the "
                f"{self.settle:.0f} s settling interval)",
            )
            self.ev["halt_to"] = self.now()
            self.read_counters()
        base = self.base_head(lib.ALL_PORTS)
        h = self.heal() if self.ev["partition_confirmed"] else self.ev["healed"]
        self.tables_gone()
        self.safety_check("after the heal")
        ok = self.wait(
            self.new_block_after(lib.ALL_PORTS, base), h + 300, "a new block after the heal"
        )
        self.ev["deadlines"]["new block <= 5 min after heal"] = ok
        self.ev["deadlines"]["all 4 rejoined <= 10 min after heal"] = self.wait(
            self.rejoin(lib.ALL_PORTS, base),
            h + 600,
            "all four within 5, progress, one hash at the common height",
        )
        if not ok:
            raise Abort("no block within 5 min of the heal")
        self.post()

    # ------------------------------------------------------------ safety

    def pull_logs(self, tag: str = "") -> dict:
        logs = {}
        for n in lib.VALIDATORS:
            rc, out = self.on(n, lib.log_cmd(), f"log pull {n}", timeout=120)
            if not self.execute:
                continue
            if rc not in (0, 1):
                logs[n] = None
                continue
            lines = lib.lines_since(out, self.t0)
            self.write(f"log-{n}{'-' + tag if tag else ''}.txt", "\n".join(lines) + "\n")
            logs[n] = lines
        self.logs = logs
        return logs

    def safety_check(self, stage: str, tag: str = "scan") -> None:
        self.say(f"SAFETY scan {stage}: double-sign allegations and conflict refusals, all 4")
        logs = self.pull_logs(tag)
        if not self.execute:
            return
        events = [e for n, lines in logs.items() for e in lib.safety_events(n, lines or [])]
        for n, r in self.node_results.items():
            if r.get("result") == "SAFETY-QUARANTINED":
                events.append(dict(kind="unsafe-marker", reporter=n, implicated=n))
        if events:
            raise SafetyAbort(events)

    def safety_abort(self, events: list[dict]) -> None:
        self.say(f"SAFETY ABORT: {len(events)} event(s); automatic restore is OFF")
        self.ev["safety"] = events
        if self.sc["partition"]:
            self.say("safety 1: heal connectivity on all 4")
            self.heal()
        hosts, unresolved = (
            lib.implicated_hosts(events, self.ids) if self.execute else (["<implicated host>"], [])
        )
        self.ev["quarantined"] = hosts
        if unresolved:
            self.ev["safety_unresolved"] = unresolved
            self.say(
                f"  implicated identity unresolved {unresolved}: no host restarted, "
                "every automatic action stopped"
            )
        for h in hosts:
            self.say(f"safety 2: quarantine {h}: stop its validator and elections, no restart")
            if self.execute:
                r = self.node(h, "--quarantine", why="quarantine")
                self.write(
                    f"QUARANTINE-{h}",
                    json.dumps(dict(run=self.run, events=events, result=r), default=str) + "\n",
                )
            else:
                self.on(h, lib.node_cmd(h, "--quarantine", "--run", self.run), "quarantine")
            if self.execute:
                (self.out / f"quarantine-{h}").mkdir(exist_ok=True)
            self.helper(
                "get",
                h,
                "/var/log/tos/validator/node.log*",
                str(self.out / f"quarantine-{h}") if self.execute else f"<run>/quarantine-{h}/",
            )
        self.say(
            "safety 3: SAFETY_FAIL recorded. Restart only after the coordinator writes "
            "CLEARED-node-N in the run directory and removes /root/t3-quarantine-RUN on "
            "the host by hand; t3-run.sh refuses every run until then"
        )

    # ------------------------------------------------------------ the abort ladder

    def ladder(self, reason: str) -> bool:
        self.say(f"ABORT LADDER (availability): {reason}")
        self.ev["ladder"].append(dict(reason=reason, utc=lib.utc(self._clock())))
        if self.sc["partition"]:
            self.say("ladder 1: heal the partition on all 4 (idempotent)")
            self.heal()
        self.say(
            "ladder 2: start every engine that is not active, then await each one's "
            "signing; an untrusted node stays fenced with elections stopped"
        )
        started = []
        for n in self.sc["targets"] + [x for x in lib.VALIDATORS if x not in self.sc["targets"]]:
            if n in self.ev["quarantined"]:
                continue
            rc, out = self.on(n, "systemctl is-active tos-testnet-validator", f"is {n} active?")
            if self.execute and out.strip() == "active":
                continue
            if not self.execute:
                self.say(f"IF {n} is not active:")
            started.append((n, self.start_engine(n)))
        for n, e in started:
            if not self.execute or e.get("result") == "ENGINE-STARTED":
                self.await_signing(n, e)
        base = self.base_head(lib.ALL_PORTS)
        if (
            self.wait(
                self.new_block_after(lib.ALL_PORTS, base),
                self.now() + 300,
                "a new block within 5 min after all 4 are active",
            )
            and self.execute
        ):
            self.ev["ladder"].append(dict(recovered=lib.utc(self._clock())))
            return True
        if not self.execute:
            self.say("IF no new block within those 5 min:")
        self.say("ladder 3: capture evidence; the one-at-a-time restarts are NOT run automatically")
        cap = {}
        for p in lib.ALL_PORTS:
            try:
                cap[p] = rpc(p, "getConsensusBlock") if self.execute else None
            except Exception as e:
                cap[p] = repr(e)
        self.write("ladder-consensus.json", cap)
        self.pull_logs("ladder")
        for n in ("node-4", "node-3", "node-2", "node-1"):
            self.say(
                f"  NEXT BY HAND: on {n} 'systemctl restart tos-testnet-validator', then the "
                "markers; wait 3 min before the next host; never tos-testnet-dht"
            )
        self.say(
            "ladder 4: if still halted at the hard abort: STOP T3, STATUS entry, tos issue, "
            "leave the network for the owner (the mute expires by itself). No genesis, "
            "ledger or binary change."
        )
        self.ev["ladder"].append(dict(stopped=lib.utc(self._clock())))
        return False

    def body(self) -> None:
        getattr(self, self.s.lower())()


def dry_run(scenario: str, printer=print) -> None:
    r = Runner(scenario, f"t3-<YYYYMMDDTHHMMZ>-{scenario}", execute=False, printer=printer)
    sc = r.sc
    printer(f"===== {scenario}: {sc['title']} (DRY RUN: nothing below is executed) =====")
    printer(f"hard abort t0+{sc['abort']}s; budget {sc['budget']}s; evidence /datax/t3/{r.run}/")
    r.say("LOCAL refuse while any QUARANTINE-node-N under /datax/t3 lacks CLEARED-node-N")
    r.say("LOCAL flock -n $DEPLOY/u76af/upgrade.lock (held for the whole run)")
    r.say(
        f"LOCAL RUN={r.run} t3-preflight.sh {scenario}    # pins, rollout accepted, the two "
        "acceptance handovers, ConfigParam 34 from two sources, then:"
    )
    r.gates("pre")
    r.load_bindings()
    r.put_node_script()
    r.local(
        [
            "python3",
            "t3-sample.py",
            "--out",
            "samples.jsonl",
            "--duration",
            str(lib.SAMPLER_LEAD + sc["abort"] + lib.SAMPLER_TAIL + 600),
        ],
        "sampler, background; R0 is its fresh progress over the lead",
    )
    r.sleep_until(-lib.SAMPLER_LEAD, "sampler lead")
    r.vnow = -2
    r.gates("t0")
    r.t0 = 0.0
    r.vnow = -1
    r.mute()
    r.vnow = 0
    r.body()
    r.say("LOCAL final log pull and safety scan; ConfigParam 36 / active_election_id at the end")
    r.say(
        "LOCAL stop the sampler at end+600 s; verdict.json (next handover pending, scope "
        "statement) and SHA256SUMS"
    )
    printer(
        f"----- availability abort ladder: only on a missed deadline, a refused step or the "
        f"hard abort (t0+{sc['abort']}s); times below are illustrative -----"
    )
    r.ladder("example trigger")
    printer("----- safety abort: on a double-sign allegation or a ledger conflict refusal -----")
    r.safety_abort([dict(kind="example")])
    printer(f"----- end of {scenario} -----")
    printer("")


def run_gates(scenario: str, run: str, out: Path) -> int:
    r = Runner(scenario, run, execute=True, out_dir=out)
    try:
        r.gates("pre")
    except GateStop as e:
        print(f"STOP: {e}")
        return 3
    print("GATES PASS (pre)")
    return 0


def finish(r: Runner, out: Path, run: str, stopped: bool, logs: dict) -> int:
    term = json.loads((out / "term.json").read_text())
    try:
        cp36 = rpc_raw(18081, "getConfigParam", 15, param=36)
        el = rpc_raw(
            18081,
            "runGetMethod",
            15,
            address="-1:" + "3" * 64,
            method="active_election_id",
            stack=[],
        )
        r.ev["election_end"] = lib.election_problems(cp36, el)
    except Exception as e:
        r.ev["election_end"] = [f"not read: {e!r}"]
    samples = lib.load_samples(out / "samples.jsonl")
    v = lib.compute_verdict(
        r.s, samples=samples, events=r.ev, node_results=r.node_results, logs=logs
    )
    if stopped and v["verdict"] != "SAFETY_FAIL":
        v["fail"].append("abort ladder reached step 4: network left for the owner")
        v["verdict"] = v["final"] = "FAIL"
    nh = lib.handover_dir(r.handovers, int(term["until"]))
    v["next_handover"].update(
        boundary=int(term["until"]),
        boundary_utc=lib.utc(int(term["until"])),
        classify=str(nh / "CLASSIFY.json"),
    )
    v.update(run=run, events=r.ev, tos_ops_commit=os.environ.get("T3_COMMIT"))
    r.write("verdict.json", v)
    names = sorted(p.name for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in names)
    )
    r.say(f"VERDICT {v['verdict']} (final: {v['final']}); {out}/verdict.json")
    return {"PASS": 0, "FAIL": 1, "SAFETY_FAIL": 5}.get(v["verdict"], 2)


def execute(scenario: str, run: str, out: Path) -> int:
    r = Runner(scenario, run, execute=True, out_dir=out)
    r.load_bindings()
    duration = lib.SAMPLER_LEAD + r.sc["abort"] + lib.SAMPLER_TAIL + 600
    sampler = subprocess.Popen(
        [
            sys.executable,
            "-I",
            str(HERE / "t3-sample.py"),
            "--out",
            str(out / "samples.jsonl"),
            "--duration",
            str(duration),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=open(out / "sampler.err", "w"),
    )
    try:
        r.put_node_script()
        start = r.now()
        r.sleep_until(start + lib.SAMPLER_LEAD, "sampler lead")
        r.gates("t0")
        r.mute()
    except (GateStop, Abort) as e:
        sampler.terminate()
        r.say(f"STOP before any fault: {e}")
        return 3
    except BaseException:
        sampler.terminate()
        raise
    r.t0 = r.now()
    r.hard_abort = r.t0 + r.sc["abort"]
    r.ev.update(t0=r.t0, t0_utc=lib.utc(r.t0), r0_from=r.t0 - lib.SAMPLER_LEAD + 5, r0_to=r.t0)
    stopped = False
    try:
        try:
            r.body()
        except Abort as e:
            r.hard_abort = None
            if e.fail:
                r.ev["deadlines"][f"abort: {e}"] = False
            else:
                r.ev["outside_abort"] = str(e)
            stopped = not r.ladder(str(e))
            r.ev.setdefault("end", r.now())
        except SafetyAbort:
            raise
        except Exception as e:  # an unexpected error still restores production first
            r.hard_abort = None
            r.ev["outside_abort"] = f"runner error {e!r}"[:300]
            stopped = not r.ladder(f"runner error {e!r}"[:300])
            r.ev.setdefault("end", r.now())
        r.hard_abort = None
        r.safety_check("final", tag="")
    except SafetyAbort as e:
        r.hard_abort = None
        r.safety_abort(e.events)
        stopped = True
        r.ev.setdefault("end", r.now())
    logs = r.logs or r.pull_logs()
    if not stopped:
        r.sleep_until(r.ev["end"] + lib.SAMPLER_TAIL, "sampler tail end+600 s")
    sampler.terminate()
    try:
        sampler.wait(timeout=15)
    except subprocess.TimeoutExpired:
        sampler.kill()
    return finish(r, out, run, stopped, logs)


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--dry-run" and argv[1] in [*lib.SCENARIOS, "all"]:
        for s in lib.SCENARIOS if argv[1] == "all" else [argv[1]]:
            dry_run(s)
        return 0
    if len(argv) == 3 and argv[0] in ("--execute", "--gates") and argv[1] in lib.SCENARIOS:
        out = Path(os.environ.get("T3_EVIDENCE", "/datax/t3")) / argv[2]
        if not out.is_dir() or "build" in out.parts:
            print(f"STOP: evidence directory {out} missing or under build/")
            return 3
        return (execute if argv[0] == "--execute" else run_gates)(argv[1], argv[2], out)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
