"""T3 scenario runner, called by t3-run.sh (which holds the upgrade lock and ran the pre-flight).

  t3_run.py --dry-run S1|S2|S3|S4|S5|all
  t3_run.py --execute S1..S5 RUN          (only from t3-run.sh --execute)

The dry run prints every host and local command a scenario would issue, in order, with its
planned time offset, including the abort ladder, and executes none of them: it does not
source the host helpers, resolve an address, take a lock or create a directory.

Execution follows the plan's section-5 table: sampler, mute, the timed actions, the resume
deadlines and the hard abort, the abort ladder (steps 1-2 automatic; step 3 evidence is
captured and its restarts are printed, not run; step 4 stops and leaves the network), the
log pulls and the section-5.1 verdict with the next handover pending. Every host action is
`on NODE CMD` through the sourced epoch helpers. Partition addresses are `$(addr X)`
references resolved in memory at execution time; files and output keep the references.
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


class Abort(Exception):
    """A missed deadline, a refused step or the hard abort: run the abort ladder.

    fail=True: the scenario's own criterion failed (stall, no resume, hard abort).
    fail=False: a step was refused for an outside reason, which is INCONCLUSIVE."""

    def __init__(self, msg: str, fail: bool = True):
        super().__init__(msg)
        self.fail = fail


def rpc(port: int, method: str, timeout: float = 10, **params):
    body = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/jsonRPC", body, {"Content-Type": "application/json"}
    )
    d = json.load(OPENER.open(req, timeout=timeout))
    if "error" in d:
        raise RuntimeError(d["error"])
    return d["result"]


def shown(arg: str) -> str:
    """Quote for display only when needed; `$NAME` references stay visible as written."""
    return arg if re.fullmatch(r"[\w$./:+=,<>-]+", arg) else f'"{arg}"'


def quote(cmd: str) -> str:
    """Display form of a host command: the plan's double quotes when it holds single quotes."""
    return f'"{cmd}"' if "'" in cmd and '"' not in cmd else shlex.quote(cmd)


def redact(text: str) -> str:
    """Host addresses never reach evidence files (an ssh error names the host)."""
    return re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<addr>", text)


def head(port: int) -> int:
    return int(rpc(port, "getMasterchainInfo")["last"]["seqno"])


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
        self.ev: dict = dict(deadlines={}, restarted=[], rates_during=[], ladder=[])
        self.node_results: dict = {}
        self.bindings: dict = {}
        self.deploy = os.environ.get(
            "T3_DEPLOY", str(Path.home() / "tos-testnet-deploy/epoch-6/run")
        )
        self.helpers = str(Path(self.deploy) / "helpers.sh")
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
        shown = f"on {node} {quote(cmd)}" + (f" < {stdin}" if stdin else "")
        if not quiet:
            self.say(f"HOST  {shown}    # {why}")
        if not self.execute:
            return 0, ""
        real = lib.resolve(cmd, self.addr)
        fin = open(stdin) if stdin else subprocess.DEVNULL
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
            f.write(json.dumps(dict(utc=lib.utc(self._clock()), cmd=shown, rc=r.returncode)) + "\n")
        return r.returncode, r.stdout + r.stderr

    def addr(self, node: str) -> str:
        r = subprocess.run(
            ["bash", "-c", '. "$1"; addr "$2"', "t3-addr", self.helpers, node],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode != 0:
            raise Abort(f"addr {node} failed")
        return r.stdout

    def local(self, argv: list[str], why: str, out_name: str | None = None, timeout: int = 120):
        self.say(
            f"LOCAL {' '.join(shown(a) for a in argv)}"
            + (f" > {out_name}" if out_name else "")
            + f"    # {why}"
        )
        if not self.execute:
            return 0, ""
        argv = [os.path.expandvars(a.replace("$DEPLOY", self.deploy)) for a in argv]
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, ""
        if out_name:
            (self.out / out_name).write_text(r.stdout)
        return r.returncode, r.stdout

    def parallel(self, cmds: dict[str, str], why: str, timeout: int = 60) -> dict:
        if not self.execute:
            return {n: self.on(n, c, why) for n, c in cmds.items()}
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
        rc, out = self.on(node, lib.node_cmd(node, mode, *extra), why)
        if not self.execute:
            return dict(result="DRY", t0=self.now())
        try:
            res = json.loads([x for x in out.splitlines() if x.startswith("{")][-1])
        except (ValueError, IndexError):
            res = dict(result="NO-JSON", rc=rc, tail=redact(out[-500:]))
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

    def rate(self, name: str) -> float | None:
        a, b = map(str, lib.RATE_PORTS)
        rc, out = self.local(
            ["python3", "$DEPLOY/u76af/block-rate.py", a, b, "300"],
            "block rate",
            f"rate-{name}.json",
        )
        if not self.execute:
            return None
        try:
            return float(json.loads(out)["rate"]) if rc == 0 else None
        except (ValueError, KeyError):
            return None

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

    def rejoined(self, node: str) -> bool:
        pa, pb = lib.REJOIN_PEERS[node]
        h_self, h_a, h_b = head(lib.PORT[node]), head(pa), head(pb)
        return abs(h_self - max(h_a, h_b)) <= 5 and min(h_a, h_b) > 0

    def all_within_5(self) -> bool:
        h = [head(p) for p in lib.ALL_PORTS]
        return max(h) - min(h) <= 5

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
            self.say(f"HOST  put {n} {src.name} /root/t3-node.py    # copy the node script")
            if not self.execute:
                self.on(n, "sha256sum /root/t3-node.py", f"must equal {want[:16]}...")
                continue
            r = subprocess.run(
                [
                    "bash",
                    "-c",
                    '. "$1"; put "$2" "$3" /root/t3-node.py',
                    "t3-put",
                    self.helpers,
                    n,
                    str(src),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            rc, out = self.on(n, "sha256sum /root/t3-node.py", "verify the copy")
            if r.returncode != 0 or rc != 0 or out.split()[:1] != [want]:
                raise SystemExit(f"STOP: t3-node.py copy on {n} differs or failed")

    def load_bindings(self) -> None:
        for n in lib.VALIDATORS:
            if self.execute:
                self.bindings[n] = lib.ledger_binding((self.out / f"pre-{n}.txt").read_text())
            else:
                self.bindings[n] = f"<DEV:INO from pre-{n}.txt>"

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
            raise SystemExit("STOP: the alert silence was not written")

    def stop(self, n: str) -> None:
        r = self.node(n, "--stop", why=f"clean stop of {n} (elections, then validator)")
        if self.execute and r.get("result") != "STOPPED":
            raise Abort(f"{n} stop refused: {r.get('result')}", fail=False)

    def start(self, n: str) -> float:
        t = self.now()
        r = self.node(
            n, "--start", "--binding", self.bindings[n], why=f"start {n}: markers, then elections"
        )
        self.node_results[n] = r
        if self.execute and r.get("result") != "TRUSTED-RESIGNED":
            self.say(f"  {n} start result {r.get('result')}")
        return t

    def apply_partition(self) -> bool:
        sides = self.sc["partition"]
        cmds = {n: lib.partition_cmd(n, sides[n], self.run) for n in lib.VALIDATORS}
        res = self.parallel(cmds, "apply the partition rule and arm the 12 min self-heal")
        if self.execute:
            for n, (rc, _out, sent, done) in res.items():
                self.action(n, "partition-apply", sent=round(sent, 3), done=round(done, 3), rc=rc)
        res = self.parallel(
            {n: lib.verify_cmd() for n in lib.VALIDATORS}, "verify the rules are loaded", timeout=15
        )
        ok = True
        if self.execute:
            (self.out / "partition-verify.json").write_text(
                json.dumps(
                    {
                        n: dict(rc=rc, loaded=lib.partition_loaded(out), done=round(d, 3))
                        for n, (rc, out, _s, d) in res.items()
                    },
                    indent=1,
                )
            )
            ok = max(d for *_x, d in res.values()) <= self.t0 + 15 and all(
                rc == 0 and lib.partition_loaded(out) for rc, out, _s, _d in res.values()
            )
        self.ev["partition_confirmed"] = ok
        if not ok:
            self.say("partition NOT confirmed on all 4 within 15 s: heal now, INCONCLUSIVE")
            self.heal()
        return ok

    def heal(self) -> float:
        t = self.now()
        res = self.parallel(
            {n: lib.heal_cmd(self.run) for n in lib.VALIDATORS},
            "heal: delete the table, stop the self-heal timer",
        )
        if self.execute:
            for n, (rc, _out, sent, done) in res.items():
                self.action(n, "heal", sent=round(sent, 3), done=round(done, 3), rc=rc)
            bad = [n for n, r in res.items() if r[0] != 0]
            if bad:
                self.say(
                    f"  heal not confirmed on {bad}; retry once (the self-heal timer is the backstop)"
                )
                for n in bad:
                    rc, _ = self.on(n, lib.heal_cmd(self.run), "heal retry")
                    self.action(n, "heal-retry", rc=rc)
        self.ev["healed"] = t
        return t

    def post(self) -> None:
        self.ev["end"] = self.now()
        self.sleep_until(self.ev["end"] + 300, "rejoin + 5 min, then the post rate")
        self.ev["rate_post"] = self.rate("post")

    # ------------------------------------------------------------ scenarios

    def s1(self) -> None:
        self.stop("node-4")
        self.ev["restarted"] = ["node-4"]
        for at in (180, 300):
            self.watch_until(self.t0 + at, f"t0+{at}s (3 of 4 must continue)")
            self.ev["rates_during"].append(self.rate(f"t0+{at}"))
        self.ev["outage_end"] = self.now()
        t = self.start("node-4")
        self.ev["deadlines"]["node-4 rejoin <= 10 min after start"] = self.wait(
            lambda: self.rejoined("node-4"), t + 600, "node-4 head within 5 of 18081/28081"
        )
        self.post()

    def s2(self) -> None:
        r = self.node(
            "node-3", "--kill", why="SIGKILL through systemd; Restart=on-failure restarts it"
        )
        self.ev["restarted"] = ["node-3"]
        if self.execute and r.get("result") not in (
            "RESTARTED-BY-SYSTEMD",
            "STARTED-AFTER-FALLBACK",
        ):
            raise Abort(f"node-3 kill refused: {r.get('result')}", fail=False)
        kill_t0 = int(r.get("t0") or self.t0)
        a = self.node(
            "node-3",
            "--after-kill",
            str(kill_t0) if self.execute else "<kill t0>",
            "--binding",
            self.bindings["node-3"],
            why="markers after the kill",
        )
        self.node_results["node-3"] = a
        ok = self.wait(
            lambda: self.rejoined("node-3"), self.t0 + 600, "node-3 head within 5 of 18081/38081"
        )
        self.ev["deadlines"]["node-3 rejoin <= 10 min after kill"] = ok
        self.ev["outage_end"] = self.now()
        self.ev["rates_during"].append(self.rate("outage"))
        self.post()

    def s3(self) -> None:
        self.stop("node-4")
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
        self.stop("node-3")
        self.ev["restarted"] = ["node-3", "node-4"]
        self.ev["halt_from"] = self.now() + 10
        self.sleep_until(self.t0 + 360, "t0+6 min (halt observed by the sampler)")
        self.ev["halt_to"] = self.now()
        base = self.base_head(lib.RATE_PORTS)
        t3 = self.start("node-3")
        ok = self.wait(
            self.new_block_after(lib.RATE_PORTS, base),
            t3 + 300,
            "a new masterchain block after node-3's start",
        )
        self.ev["deadlines"]["new block <= 5 min after node-3 start"] = ok
        self.sleep_until(self.t0 + 660 if not ok else self.now(), "resumed, or t0+11 min")
        t4 = self.start("node-4")
        self.ev["deadlines"]["all 4 rejoined <= 10 min after node-4 start"] = self.wait(
            self.all_within_5, t4 + 600, "all four heads within 5"
        )
        if not ok:
            raise Abort("no resume within 5 min of node-3's start")
        self.post()

    def s4(self) -> None:
        if self.apply_partition():
            self.ev["halt_from"] = self.t0 + 20
            self.sleep_until(self.t0 + 300, "t0+5 min (both sides frozen, sampler)")
            self.ev["halt_to"] = self.now()
            base = self.base_head(lib.ALL_PORTS)
            h = self.heal()
        else:
            base = self.base_head(lib.ALL_PORTS)
            h = self.ev["healed"]
        ok = self.wait(
            self.new_block_after(lib.ALL_PORTS, base), h + 300, "a new block after the heal"
        )
        self.ev["deadlines"]["new block <= 5 min after heal"] = ok
        self.ev["deadlines"]["all 4 heads within 5 <= 10 min after heal"] = self.wait(
            self.all_within_5, h + 600, "all four heads within 5"
        )
        self.tables_gone()
        if not ok:
            raise Abort("no block within 5 min of the heal")
        self.post()

    def s5(self) -> None:
        if self.apply_partition():
            for at in (180, 300):
                self.watch_until(self.t0 + at, f"t0+{at}s (the side of three continues)")
                self.ev["rates_during"].append(self.rate(f"t0+{at}"))
            self.ev["outage_end"] = self.now()
            h = self.heal()
        else:
            h = self.ev["healed"]
            self.ev["outage_end"] = h
        self.ev["deadlines"]["node-4 rejoin <= 10 min after heal"] = self.wait(
            lambda: self.rejoined("node-4"), h + 600, "node-4 head within 5 of 18081/28081"
        )
        self.tables_gone()
        self.post()

    def tables_gone(self) -> None:
        res = self.parallel({n: "nft list tables" for n in lib.VALIDATORS}, "no t3part left")
        if self.execute:
            gone = True
            for n, (rc, out, _s, _d) in res.items():
                (self.out / f"nft-{n}.txt").write_text(out)
                gone = gone and rc == 0 and lib.TABLE not in out
            self.ev["deadlines"]["no t3part table on all 4 after heal"] = gone

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

    # ------------------------------------------------------------ the abort ladder

    def ladder(self, reason: str) -> bool:
        self.say(f"ABORT LADDER: {reason}")
        self.ev["ladder"].append(dict(reason=reason, utc=lib.utc(self._clock())))
        if self.sc["partition"]:
            self.say("ladder 1: heal the partition on all 4 (idempotent)")
            self.heal()
        self.say(
            "ladder 2: start every validator that is not active (markers; untrusted stays fenced)"
        )
        for n in self.sc["targets"] + [x for x in lib.VALIDATORS if x not in self.sc["targets"]]:
            rc, out = self.on(n, "systemctl is-active tos-testnet-validator", f"is {n} active?")
            if self.execute and out.strip() == "active":
                continue
            if not self.execute:
                self.say(f"IF {n} is not active:")
            self.start(n)
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
        if self.execute:
            (self.out / "ladder-consensus.json").write_text(json.dumps(cap, indent=1))
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

    # ------------------------------------------------------------ logs and verdict

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
            (self.out / f"log-{n}{'-' + tag if tag else ''}.txt").write_text(
                "\n".join(lines) + "\n"
            )
            logs[n] = lines
        return logs

    def body(self) -> None:
        getattr(self, self.s.lower())()


def dry_run(scenario: str, printer=print) -> None:
    r = Runner(scenario, f"t3-<YYYYMMDDTHHMMZ>-{scenario}", execute=False, printer=printer)
    sc = r.sc
    printer(f"===== {scenario}: {sc['title']} (DRY RUN: nothing below is executed) =====")
    printer(f"hard abort t0+{sc['abort']}s; budget {sc['budget']}s; evidence /datax/t3/{r.run}/")
    r.say("LOCAL flock -n $DEPLOY/u76af/upgrade.lock (held for the whole run)")
    r.say(f"LOCAL RUN={r.run} t3-preflight.sh {scenario}    # section 4; read-only")
    for n in lib.VALIDATORS:
        r.on(n, f"bash -s -- {n}", "pre-flight host facts (read-only)", stdin="t3-host-check.sh")
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
        "sampler, background",
    )
    r.sleep_until(-lib.SAMPLER_LEAD, "sampler lead")
    r.t0 = 0.0
    r.vnow = -1
    r.mute()
    r.vnow = 0
    r.body()
    r.pull_logs()
    r.say(
        "LOCAL stop the sampler at end+600 s; write verdict.json (next handover pending) and SHA256SUMS"
    )
    printer(
        f"----- abort ladder: only on a missed deadline, a refused step or the hard abort "
        f"(t0+{sc['abort']}s); times below are illustrative -----"
    )
    r.ladder("example trigger")
    printer(f"----- end of {scenario} -----")
    printer("")


def execute(scenario: str, run: str, out: Path) -> int:
    r = Runner(scenario, run, execute=True, out_dir=out)
    r.load_bindings()
    r.put_node_script()
    term = json.loads((out / "term.json").read_text())
    r0 = float(json.loads((out / "R0.json").read_text())["rate"])
    duration = lib.SAMPLER_LEAD + r.sc["abort"] + lib.SAMPLER_TAIL + 600
    r.say(f"LOCAL sampler for {duration}s")
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
        r.sleep_until(r.now() + lib.SAMPLER_LEAD, "sampler lead")
        r.mute()
    except BaseException:
        sampler.terminate()
        raise
    r.t0 = r.now()
    r.hard_abort = r.t0 + r.sc["abort"]
    r.ev["t0"] = r.t0
    r.ev["t0_utc"] = lib.utc(r.t0)
    stopped = False
    try:
        r.body()
    except Abort as e:
        r.hard_abort = None
        if e.fail:
            r.ev["deadlines"][f"abort: {e}"] = False
        else:
            r.ev["outside_abort"] = str(e)
        if not r.ladder(str(e)):
            stopped = True
        r.ev.setdefault("end", r.now())
    except Exception as e:  # an unexpected error still restores production first
        r.hard_abort = None
        r.ev["outside_abort"] = f"runner error {e!r}"[:300]
        if not r.ladder(f"runner error {e!r}"[:300]):
            stopped = True
        r.ev.setdefault("end", r.now())
    logs = r.pull_logs()
    if not stopped:
        r.sleep_until(r.ev["end"] + lib.SAMPLER_TAIL, "sampler tail end+600 s")
    sampler.terminate()
    try:
        sampler.wait(timeout=15)
    except subprocess.TimeoutExpired:
        sampler.kill()
    samples = lib.load_samples(out / "samples.jsonl")
    v = lib.compute_verdict(
        scenario, r0=r0, samples=samples, events=r.ev, node_results=r.node_results, logs=logs
    )
    if stopped:
        v["fail"].append("abort ladder reached step 4: network left for the owner")
        v["verdict"] = v["final"] = "FAIL"
    nh = lib.handover_dir(Path(r.deploy) / "remote-reval-20261105", int(term["until"]))
    v["next_handover"] = dict(
        status="pending",
        boundary=int(term["until"]),
        boundary_utc=lib.utc(int(term["until"])),
        classify=str(nh / "CLASSIFY.json"),
    )
    v["run"] = run
    v["events"] = r.ev
    v["tos_ops_commit"] = os.environ.get("T3_COMMIT")
    (out / "verdict.json").write_text(json.dumps(v, indent=1, default=str) + "\n")
    names = sorted(p.name for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in names)
    )
    r.say(f"VERDICT {v['verdict']} (final: {v['final']}); {out}/verdict.json")
    return {"PASS": 0, "FAIL": 1}.get(v["verdict"], 2)


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--dry-run" and argv[1] in [*lib.SCENARIOS, "all"]:
        for s in lib.SCENARIOS if argv[1] == "all" else [argv[1]]:
            dry_run(s)
        return 0
    if len(argv) == 3 and argv[0] == "--execute" and argv[1] in lib.SCENARIOS:
        out = Path(os.environ.get("T3_EVIDENCE", "/datax/t3")) / argv[2]
        if not out.is_dir() or "build" in out.parts:
            print(f"STOP: evidence directory {out} missing or under build/")
            return 3
        return execute(argv[1], argv[2], out)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
