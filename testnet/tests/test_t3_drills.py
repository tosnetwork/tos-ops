"""T3 drill scripts (testnet/drills/t3, plan v2): verdicts, markers, gates, timers, partition
commands, the node script's refusals and quarantine, the dry run and the executing timelines
on fake hosts. Nothing here talks to a host; `on`, `put`, `get` and `addr` are fakes.
Mutation controls: t3_drill_mutants.py."""

import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

DRILL = Path(os.environ.get("T3_DRILL_DIR") or Path(__file__).resolve().parents[1] / "drills/t3")


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, DRILL / file)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


lib = load("t3_lib", "t3_lib.py")
node = load("t3_node", "t3-node.py")

T0 = 1794270000.0
R0 = 2.4
# Log lines in the shape the epoch-6 restart script expects (from its recorded results).
TRUSTED = (
    "[ 3][t 5][2026-11-10 03:40:02.546846646][signing-ledger.cpp:1013][!SigningLedger]\t"
    "signing ledger /var/lib/tos/validator/consensus/signing-ledger: trusted, 4 sessions"
)
OWN_MC = (
    "[ 3][t12][2026-11-10 03:40:03.472453844][pool.cpp:879][!valgroup(-1,8000000000000000)"
    ".979.SimplexPool]\tconsensus: own signature: first skip vote signed in session "
    "69F70D6F6A430EACA47B16D5206764ECB2F4FF8F3A95C17DA3DFA38FAA044EB1 of "
    "(-1,8000000000000000) catchain 979"
)
OWN_WC0 = OWN_MC.replace("(-1,8000000000000000)", "(0,8000000000000000)")
ADMITTED = (
    "[ 2][t13][2026-11-10 03:40:02.239384454][manager.cpp:4571][!manager]\tsigning ledger: "
    "session 69F70D6F6A430EACA47B16D5206764ECB2F4FF8F3A95C17DA3DFA38FAA044EB1 of "
    "(-1,8000000000000000) catchain 979: admitted"
)
FENCED = ADMITTED.replace(": admitted", ": fenced (unknown history)")
UNTRUSTED = (
    "[ 1][t 5][2026-11-10 03:40:02.100000000][signing-ledger.cpp:989][!SigningLedger]\t"
    "signing ledger /var/lib/tos/validator/consensus/signing-ledger: the signing ledger "
    "directory is not the one it was created as: it was copied, restored or recreated; a "
    "pending ledger for unknown history replaces it at the first admission"
)
FULL = (
    "[ 1][t 7][2026-11-10 03:40:05.000000000][signing-ledger.cpp:647][!SigningLedger]\t"
    "signing decision log 69F70D6F of (-1,8000000000000000) is full at 1048576 records"
)
CONFLICT = TRUSTED.replace(
    "trusted, 4 sessions", "refusing a skip which conflicts with a decision already recorded"
)
VID = ["%064x" % (i + 1) for i in range(4)]
ADNL = ["%064x" % (i + 0xA0) for i in range(4)]
ALLEGATION = (
    "[ 1][t 3][2026-11-10 03:41:00.0][misbehavior-reporter.cpp:145][!x]\tMISBEHAVIOR DETECTED"
    f" kind=ConflictingVotes validator={VID[2].upper()} adnl=CD session=EF allegation_bytes=10"
)
OLD_TRUSTED = TRUSTED.replace("2026-11-10 03:40:02", "2026-11-10 03:20:00")
START = 1794282000  # 2026-11-10 03:40:00 UTC, the start the lines above follow
RUN3 = "t3-20261110T0330Z-S3"


# ------------------------------------------------------------------ synthetic runs


def series(ports, a, b, rate, frozen=(), stall=None, halt=None, base=1000):
    """Samples every 2 s: seqno grows at rate(t) (or a constant) except on frozen ports and
    during stall/halt=(x, y); last_block_utime is the time of the last growth."""
    rate_at = rate if callable(rate) else (lambda t: rate)
    rows = []
    for port in ports:
        seq, last, t, utime = base, a, a, a
        while t <= b:
            dt, last = t - last, t
            stopped = (stall and stall[0] <= t <= stall[1]) or (halt and halt[0] <= t <= halt[1])
            if port not in frozen and not stopped:
                seq += rate_at(t) * dt
                utime = t
            rows.append(dict(t=t, port=port, seqno=int(seq), last_block_utime=utime, error=None))
            t += 2
    return rows


def good_events(**kw):
    ev = dict(
        t0=T0,
        r0_from=T0 - 115,
        r0_to=T0,
        outage_from=T0 + 30,
        outage_to=T0 + 300,
        end=T0 + 400,
        post_from=T0 + 400,
        deadlines={"node-4 rejoin <= 10 min after start": True},
        restarted=["node-4"],
    )
    ev.update(kw)
    return ev


def clean_logs(**extra):
    logs = {n: [] for n in lib.VALIDATORS}
    logs["node-4"] = [ADMITTED]
    logs["node-3"] = [ADMITTED]
    logs.update(extra)
    return logs


def one_down(t):
    return 0.8 * R0 if T0 <= t <= T0 + 300 else R0


def s1(samples=None, events=None, results=None, logs=None):
    if samples is None:
        samples = series(lib.ALL_PORTS, T0 - 120, T0 + 1000, one_down)
    return lib.compute_verdict(
        "S1",
        samples=samples,
        events=events or good_events(),
        node_results=results or {"node-4": {"result": "TRUSTED-RESIGNED"}},
        logs=logs if logs is not None else clean_logs(),
    )


def test_verdict_pass_with_scope_and_next_handover_pending():
    v = s1()
    assert v["verdict"] == "PASS", v
    assert v["final"] == "pending-next-handover" and v["next_handover"]["status"] == "pending"
    assert "does not authenticate the fault interval" in v["scope"]
    assert 0.75 < v["checks"]["outage_rate_ratio"] < 0.85


def test_verdict_fail_on_a_stall_with_three_up():
    samples = series(lib.ALL_PORTS, T0 - 120, T0 + 1000, one_down, stall=(T0 + 100, T0 + 140))
    v = s1(samples=samples)
    assert v["verdict"] == "FAIL", v
    assert any("stalled" in x for x in v["fail"]), v


def test_verdict_rate_band_from_fresh_samples():
    band = series(
        lib.ALL_PORTS, T0 - 120, T0 + 1000, lambda t: 0.6 * R0 if T0 <= t <= T0 + 300 else R0
    )
    v = s1(samples=band)
    assert v["verdict"] == "INCONCLUSIVE", v
    assert any("0.50-0.70" in x for x in v["inconclusive"])
    low = series(
        lib.ALL_PORTS, T0 - 120, T0 + 1000, lambda t: 0.4 * R0 if T0 <= t <= T0 + 300 else R0
    )
    assert s1(samples=low)["verdict"] == "FAIL"


def test_four_frozen_heads_are_not_progress():
    frozen = series(lib.ALL_PORTS, T0 - 120, T0 + 1000, R0, frozen=lib.ALL_PORTS)
    assert lib.interval_rate(frozen, lib.RATE_PORTS, T0 + 30, T0 + 300) is None
    assert s1(samples=frozen)["verdict"] != "PASS"
    stale = [
        dict(r, last_block_utime=r["t"] - 120)
        for r in series(lib.ALL_PORTS, T0 - 120, T0 + 1000, R0)
    ]
    assert lib.interval_rate(stale, lib.RATE_PORTS, T0 + 30, T0 + 300) is None


def test_verdict_safety_fail_on_a_double_sign_allegation():
    v = s1(logs=clean_logs(**{"node-2": [ALLEGATION]}))
    assert v["verdict"] == "SAFETY_FAIL", v
    assert any("double-sign" in x for x in v["safety"])
    assert s1(logs=clean_logs(**{"node-2": [CONFLICT]}))["verdict"] == "SAFETY_FAIL"
    benign = ALLEGATION.replace("ConflictingVotes", "RejectedCandidate(V-020)")
    assert s1(logs=clean_logs(**{"node-2": [benign]}))["verdict"] == "INCONCLUSIVE"


def test_verdict_fail_on_untrusted_restart_fenced_session_and_missing_deadline():
    assert s1(results={"node-4": {"result": "UNTRUSTED-FENCED"}})["verdict"] == "FAIL"
    assert s1(logs=clean_logs(**{"node-4": [FENCED]}))["verdict"] == "FAIL"
    assert s1(logs=clean_logs(**{"node-4": []}))["verdict"] == "INCONCLUSIVE"
    ev = good_events(deadlines={"node-4 rejoin <= 10 min after start": False})
    assert s1(events=ev)["verdict"] == "FAIL"


def halt_run(scenario, samples, **kw):
    ev = dict(
        t0=T0,
        r0_from=T0 - 115,
        r0_to=T0,
        halt_from=T0 + 60,
        halt_to=T0 + 360,
        settle=30.0,
        end=T0 + 600,
        post_from=T0 + 600,
        deadlines={"new block <= 5 min after node-3 start": True},
        restarted=["node-3", "node-4"] if scenario == "S3" else [],
    )
    if scenario == "S4":
        ev.update(
            partition_confirmed=True,
            partition_counters={
                n: {x: {"in": 9, "out": 9} for x in lib.S4_SIDES[n]} for n in lib.VALIDATORS
            },
        )
    ev.update(kw)
    res = {"node-3": {"result": "TRUSTED-RESIGNED"}, "node-4": {"result": "TRUSTED-RESIGNED"}}
    return lib.compute_verdict(
        scenario, samples=samples, events=ev, node_results=res, logs=clean_logs()
    )


def test_halt_progress_within_settling_is_recorded_after_settling_fails():
    drained = series(lib.ALL_PORTS, T0 - 120, T0 + 1500, R0, halt=(T0 + 80, T0 + 370))
    v = halt_run("S3", drained)
    assert v["verdict"] == "PASS", v
    assert v["checks"]["settling_18081_advance"] > 0
    late = series(lib.ALL_PORTS, T0 - 120, T0 + 1500, R0, halt=(T0 + 80, T0 + 300))
    v = halt_run("S3", late)
    assert v["verdict"] == "FAIL", v
    assert any("after settling" in x for x in v["fail"])


def test_verdict_inconclusive_on_an_unconfirmed_or_uncounted_partition():
    halted = series(lib.ALL_PORTS, T0 - 120, T0 + 1500, R0, halt=(T0 + 70, T0 + 370))
    assert halt_run("S4", halted)["verdict"] == "PASS"
    v = halt_run("S4", halted, partition_confirmed=False)
    assert v["verdict"] == "INCONCLUSIVE", v
    assert any("partition not confirmed" in x for x in v["inconclusive"])
    zero = {n: {x: {"in": 9, "out": 9} for x in lib.S4_SIDES[n]} for n in lib.VALIDATORS}
    zero["node-2"]["node-3"]["in"] = 0
    v = halt_run("S4", halted, partition_counters=zero)
    assert v["verdict"] == "INCONCLUSIVE" and any("INCOMPLETE" in x for x in v["inconclusive"])


def test_verdict_inconclusive_on_a_missing_sampler_window():
    samples = [
        s
        for s in series(lib.ALL_PORTS, T0 - 120, T0 + 1000, one_down)
        if not T0 + 200 <= s["t"] <= T0 + 260
    ]
    assert s1(samples=samples)["verdict"] == "INCONCLUSIVE"


def test_s2_never_claims_a_torn_tail():
    ev = dict(
        t0=T0,
        r0_from=T0 - 115,
        r0_to=T0,
        outage_from=T0,
        outage_to=T0 + 60,
        end=T0 + 60,
        post_from=T0 + 60,
        deadlines={},
        restarted=["node-3"],
    )
    v = lib.compute_verdict(
        "S2",
        samples=series(lib.ALL_PORTS, T0 - 120, T0 + 1000, R0),
        events=ev,
        node_results={"node-3": {"result": "TRUSTED-RESIGNED"}},
        logs=clean_logs(),
    )
    assert v["verdict"] == "PASS", v
    assert v["checks"]["torn_tail_exercised"].startswith("unobservable")


# ------------------------------------------------------------------ markers


def test_marker_parser_accepts_trusted_plus_own_masterchain_signature():
    lines = node.lines_since("\n".join([OLD_TRUSTED, ADMITTED, TRUSTED, OWN_WC0, OWN_MC]), START)
    assert OLD_TRUSTED not in lines
    state, sig = node.classify(lines)
    assert state == "resigned" and sig == [OWN_MC]


def test_marker_parser_waits_without_a_masterchain_signature_or_fresh_trusted_line():
    assert node.classify(node.lines_since("\n".join([TRUSTED, OWN_WC0]), START))[0] == "waiting"
    assert node.classify(node.lines_since("\n".join([OLD_TRUSTED, OWN_MC]), START))[0] == "waiting"


def test_marker_parser_refuses_untrusted_and_unsafe():
    assert node.classify([UNTRUSTED, OWN_MC])[0] == "untrusted"
    assert node.classify([TRUSTED, OWN_MC, FULL])[0] == "unsafe"
    assert node.classify([CONFLICT])[0] == "unsafe"


class FakeHost:
    def __init__(self, monkeypatch, tmp_path, marker_lines, validator_active=False, timer_ok=True):
        self.calls = []
        self.state = {"tos-testnet-validator": validator_active, "tos-testnet-elections": False}
        self.timer_ok = timer_ok
        monkeypatch.setattr(node, "run", self.run)
        monkeypatch.setattr(node, "quiet", lambda args: self.run(args) and 0)
        monkeypatch.setattr(node, "active", self.active)
        monkeypatch.setattr(node, "engine_running", lambda: self.state["tos-testnet-validator"])
        monkeypatch.setattr(node, "binding_now", lambda: (64770, 1723026))
        monkeypatch.setattr(node, "markers", lambda t0: list(marker_lines))
        monkeypatch.setattr(node, "ledger_listing", lambda: {"entries": []})
        monkeypatch.setattr(node, "WAIT_STEP", 0)
        monkeypatch.setattr(node.time, "sleep", lambda s: None)
        monkeypatch.setattr(node.time, "monotonic", lambda: 1000.0)
        monkeypatch.setattr(node, "QUARANTINE", str(tmp_path / "t3-quarantine-"))
        monkeypatch.setattr(
            node,
            "LEDGER",
            type("L", (), {"__truediv__": lambda s, o: s, "is_file": lambda s: True})(),
        )

    def active(self, unit):
        if unit.endswith(".timer"):
            return self.timer_ok
        return bool(self.state.get(unit))

    def run(self, args, timeout=150):
        self.calls.append(args)
        if args[:2] == ["systemctl", "start"]:
            for u in args[2:]:
                self.state[u] = True
        if args[:2] == ["systemctl", "stop"]:
            for u in args[2:]:
                self.state[u] = False
        if args[:2] == ["systemctl", "show"]:
            if args[3] == "NextElapseUSecMonotonic":
                return "28min 20s"  # 1700 s monotonic: fires 700 s after 1000
            if args[3] == "ExecStart":
                return "{ path=/usr/bin/systemctl ; " + node.RESTORE_ARGV + " ; }"
            return "1"
        return ""


def test_node_await_refuses_elections_on_an_untrusted_ledger(monkeypatch, tmp_path):
    host = FakeHost(monkeypatch, tmp_path, [UNTRUSTED])
    e = node.do_start_engine("node-3", (64770, 1723026))
    with pytest.raises(node.Refused) as r:
        node.do_await("node-3", e["t0"], (64770, 1723026), RUN3, True)
    assert r.value.result == "UNTRUSTED-FENCED"
    assert ["systemctl", "start", "tos-testnet-elections"] not in host.calls
    assert host.state["tos-testnet-validator"] is True  # fenced, not stopped


def test_node_start_engine_never_waits_and_await_starts_elections(monkeypatch, tmp_path):
    host = FakeHost(monkeypatch, tmp_path, [TRUSTED, OWN_MC])
    e = node.do_start_engine("node-3", (64770, 1723026))
    assert e["result"] == "ENGINE-STARTED"
    assert host.calls == [["systemctl", "start", "tos-testnet-validator"]]
    out = node.do_await("node-3", e["t0"], (64770, 1723026), RUN3, True)
    assert out["result"] == "TRUSTED-RESIGNED"
    assert host.calls[1] == ["systemctl", "start", "tos-testnet-elections"]
    assert ["systemctl", "stop", f"t3-restore-{RUN3}.timer"] in host.calls


def test_node_unsafe_marker_quarantines_the_host(monkeypatch, tmp_path):
    host = FakeHost(monkeypatch, tmp_path, [TRUSTED, OWN_MC, CONFLICT], validator_active=True)
    with pytest.raises(node.Refused) as r:
        node.do_await("node-3", START, (64770, 1723026), RUN3, True)
    assert r.value.result == "SAFETY-QUARANTINED"
    assert ["systemctl", "start", "tos-testnet-elections"] not in host.calls
    units = ["systemctl", "stop", "tos-testnet-elections", "tos-testnet-validator"]
    timer = ["systemctl", "stop", f"t3-restore-{RUN3}.timer"]
    assert host.calls.index(timer) < host.calls.index(units)
    assert (tmp_path / f"t3-quarantine-{RUN3}").exists()


def test_a_quarantine_marker_blocks_every_start(monkeypatch, tmp_path):
    host = FakeHost(monkeypatch, tmp_path, [TRUSTED, OWN_MC])
    (tmp_path / f"t3-quarantine-{RUN3}").write_text("{}")
    monkeypatch.setattr(node.os, "geteuid", lambda: 0)
    for mode in (["--start-engine"], ["--start"], ["--await-signing", str(START)]):
        rc = node.main(
            ["node-3", *mode, "--run", "t3-20261110T0530Z-S4", "--binding", "64770:1723026"]
        )
        assert rc == 6, mode
    assert host.calls == []


def test_node_stop_arms_and_verifies_the_restore_timer_first(monkeypatch, tmp_path):
    host = FakeHost(monkeypatch, tmp_path, [], validator_active=True)
    out = node.do_stop("node-4", RUN3, 700)
    assert out["result"] == "STOPPED" and out["restore_timer"]["left"] == 700
    arm = host.calls.index(
        [
            "systemd-run",
            f"--unit=t3-restore-{RUN3}",
            "--on-active=700s",
            "/usr/bin/systemctl",
            "start",
            "tos-testnet-validator",
        ]
    )
    units = ["systemctl", "stop", "tos-testnet-elections", "tos-testnet-validator"]
    assert arm < host.calls.index(units)
    host = FakeHost(monkeypatch, tmp_path, [], validator_active=True, timer_ok=False)
    with pytest.raises(node.Refused) as r:
        node.do_stop("node-4", RUN3, 700)
    assert r.value.result == "RESTORE-TIMER-NOT-VERIFIED"
    assert units not in host.calls


def test_node_refuses_a_replaced_ledger_a_running_engine_and_bad_usage(monkeypatch, tmp_path):
    FakeHost(monkeypatch, tmp_path, [TRUSTED, OWN_MC])
    with pytest.raises(node.Refused) as r:
        node.do_start_engine("node-3", (64770, 1))
    assert r.value.result == "LEDGER-REPLACED"
    FakeHost(monkeypatch, tmp_path, [TRUSTED, OWN_MC], validator_active=True)
    with pytest.raises(node.Refused) as r:
        node.do_start_engine("node-3", (64770, 1723026))
    assert r.value.result == "ALREADY-ACTIVE"
    with pytest.raises(node.Refused):
        node.parse(["node-3", "--start", "--run", "bad"])
    with pytest.raises(node.Refused):
        node.parse(["node-3", "--kill", "--run", RUN3, "--restore-after", "60"])


def test_node_script_never_touches_dht_or_deletes():
    text = (DRILL / "t3-node.py").read_text()
    code = "\n".join(x for x in text.splitlines() if not x.lstrip().startswith("#"))
    body = code.split('"""', 2)[2]
    assert "tos-testnet-dht" not in body and "dht-server" not in body
    for word in ("rmtree", "unlink", "rename", "os.replace", "os.remove", "'rm'", '"rm"', "mkdir"):
        assert word not in body, word


def test_systemd_timespans():
    assert node.timespan("1d 4h 13min 50.843801s") == pytest.approx(101630.843801)
    assert lib.timespan("12min") == 720
    with pytest.raises(ValueError):
        lib.timespan("n/a")


# ------------------------------------------------------------------ dry run


@pytest.fixture
def fake_deploy(tmp_path):
    """A deploy dir whose helpers record any on/put/get/addr call, and PATH shims that
    record any ssh/scp/nft/systemctl/systemd-run/flock/curl call."""
    calls = tmp_path / "calls"
    (tmp_path / "u76af").mkdir()
    (tmp_path / "helpers.sh").write_text(
        f'on() {{ echo "on $*" >> {calls}; }}\nput() {{ echo "put $*" >> {calls}; }}\n'
        f'get() {{ echo "get $*" >> {calls}; }}\n'
        f'addr() {{ echo "addr $*" >> {calls}; echo 192.0.2.9; }}\nE={tmp_path}\n'
        "VALIDATORS='node-1 node-2 node-3 node-4'\n"
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("ssh", "scp", "nft", "systemctl", "systemd-run", "flock", "curl"):
        shim = bin_dir / tool
        shim.write_text(f'#!/bin/sh\necho "{tool} $*" >> {calls}\n')
        shim.chmod(0o755)
    env = dict(
        os.environ,
        T3_DEPLOY=str(tmp_path),
        T3_EVIDENCE=str(tmp_path / "evidence"),
        PATH=f"{bin_dir}:{os.environ['PATH']}",
    )
    return env, calls, tmp_path


def dry(env, *args):
    return subprocess.run(
        ["bash", str(DRILL / "t3-run.sh"), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def test_dry_run_is_the_default_and_executes_nothing(fake_deploy):
    env, calls, root = fake_deploy
    for args in (["S1"], ["S2", "--dry-run"], ["all"]):
        r = dry(env, *args)
        assert r.returncode == 0, r.stderr
        assert "DRY RUN" in r.stdout and "nothing below is executed" in r.stdout
    assert "on node-4 'python3 /root/t3-node.py node-4 --stop --run" in dry(env, "S1").stdout
    assert not calls.exists(), calls.read_text()
    assert not (root / "evidence").exists()
    assert not (root / "u76af" / "upgrade.lock").exists()


def test_dry_run_prints_every_scenario_and_no_address(fake_deploy):
    env, calls, _ = fake_deploy
    out = dry(env, "all").stdout
    for s in lib.SCENARIOS:
        assert f"===== {s}:" in out and f"----- end of {s} -----" in out
    assert "S5" not in out
    for token in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", out):
        with pytest.raises(ValueError):
            ipaddress.IPv4Address(token)
    assert not calls.exists()


def test_dry_run_refuses_unknown_arguments(fake_deploy):
    env, calls, _ = fake_deploy
    assert dry(env, "S5").returncode == 2
    assert dry(env, "S1", "--go").returncode == 2
    assert not calls.exists()


def test_execute_refuses_an_open_quarantine(fake_deploy):
    env, calls, root = fake_deploy
    q = root / "evidence" / RUN3
    q.mkdir(parents=True)
    (q / "QUARANTINE-node-2").write_text("{}")
    r = dry(env, "S4", "--execute")
    assert r.returncode == 3 and "open quarantine" in r.stdout, r.stdout + r.stderr
    assert not calls.exists()
    (q / "CLEARED-node-2").write_text("cleared")
    assert lib.open_quarantines(root / "evidence") == []


def test_partition_dry_run_arms_and_verifies_the_self_heal_before_any_rule(fake_deploy):
    env, _, _ = fake_deploy
    out = dry(env, "S4").stdout
    main, ladder = out.split("----- availability abort ladder", 1)
    ladder, safety = ladder.split("----- safety abort", 1)
    first_load = main.index("nft -f - <<'T3EOF'")
    for n in lib.VALIDATORS:
        assert main.index(f"on {n} 'systemd-run --unit=t3-heal-") < first_load, n
        heal = f"on {n} 'nft delete table inet t3part 2>/dev/null; systemctl stop t3-heal-"
        assert heal in main and heal in ladder and heal in safety, n
    assert main.index("CHECK each host: timer active") < first_load
    assert "counter drop comment" in main and "read the drop counters" in main


def test_s3_dry_run_arms_restore_timers_and_always_starts_both(fake_deploy):
    env, _, _ = fake_deploy
    main = dry(env, "S3").stdout.split("----- availability abort ladder", 1)[0]
    for n in ("node-4", "node-3"):
        assert re.search(rf"on {n} 'python3 /root/t3-node.py {n} --stop --restore-after \d+ ", main)
        engine = main.index(f"on {n} 'python3 /root/t3-node.py {n} --start-engine")
        assert engine < main.index(f"on {n} 'python3 /root/t3-node.py {n} --await-signing")
    assert "--start " not in main


def test_partition_rule_parses_loads_counts_and_heals_in_an_isolated_namespace():
    sides = lib.S4_SIDES["node-1"]
    cmd = lib.resolve(
        lib.load_cmd("node-1", sides, True),
        lambda n: "192.0.2." + n[-1],
        lambda n: ["2001:db8::" + n[-1]] if n == "node-3" else [],
    )
    assert subprocess.run(["bash", "-n", "-c", cmd]).returncode == 0
    assert "2001:db8::3" in cmd and "2001:db8::4" not in cmd
    with pytest.raises(ValueError):
        lib.resolve("$(addr node-2)", lambda n: "host.example")
    nft = shutil.which("nft") or "/usr/sbin/nft"
    probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
    if probe.returncode != 0 or not Path(nft).exists():
        pytest.skip("no unprivileged network namespace or nft")
    script = (
        cmd.replace("nft ", nft + " ")
        + f"\n{nft} list table inet t3part\n"
        + lib.heal_cmd("t3-x-S4").replace("nft ", nft + " ")
    )
    r = subprocess.run(["unshare", "-rn", "bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert lib.partition_loaded(r.stdout, sides)
    c = lib.counters(r.stdout)
    assert set(c) == set(sides) and all(v == {"in": 0, "out": 0} for v in c.values())


# ------------------------------------------------------------------ gates, timers, inventory


def write_handover(root, boundary, **over):
    d = lib.handover_dir(root, boundary)
    d.mkdir(parents=True)
    c = dict(
        verify="PASS",
        failures=0,
        final_agree=True,
        alert=[],
        boundary=boundary,
        certificates=800,
        rounds={n: 2 for n in lib.VALIDATORS},
    )
    c.update(over)
    (d / "CLASSIFY.json").write_text(json.dumps(c))
    (d / "RESULT.txt").write_text(f"boundary={boundary} sources=18081,38081,28081,48084\n")


def test_window_gate_needs_the_full_abort_budget_before_the_recovery_deadline():
    since = 1794266287  # 2026-11-09 23:18:07
    term = dict(since=since, until=since + 7200, total=4)
    assert lib.window_problems(term, "S1", since + 720) == []
    assert any("pending" in x for x in lib.window_problems(term, "S1", since + 300))
    late = since + 7200 - 3600 - 780 - 1200 - 120 + 30  # 30 s past the latest S1 start
    assert any("recovery deadline" in x for x in lib.window_problems(term, "S1", late))
    assert lib.window_problems(term, "S1", late - 60) == []
    assert lib.window_problems(term, "S3", since + 720) == []
    assert any(
        "recovery deadline" in x
        for x in lib.window_problems(term, "S3", since + 7200 - 3600 - 780 - 1500)
    )


def test_handover_gate_refuses_a_failed_or_three_source_handover(tmp_path):
    since = 1794266287
    write_handover(tmp_path, since, rounds={"node-1": 2, "node-2": 2, "node-3": 2})
    assert any("sources" in x for x in lib.handover_problems(tmp_path, since))
    assert lib.handover_problems(tmp_path, since + 7200) != []


def test_set_election_heads_and_clock_gates():
    good = dict(total=4, main=4, validators=[{"weight": lib.EQUAL_WEIGHT}] * 4)
    assert lib.set_problems(good) == []
    assert lib.set_problems(dict(good, validators=[{"weight": 1}] * 4)) != []
    absent = {"error": {"message": "CONFIG_PARAM_ABSENT"}}
    idle = {"result": {"exit_code": 0, "stack": [["num", "0x0"]]}}
    assert lib.election_problems(absent, idle) == []
    assert lib.election_problems({"result": {}}, idle) != []
    assert lib.election_problems(absent, {"result": {"exit_code": 0, "stack": [["num", "0x5"]]}})
    a = {p: dict(seqno=10, utime=100, t=101) for p in lib.ALL_PORTS}
    b = {p: dict(seqno=12, utime=105, t=106) for p in lib.ALL_PORTS}
    assert lib.heads_problems(a, b) == []
    assert lib.heads_problems(a, a) != []  # frozen
    assert lib.heads_problems(a, {p: dict(v, utime=10) for p, v in b.items()}) != []  # stale
    assert lib.clock_problems({"node-1": lib.clock_offset(100.0, 100.3, 100.2)}) == []
    assert lib.clock_problems({"node-1": lib.clock_offset(100.0, 101.5, 100.2)}) != []
    assert lib.settle_seconds({"node-1": (0.2, 0.1)}) == 31


def report(left=720.0, argv=None, rc="0", timer="active"):
    mono = 5000.0
    return (
        f"armed_rc={rc}\nnft_x=0\ntimer={timer}\nnext={(mono + left) / 60:.6f}min\n"
        f"mono={mono}\nexec={{ path=/usr/sbin/nft ; {argv or lib.HEAL_ARGV} ; }}\n"
    )


def test_self_heal_timer_verification():
    assert lib.timer_problems(report(), lib.HEAL_ARGV, 720) == []
    assert lib.timer_problems(report(rc="1"), lib.HEAL_ARGV, 720) != []
    assert lib.timer_problems(report(timer="inactive"), lib.HEAL_ARGV, 720) != []
    assert lib.timer_problems(report(left=7200), lib.HEAL_ARGV, 720) != []
    assert lib.timer_problems(report(argv="argv[]=/bin/true"), lib.HEAL_ARGV, 720) != []


GOOD_PRE = """== units
tos-testnet-validator rc=0
tos-testnet-elections rc=0
== version
validator-engine build information: [ Commit: 76af11250aab1d4243159f5953605d8626fa32d3 ]
== restart
Restart=on-failure
RestartUSec=10s
== ledger
64770 1723026
-rw------- 1 tos tos 100 Nov 10 00:00 ledger
== tools
/usr/sbin/nft
/usr/bin/systemd-run
== tables
table inet ufw
== t3-units
== udp
UNCONN 0 0 198.51.100.7:30001 0.0.0.0:*
== sockets
udp UNCONN 0 0 198.51.100.7:30001 0.0.0.0:* users:(("validator-engi",pid=9,fd=40))
udp ESTAB 0 0 198.51.100.7:31001 203.0.113.5:31001 users:(("validator-engi",pid=9,fd=41))
== v6
2: eth0    inet6 2001:db8::7/64 scope global
== config
adnlid %s
listen engine.addr v4 30001
== custody
== allegations
0
== end
""" % ADNL[2]


def test_host_precheck_parser_and_redaction():
    assert lib.pre_problems("S4", "node-3", GOOD_PRE) == []
    assert lib.ledger_binding(GOOD_PRE) == "64770:1723026"
    assert lib.pre_problems("S4", "node-1", GOOD_PRE) != []  # node-1 needs its DHT rc
    assert lib.pre_problems("S1", "node-3", GOOD_PRE.replace("elections rc=0", "elections rc=3"))
    assert lib.pre_problems("S1", "node-3", GOOD_PRE.replace("76af11250", "084e43158")) != []
    assert lib.pre_problems("S1", "node-3", GOOD_PRE.replace("ufw", "t3part")) != []
    assert lib.pre_problems("S2", "node-3", GOOD_PRE.replace("on-failure", "no")) != []
    assert lib.pre_problems("S4", "node-3", GOOD_PRE.replace("/usr/sbin/nft\n", "")) != []
    leftover = GOOD_PRE.replace("== t3-units\n", "== t3-units\nt3-heal-x.timer loaded\n")
    assert lib.pre_problems("S1", "node-3", leftover) != []
    red = lib.redact_pre(GOOD_PRE)
    for a in ("198.51.100.7", "203.0.113.5", "2001:db8::7"):
        assert a not in red
    assert "global IPv6 addresses: 1" in red and lib.ledger_binding(red) == "64770:1723026"
    rows = [json.loads(x) for x in lib.sections(red)["sockets"]]
    assert {r["peer"] for r in rows} == {"v4any", "v4"} and not lib.needs_v6(rows)
    assert lib.needs_v6([dict(local="any", peer="v4")])


def test_identities_and_implicated_hosts():
    term = dict(validators=[dict(id=VID[i], adnl=ADNL[i]) for i in range(4)])
    texts = {n: GOOD_PRE.replace(ADNL[2], ADNL[i]) for i, n in enumerate(lib.VALIDATORS)}
    ids = lib.identities(texts, term)
    assert ids["node-3"]["validator"] == VID[2]
    ev = lib.safety_events("node-1", [ALLEGATION]) + lib.safety_events("node-2", [CONFLICT])
    assert lib.implicated_hosts(ev, ids) == (["node-2", "node-3"], [])
    assert lib.implicated_hosts(lib.safety_events("node-1", [ALLEGATION]), {}) == ([], [VID[2]])


def test_pins_refuse_a_changed_script(tmp_path):
    (tmp_path / "a.sh").write_text("x")
    pins = tmp_path / "pins"
    pins.write_text(
        "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881  DEPLOY/a.sh\n"
    )
    assert lib.pin_problems(pins, tmp_path) == []
    (tmp_path / "a.sh").write_text("y")
    assert lib.pin_problems(pins, tmp_path) != []


def test_sampler_is_bounded_and_records_errors(tmp_path):
    sample = load("t3_sample", "t3-sample.py")
    clock = [100.0]

    def call(port, method):
        if port == 2:
            raise OSError("refused")
        return (
            {"last": {"seqno": 7}}
            if method == "getMasterchainInfo"
            else {"consensus_block": 7, "last_block_utime": 99}
        )

    def sleep(s):
        clock[0] += max(s, 0.05)

    out = tmp_path / "s.jsonl"
    assert sample.main(["--out", str(out), "--duration", "4000"], call, sleep) == 2
    assert (
        sample.main(
            ["--out", str(out), "--duration", "6", "--port", "1", "--port", "2"],
            call,
            sleep,
            lambda: clock[0],
        )
        == 0
    )
    rows = [json.loads(x) for x in out.read_text().splitlines()]
    data = [r for r in rows if "port" in r]
    assert rows[-1]["reason"] == "duration" and 6 <= len(data) <= 8
    assert all(r["seqno"] == 7 for r in data if r["port"] == 1)
    assert all(r["seqno"] is None and "refused" in r["error"] for r in data if r["port"] == 2)


def test_preflight_fails_closed_on_changed_pins(fake_deploy):
    env, calls, _ = fake_deploy
    env = dict(env, RUN="t3-20261109T2330Z-S1")
    r = subprocess.run(
        ["bash", str(DRILL / "t3-preflight.sh"), "S1"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert r.returncode == 3 and "STOP: pinned" in r.stdout, r.stdout + r.stderr
    assert not calls.exists()
    r = subprocess.run(
        ["bash", str(DRILL / "t3-preflight.sh"), "S5"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert r.returncode == 2


def test_drill_shell_scripts_parse_and_pass_shellcheck():
    scripts = sorted(DRILL.glob("*.sh"))
    assert {p.name for p in scripts} >= {"t3-run.sh", "t3-preflight.sh", "t3-host-check.sh"}
    for p in scripts:
        assert subprocess.run(["bash", "-n", str(p)]).returncode == 0, p
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck is not installed")
    r = subprocess.run(["shellcheck", "-x", *map(str, scripts)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-2000:]


# ------------------------------------------------------------------ execute path, all fake


class FakeNet:
    """Fake `on`, clock and RPC for the executing timelines."""

    def __init__(
        self,
        monkeypatch,
        tmp_path,
        scenario,
        await_result=None,
        engine_result=None,
        arm_fail=(),
        load_fail=(),
        logs=None,
    ):
        self.run_mod = load("t3_run", "t3_run.py")
        self.clock = [T0 - 200]
        self.calls = []
        self.await_result = await_result or {}
        self.engine_result = engine_result or {}
        self.arm_fail, self.load_fail = set(arm_fail), set(load_fail)
        self.logs = logs or {}
        monkeypatch.setattr(self.run_mod, "head", lambda port: int(self.clock[0] * 2))
        monkeypatch.setattr(self.run_mod, "block_hash", lambda port, seq: f"h{seq}")
        r = self.run_mod.Runner(
            scenario,
            f"t3-20261110T0130Z-{scenario}",
            execute=True,
            out_dir=tmp_path,
            printer=lambda *_: None,
            clock=lambda: self.clock[0],
            sleep=lambda s: self.clock.__setitem__(0, self.clock[0] + max(s, 0.5)),
        )
        monkeypatch.setattr(r, "on", self.on)
        monkeypatch.setattr(
            r,
            "helper",
            lambda fn, *a, timeout=300: self.calls.append(("local", f"{fn} {' '.join(a)}")) or 0,
        )
        for n in lib.VALIDATORS:
            r.bindings[n] = "64770:1723026"
        r.ids = {n: dict(validator=VID[i]) for i, n in enumerate(lib.VALIDATORS)}
        r.t0 = self.clock[0]
        r.hard_abort = r.t0 + r.sc["abort"]
        r.ev["t0"] = r.t0
        self.r = r

    def on(self, node, cmd, why, timeout=600, stdin=None, quiet=False):
        self.calls.append((node, cmd))
        if "t3-node.py" in cmd:
            mode = cmd.split()[3]
            result = {
                "--stop": "STOPPED",
                "--kill": "RESTARTED-BY-SYSTEMD",
                "--start-engine": self.engine_result.get(node, "ENGINE-STARTED"),
                "--await-signing": self.await_result.get(node, "TRUSTED-RESIGNED"),
                "--quarantine": "QUARANTINED",
            }.get(mode, "TRUSTED-RESIGNED")
            return 0, json.dumps(dict(result=result, t0=self.clock[0]))
        if cmd.startswith("systemd-run --unit=t3-heal-"):
            return 0, report(argv=lib.HEAL_ARGV, rc="1" if node in self.arm_fail else "0")
        if cmd.startswith("nft -f -"):
            return (1, "") if node in self.load_fail else (0, "")
        if cmd == lib.verify_cmd():
            drops = lib.S4_SIDES[node]
            body = "\n".join(
                f"  chain {c} {{\n"
                + "\n".join(
                    f'    ip saddr 192.0.2.1 counter packets 7 bytes 9 drop comment "{x}"'
                    for x in drops
                )
                + "\n  }"
                for c in ("i", "o")
            )
            return 0, "table inet t3part {\n" + body + "\n}\n"
        if cmd == "nft list tables":
            return 0, "table inet ufw\n"
        if cmd == lib.log_cmd():
            return 0, "\n".join(self.logs.get(node, []))
        if cmd.startswith("systemctl is-active"):
            return 0, "active\n"
        return 0, ""

    def hosts(self, needle):
        return [n for n, c in self.calls if needle in c]


@pytest.mark.parametrize("scenario", list(lib.SCENARIOS))
def test_execute_timeline_on_fake_hosts(tmp_path, monkeypatch, scenario):
    net = FakeNet(monkeypatch, tmp_path, scenario)
    r = net.r
    r.body()
    assert all(v is True for v in r.ev["deadlines"].values()), r.ev
    assert r.ev["end"] - r.t0 < r.sc["abort"]
    if r.sc["partition"]:
        assert r.ev["partition_confirmed"] is True
        assert set(net.hosts(lib.heal_cmd(r.run))) == set(lib.VALIDATORS)
        assert set(r.ev["partition_counters"]) == set(lib.VALIDATORS)
    for n in r.sc["targets"]:
        if scenario == "S2":
            assert n in net.hosts("--kill") and n in net.hosts("--after-kill")
        else:
            assert n in net.hosts("--start-engine") and n in net.hosts("--await-signing")
    actions = [json.loads(x) for x in (tmp_path / "actions.jsonl").read_text().splitlines()]
    assert actions and all("utc" in a and "action" in a for a in actions)


@pytest.mark.parametrize("fail", ["arm", "load"])
def test_partial_partition_install_heals_every_host(tmp_path, monkeypatch, fail):
    kw = {"arm_fail": ["node-3"]} if fail == "arm" else {"load_fail": ["node-2"]}
    net = FakeNet(monkeypatch, tmp_path, "S4", **kw)
    assert net.r.apply_partition() is False
    assert set(net.hosts(lib.heal_cmd(net.r.run))) == set(lib.VALIDATORS)
    if fail == "arm":
        assert net.hosts("nft -f -") == []  # no rule loaded anywhere


@pytest.mark.parametrize(
    "node3",
    [
        {"await_result": {"node-3": "UNTRUSTED-FENCED"}},
        {"await_result": {"node-3": "INCONCLUSIVE-NO-TRUSTED-RESIGN"}},
        {"engine_result": {"node-3": "COMMAND-FAILED"}},
    ],
)
def test_s3_node4_start_is_never_skipped(tmp_path, monkeypatch, node3):
    net = FakeNet(monkeypatch, tmp_path, "S3", **node3)
    net.r.ev["halt_to"] = net.clock[0]
    net.r.restore_both()
    assert "node-4" in net.hosts("--start-engine") and "node-4" in net.hosts("--await-signing")


def test_safety_abort_quarantines_the_implicated_host_and_restores_nothing(tmp_path, monkeypatch):
    net = FakeNet(monkeypatch, tmp_path, "S4", logs={"node-2": [CONFLICT]})
    net.r.t0 = START - 10
    with pytest.raises(net.run_mod.SafetyAbort) as e:
        net.r.safety_check("test")
    net.r.safety_abort(e.value.events)
    assert net.hosts("--quarantine") == ["node-2"]
    assert set(net.hosts(lib.heal_cmd(net.r.run))) == set(lib.VALIDATORS)
    assert net.hosts("--start-engine") == [] and net.hosts("is-active") == []
    assert (tmp_path / "QUARANTINE-node-2").exists()
    assert any("get node-2 /var/log/tos/validator/node.log*" in c for _, c in net.calls)


def test_safety_abort_with_an_unresolved_identity_quarantines_nobody(tmp_path, monkeypatch):
    net = FakeNet(monkeypatch, tmp_path, "S1", logs={"node-1": [ALLEGATION]})
    net.r.ids = {}
    net.r.t0 = START - 10
    with pytest.raises(net.run_mod.SafetyAbort) as e:
        net.r.safety_check("test")
    net.r.safety_abort(e.value.events)
    assert net.hosts("--quarantine") == [] and net.hosts("--start-engine") == []
    assert net.r.ev["safety_unresolved"] == [VID[2]]


def gate_runner(monkeypatch, tmp_path, stage, cp36=None, host_text=None, skew=0.0):
    net = FakeNet(monkeypatch, tmp_path, "S4")
    r, mod = net.r, net.run_mod
    since = int(net.clock[0]) - 1200
    term = dict(
        since=since,
        until=since + 7200,
        total=4,
        main=4,
        validators=[dict(id=VID[i], adnl=ADNL[i], weight=lib.EQUAL_WEIGHT) for i in range(4)],
    )
    (tmp_path / "term.json").write_text(json.dumps(term))
    r.handovers = tmp_path / "handovers"
    write_handover(r.handovers, since)
    absent = {"error": {"message": "CONFIG_PARAM_ABSENT"}}
    idle = {"result": {"exit_code": 0, "stack": [["num", "0x0"]]}}
    monkeypatch.setattr(
        mod,
        "rpc_raw",
        lambda port, rpc_method, timeout=10, /, **p: (
            (cp36 or absent) if rpc_method == "getConfigParam" else idle
        ),
    )
    monkeypatch.setattr(
        mod,
        "head_fact",
        lambda port: dict(seqno=int(net.clock[0] * 2), utime=int(net.clock[0]), t=net.clock[0]),
    )
    base_on = net.on

    def on(node, cmd, why, timeout=600, stdin=None, quiet=False):
        if stdin == "t3-host-check.sh":
            text = host_text or GOOD_PRE.replace(ADNL[2], ADNL[int(node[-1]) - 1])
            if node == "node-1":
                text = text.replace("elections rc=0\n", "elections rc=0\ntos-testnet-dht rc=0\n")
            return 0, text
        if cmd == "date +%s.%N":
            return 0, f"{net.clock[0] + skew:.6f}\n"
        if cmd.startswith("systemctl is-active --quiet"):
            return 0, "\n".join(f"{u} rc=0" for u in lib.units_of(node)) + "\n"
        if cmd.startswith("ip -6"):
            return 0, "2: eth0    inet6 2001:db8::7/64 scope global\n"
        return base_on(node, cmd, why, timeout, stdin, quiet)

    monkeypatch.setattr(r, "on", on)
    return r, mod


def test_gates_are_recorded_assertions(tmp_path, monkeypatch):
    r, mod = gate_runner(monkeypatch, tmp_path, "pre")
    r.gates("pre")
    g = json.loads((tmp_path / "gates-pre.json").read_text())
    assert g and all(x["ok"] for x in g), g
    names = " ".join(x["name"] for x in g)
    for want in ("window", "handover", "weights", "ConfigParam 36", "heads", "host facts", "clock"):
        assert want in names, want
    assert json.loads((tmp_path / "identities.json").read_text())["node-3"]["validator"] == VID[2]
    assert "2001:db8::7" not in (tmp_path / "pre-node-3.txt").read_text()
    r.gates("t0")
    assert r.v6["node-3"] == ["2001:db8::7"]
    assert "2001:db8::7" not in "".join(p.read_text() for p in tmp_path.glob("*.json"))


@pytest.mark.parametrize("bad", ["cp36", "unit", "skew"])
def test_a_failed_gate_stops_before_any_fault(tmp_path, monkeypatch, bad):
    kw = {"cp36": {"result": {"config": {}}}} if bad == "cp36" else {}
    if bad == "unit":
        kw["host_text"] = GOOD_PRE.replace("validator rc=0", "validator rc=3")
    if bad == "skew":
        kw["skew"] = 2.0
    r, mod = gate_runner(monkeypatch, tmp_path, "pre", **kw)
    with pytest.raises(mod.GateStop):
        r.gates("pre")
    g = json.loads((tmp_path / "gates-pre.json").read_text())
    assert any(not x["ok"] for x in g)


def test_rejoin_needs_progress_and_one_hash_at_the_common_height(tmp_path, monkeypatch):
    net = FakeNet(monkeypatch, tmp_path, "S4")
    base = int(net.clock[0] * 2) - 3
    assert net.r.rejoin(lib.ALL_PORTS, base)() is True
    assert net.r.rejoin(lib.ALL_PORTS, int(net.clock[0] * 2) + 10)() is False  # no progress
    monkeypatch.setattr(net.run_mod, "block_hash", lambda port, seq: f"h{seq}-{port}")
    assert net.r.rejoin(lib.ALL_PORTS, base)() is False  # diverged hashes
