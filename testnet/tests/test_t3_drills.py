"""T3 drill scripts (testnet/drills/t3): verdicts, markers, dry run, partition commands and
the node script's refusals. Nothing here talks to a host; `on`, `put` and `addr` are fakes.
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
R0 = 2.44
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
OWN_WC0 = (
    "[ 3][t11][2026-11-10 03:40:03.747488918][pool.cpp:879][!valgroup(0,8000000000000000)"
    ".979.SimplexPool]\tconsensus: own signature: first skip vote signed in session "
    "B85ACB7C8C554B9E07EC1CA747C607D1C4DEA7A75A7983DB3296A68DE4F8F136 of "
    "(0,8000000000000000) catchain 979"
)
ADMITTED = (
    "[ 2][t13][2026-11-10 03:40:02.239384454][manager.cpp:4571][!manager]\tsigning ledger: "
    "session 69F70D6F6A430EACA47B16D5206764ECB2F4FF8F3A95C17DA3DFA38FAA044EB1 of "
    "(-1,8000000000000000) catchain 979: admitted"
)
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
OLD_TRUSTED = TRUSTED.replace("2026-11-10 03:40:02", "2026-11-10 03:20:00")
START = 1794282000  # 2026-11-10 03:40:00 UTC, the start the lines above follow


# ------------------------------------------------------------------ synthetic runs


def series(ports, a, b, rate, frozen=(), stall=None, halt=None, base=1000):
    """Samples every 2 s: seqno grows at `rate` except on frozen ports, during stall=(x, y)
    on every port, and during halt=(x, y) on every port."""
    rows = []
    for port in ports:
        seq, last, t = base, a, a
        while t <= b:
            dt = t - last
            last = t
            stopped = (stall and stall[0] <= t <= stall[1]) or (halt and halt[0] <= t <= halt[1])
            if port not in frozen and not stopped:
                seq += rate * dt
            rows.append(dict(t=t, port=port, seqno=int(seq), error=None))
            t += 2
    return rows


def good_events(**kw):
    ev = dict(
        t0=T0,
        outage_end=T0 + 300,
        end=T0 + 400,
        rates_during=[0.8 * R0, 0.8 * R0],
        rate_post=R0,
        deadlines={"node-4 rejoin <= 10 min after start": True},
        restarted=["node-4"],
        partition_confirmed=None,
    )
    ev.update(kw)
    return ev


def clean_logs():
    return {n: [] for n in lib.VALIDATORS}


def s1(samples=None, events=None, results=None, logs=None):
    return lib.compute_verdict(
        "S1",
        r0=R0,
        samples=samples if samples is not None else series(lib.ALL_PORTS, T0 - 120, T0 + 1000, 2.0),
        events=events or good_events(),
        node_results=results or {"node-4": {"result": "TRUSTED-RESIGNED"}},
        logs=logs if logs is not None else clean_logs(),
    )


def test_verdict_pass_with_next_handover_pending():
    v = s1()
    assert v["verdict"] == "PASS", v
    assert v["final"] == "pending-next-handover"
    assert v["next_handover"]["status"] == "pending"


def test_verdict_fail_on_a_stall_with_three_up():
    samples = series(lib.ALL_PORTS, T0 - 120, T0 + 1000, 2.0, stall=(T0 + 100, T0 + 140))
    v = s1(samples=samples)
    assert v["verdict"] == "FAIL", v
    assert any("stalled" in x for x in v["fail"]), v


def test_verdict_inconclusive_in_the_rate_band():
    v = s1(events=good_events(rates_during=[0.6 * R0]))
    assert v["verdict"] == "INCONCLUSIVE", v
    assert any("0.50-0.70" in x for x in v["inconclusive"])
    assert s1(events=good_events(rates_during=[0.4 * R0]))["verdict"] == "FAIL"


def test_verdict_fail_on_a_double_sign_allegation():
    logs = clean_logs()
    logs["node-2"] = [
        "[ 1][t 3][2026-11-10 03:41:00.0][misbehavior-reporter.cpp:145][!x]\tMISBEHAVIOR DETECTED"
        " kind=ConflictingVotes validator=AB adnl=CD session=EF allegation_bytes=10"
    ]
    v = s1(logs=logs)
    assert v["verdict"] == "FAIL", v
    assert any("double-sign" in x for x in v["fail"])
    logs["node-2"] = [logs["node-2"][0].replace("ConflictingVotes", "RejectedCandidate(V-020)")]
    assert s1(logs=logs)["verdict"] == "INCONCLUSIVE"


def test_verdict_fail_on_untrusted_restart_and_missing_deadline():
    assert s1(results={"node-4": {"result": "UNTRUSTED-FENCED"}})["verdict"] == "FAIL"
    ev = good_events(deadlines={"node-4 rejoin <= 10 min after start": False})
    assert s1(events=ev)["verdict"] == "FAIL"


def halt_run(scenario, samples, **kw):
    ev = dict(
        t0=T0,
        halt_from=T0 + 70,
        halt_to=T0 + 360,
        end=T0 + 900,
        rate_post=R0,
        deadlines={"new block <= 5 min after node-3 start": True},
        restarted=["node-3", "node-4"] if scenario == "S3" else [],
        partition_confirmed=True if scenario == "S4" else None,
    )
    ev.update(kw)
    res = {"node-3": {"result": "TRUSTED-RESIGNED"}, "node-4": {"result": "TRUSTED-RESIGNED"}}
    return lib.compute_verdict(
        scenario, r0=R0, samples=samples, events=ev, node_results=res, logs=clean_logs()
    )


def test_verdict_halt_pass_and_fail_on_blocks_during_a_two_down_halt():
    halted = series(lib.ALL_PORTS, T0 - 120, T0 + 1500, 2.0, halt=(T0 + 65, T0 + 365))
    assert halt_run("S3", halted)["verdict"] == "PASS"
    moving = series(lib.ALL_PORTS, T0 - 120, T0 + 1500, 2.0)
    v = halt_run("S3", moving)
    assert v["verdict"] == "FAIL", v
    assert any("only 2 of 4" in x for x in v["fail"])


def test_verdict_inconclusive_on_an_unconfirmed_partition():
    halted = series(lib.ALL_PORTS, T0 - 120, T0 + 1500, 2.0, halt=(T0 + 15, T0 + 365))
    assert halt_run("S4", halted)["verdict"] == "PASS"
    v = halt_run("S4", halted, partition_confirmed=False)
    assert v["verdict"] == "INCONCLUSIVE", v
    assert any("partition not confirmed" in x for x in v["inconclusive"])


def test_verdict_inconclusive_on_a_missing_sampler_window():
    samples = [
        s
        for s in series(lib.ALL_PORTS, T0 - 120, T0 + 1000, 2.0)
        if not T0 + 200 <= s["t"] <= T0 + 260
    ]
    assert s1(samples=samples)["verdict"] == "INCONCLUSIVE"


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
    conflict = TRUSTED.replace(
        "trusted, 4 sessions", "refusing a skip which conflicts with a decision already recorded"
    )
    assert node.classify([conflict])[0] == "unsafe"


class FakeHost:
    def __init__(self, monkeypatch, marker_lines, validator_active=False):
        self.calls = []
        self.state = {"tos-testnet-validator": validator_active, "tos-testnet-elections": False}
        monkeypatch.setattr(node, "run", self.run)
        monkeypatch.setattr(node, "active", lambda u: self.state[u])
        monkeypatch.setattr(node, "engine_running", lambda: self.state["tos-testnet-validator"])
        monkeypatch.setattr(node, "binding_now", lambda: (64770, 1723026))
        monkeypatch.setattr(node, "markers", lambda t0: list(marker_lines))
        monkeypatch.setattr(node, "WAIT_STEP", 0)
        monkeypatch.setattr(node.time, "sleep", lambda s: None)
        monkeypatch.setattr(
            node,
            "LEDGER",
            type("L", (), {"__truediv__": lambda s, o: s, "is_file": lambda s: True})(),
        )

    def run(self, args, timeout=150):
        self.calls.append(args)
        if args[:2] == ["systemctl", "start"]:
            for u in args[2:]:
                self.state[u] = True
        if args[:2] == ["systemctl", "stop"]:
            for u in args[2:]:
                self.state[u] = False
        return ""


def test_node_start_refuses_elections_on_an_untrusted_ledger(monkeypatch):
    host = FakeHost(monkeypatch, [UNTRUSTED])
    with pytest.raises(node.Refused) as e:
        node.do_start("node-3", (64770, 1723026))
    assert e.value.result == "UNTRUSTED-FENCED"
    assert ["systemctl", "start", "tos-testnet-elections"] not in host.calls
    assert host.state["tos-testnet-validator"] is True  # fenced, not stopped
    assert not any(c[:2] == ["systemctl", "stop"] for c in host.calls)


def test_node_start_happy_path_then_elections(monkeypatch):
    host = FakeHost(monkeypatch, [TRUSTED, OWN_MC])
    out = node.do_start("node-3", (64770, 1723026))
    assert out["result"] == "TRUSTED-RESIGNED"
    assert host.calls == [
        ["systemctl", "start", "tos-testnet-validator"],
        ["systemctl", "start", "tos-testnet-elections"],
    ]


def test_node_start_unsafe_stops_and_never_starts_elections(monkeypatch):
    host = FakeHost(monkeypatch, [TRUSTED, OWN_MC, FULL])
    with pytest.raises(node.Refused) as e:
        node.do_start("node-3", (64770, 1723026))
    assert e.value.result == "STOPPED-UNEXPECTED-LEDGER-STATE"
    assert ["systemctl", "start", "tos-testnet-elections"] not in host.calls


def test_node_start_refuses_a_replaced_ledger_and_a_running_engine(monkeypatch):
    FakeHost(monkeypatch, [TRUSTED, OWN_MC])
    with pytest.raises(node.Refused) as e:
        node.do_start("node-3", (64770, 1))
    assert e.value.result == "LEDGER-REPLACED"
    FakeHost(monkeypatch, [TRUSTED, OWN_MC], validator_active=True)
    with pytest.raises(node.Refused) as e:
        node.do_start("node-3", (64770, 1723026))
    assert e.value.result == "ALREADY-ACTIVE"


def test_node_script_never_touches_dht_or_deletes():
    text = (DRILL / "t3-node.py").read_text()
    code = "\n".join(x for x in text.splitlines() if not x.lstrip().startswith("#"))
    body = code.split('"""', 2)[2]
    assert "tos-testnet-dht" not in body and "dht-server" not in body
    for word in ("rmtree", "unlink", "rename", "os.replace", "os.remove", "'rm'", '"rm"', "mkdir"):
        assert word not in body, word


# ------------------------------------------------------------------ dry run


@pytest.fixture
def fake_deploy(tmp_path):
    """A deploy dir whose helpers record any on/put/addr call, and PATH shims that record any
    ssh/scp/nft/systemctl/systemd-run call."""
    calls = tmp_path / "calls"
    (tmp_path / "u76af").mkdir()
    (tmp_path / "helpers.sh").write_text(
        f'on() {{ echo "on $*" >> {calls}; }}\nput() {{ echo "put $*" >> {calls}; }}\n'
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
        assert "on node-4 'python3 /root/t3-node.py node-4 --stop'" in r.stdout or args[0] != "S1"
    assert not calls.exists(), calls.read_text()
    assert not (root / "evidence").exists()
    assert not (root / "u76af" / "upgrade.lock").exists()


def test_dry_run_prints_every_scenario_and_no_address(fake_deploy):
    env, calls, _ = fake_deploy
    out = dry(env, "all").stdout
    for s in lib.SCENARIOS:
        assert f"===== {s}:" in out and f"----- end of {s} -----" in out
    for token in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", out):
        with pytest.raises(ValueError):
            ipaddress.IPv4Address(token)
    assert not calls.exists()


def test_dry_run_refuses_unknown_arguments(fake_deploy):
    env, calls, _ = fake_deploy
    assert dry(env, "S9").returncode == 2
    assert dry(env, "S1", "--go").returncode == 2
    assert not calls.exists()


@pytest.mark.parametrize("scenario", ["S4", "S5"])
def test_every_partition_dry_run_arms_the_self_heal_and_heals(fake_deploy, scenario):
    env, _, _ = fake_deploy
    out = dry(env, scenario).stdout
    main, ladder = out.split("----- abort ladder", 1)
    for n in lib.VALIDATORS:
        arm = re.search(
            rf'on {n} "systemd-run --unit=t3-heal-\S+ --on-active=12min '
            rf"/usr/sbin/nft delete table inet t3part && nft -f -",
            main,
        )
        assert arm, n
        heal = f"on {n} 'nft delete table inet t3part 2>/dev/null; systemctl stop t3-heal-"
        assert heal in main and heal in ladder, n
        assert f"on {n} 'nft list table inet t3part'" in main


def test_partition_rule_parses_and_loads_in_an_isolated_namespace(tmp_path):
    cmd = lib.resolve(
        lib.partition_cmd("node-1", ("node-3", "node-4"), "t3-x-S4"), lambda n: "192.0.2." + n[-1]
    )
    assert subprocess.run(["bash", "-n", "-c", cmd]).returncode == 0
    with pytest.raises(ValueError):
        lib.resolve("$(addr node-2)", lambda n: "host.example")
    rule = cmd.split("<<'T3EOF'\n", 1)[1].rsplit("T3EOF", 1)[0]
    nft = shutil.which("nft") or "/usr/sbin/nft"
    probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
    if probe.returncode != 0 or not Path(nft).exists():
        pytest.skip("no unprivileged network namespace or nft")
    script = (
        f"{nft} -f - <<'EOF'\n{rule}EOF\n"
        f"{nft} list table inet t3part\n"
        f"{lib.heal_cmd('t3-x-S4').replace('nft ', nft + ' ')}\n"
    )
    r = subprocess.run(["unshare", "-rn", "bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert lib.partition_loaded(r.stdout)


# ------------------------------------------------------------------ gates and pre-flight


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


def test_gates_window_and_pending_verdict(tmp_path):
    since = 1794266287  # 2026-11-09 23:18:07
    term = dict(since=since, until=since + 7200, total=4)
    assert lib.gate_problems(term, "S1", tmp_path, since + 720) != []  # verdict missing
    write_handover(tmp_path, since)
    assert lib.gate_problems(term, "S1", tmp_path, since + 720) == []
    assert any("pending" in x for x in lib.gate_problems(term, "S1", tmp_path, since + 300))
    late = lib.gate_problems(term, "S1", tmp_path, since + 2400)
    assert any("term left" in x for x in late) and any("election opening" in x for x in late)
    assert any("term left" in x for x in lib.gate_problems(term, "S3", tmp_path, since + 1500))


def test_gate_refuses_a_failed_or_three_source_handover(tmp_path):
    since = 1794266287
    write_handover(tmp_path, since, rounds={"node-1": 2, "node-2": 2, "node-3": 2})
    assert any("sources" in x for x in lib.handover_problems(tmp_path, since))


GOOD_PRE = """== is-active
active
active
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
== udp
UNCONN 0 0 0.0.0.0:30001 0.0.0.0:*
== allegations
0
== end
"""


def test_host_precheck_parser():
    assert lib.pre_problems("S4", "node-3", GOOD_PRE) == []
    assert lib.ledger_binding(GOOD_PRE) == "64770:1723026"
    assert lib.pre_problems("S4", "node-1", GOOD_PRE) != []  # node-1 needs its DHT active
    assert lib.pre_problems("S1", "node-3", GOOD_PRE.replace("76af11250", "084e43158")) != []
    assert lib.pre_problems("S1", "node-3", GOOD_PRE.replace("ufw", "t3part")) != []
    assert lib.pre_problems("S2", "node-3", GOOD_PRE.replace("on-failure", "no")) != []
    v6 = GOOD_PRE.replace("0.0.0.0:30001 0.0.0.0:*", "[::]:30001 [::]:*")
    assert lib.pre_problems("S1", "node-3", v6) == [] and lib.pre_problems("S4", "node-3", v6)
    assert lib.pre_problems("S5", "node-3", GOOD_PRE.replace("/usr/sbin/nft\n", "")) != []


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
        ["bash", str(DRILL / "t3-preflight.sh"), "S9"],
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


@pytest.mark.parametrize("scenario", list(lib.SCENARIOS))
def test_execute_timeline_on_fake_hosts(tmp_path, monkeypatch, scenario):
    """The executing timeline with a fake clock, fake `on` and fake RPC: no host, no ssh."""
    run_mod = load("t3_run", "t3_run.py")
    clock = [T0 - 200]
    monkeypatch.setattr(run_mod, "head", lambda port: int(clock[0] * 2))
    r = run_mod.Runner(
        scenario,
        f"t3-20261110T0130Z-{scenario}",
        execute=True,
        out_dir=tmp_path,
        printer=lambda *_: None,
        clock=lambda: clock[0],
        sleep=lambda s: clock.__setitem__(0, clock[0] + max(s, 0.5)),
    )
    calls = []

    def on(node, cmd, why, timeout=600, stdin=None, quiet=False):
        calls.append((node, cmd))
        if "t3-node.py" in cmd:
            mode = cmd.split()[3]
            result = {"--stop": "STOPPED", "--kill": "RESTARTED-BY-SYSTEMD"}.get(
                mode, "TRUSTED-RESIGNED"
            )
            return 0, json.dumps(dict(result=result, t0=clock[0]))
        if cmd == lib.verify_cmd():
            return 0, "table inet t3part {\n ... drop;\n ... drop;\n}"
        if cmd == "nft list tables":
            return 0, "table inet ufw\n"
        return 0, ""

    monkeypatch.setattr(r, "on", on)
    monkeypatch.setattr(
        r, "local", lambda argv, why, out_name=None, timeout=120: (0, json.dumps(dict(rate=2.0)))
    )
    for n in lib.VALIDATORS:
        r.bindings[n] = "64770:1723026"
    r.t0 = clock[0]
    r.hard_abort = r.t0 + r.sc["abort"]
    r.ev["t0"] = r.t0
    r.body()
    assert all(v is True for v in r.ev["deadlines"].values()), r.ev
    assert r.ev["end"] - r.t0 < r.sc["abort"]
    if r.sc["partition"]:
        assert r.ev["partition_confirmed"] is True
        heals = [c for c in calls if c[1] == lib.heal_cmd(r.run)]
        assert {n for n, _ in heals} == set(lib.VALIDATORS)
    for n in r.sc["targets"]:
        assert any(n == x and "--start" in c for x, c in calls) or scenario == "S2"
    actions = [json.loads(x) for x in (tmp_path / "actions.jsonl").read_text().splitlines()]
    assert actions and all("utc" in a and "action" in a for a in actions)
