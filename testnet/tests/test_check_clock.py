"""The clock discipline checks: check-host-disk.py's readers, check-clock.py's verdict
and the refusal in enable-elections.sh.

The command outputs below are the formats ntpsec's `ntpq -pn` and
`ntpq -c "rv 0 offset"` print. Offsets are local clock minus NTP time
(positive = local clock ahead); ntpd's system `offset` is the opposite sign.
"""

import contextlib
import importlib.util
import io
import json
import subprocess

import pytest
from testnet_support import SCRIPTS

spec = importlib.util.spec_from_file_location(
    "check_host_disk_clock", SCRIPTS / "check-host-disk.py"
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
spec = importlib.util.spec_from_file_location("check_clock", SCRIPTS / "check-clock.py")
check_clock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_clock)

NTPQ = """\
     remote           refid      st t when poll reach   delay   offset   jitter
=======================================================================================================
 0.ubuntu.pool.n .POOL.          16 p    -  256    0   0.0000   0.0000   0.0001
*133.243.238.164 .NICT.           1 u   36   64  377   1.6920  -0.4120   0.1550
+185.125.190.56  79.243.60.50     2 u   33   64  377 214.1340   1.2180   0.3110
"""
NTPQ_NO_SOURCE = NTPQ.replace("*133", " 133")
# A selected peer whose last sample jitters far off while the disciplined system
# offset is small: the system offset is the one that counts.
NTPQ_JITTERY = NTPQ.replace("  -0.4120   0.1550", " 250.4120  95.1550")


class Commands:
    """A stand-in for subprocess.run: `ntpq -pn`, `ntpq -c "rv 0 offset"` and
    `timedatectl`, each answered by (returncode, stdout) or missing."""

    def __init__(self, synced="yes\n", peers=NTPQ, system="offset=0.412\n"):
        self.synced, self.peers, self.system = synced, peers, system

    def __call__(self, argv, **kwargs):
        if argv[0] == "timedatectl":
            out = self.synced
        elif argv[:2] == ["ntpq", "-pn"]:
            out = self.peers
        elif argv[:2] == ["ntpq", "-c"]:
            out = self.system
        else:
            out = None
        if out is None:
            raise FileNotFoundError(argv[0])
        return subprocess.CompletedProcess(argv, 0, out, "")


def test_ntpq_gives_the_selected_peers():
    assert probe.parse_ntpq_peers(NTPQ) == 1
    assert probe.parse_ntpq_peers(NTPQ_NO_SOURCE) == 0


@pytest.mark.parametrize(
    "text, offset",
    [
        # ntpd's offset is NTP time minus the local clock: turned to local minus NTP.
        ("offset=0.412\n", -0.412),
        ("offset=-12.5\n", 12.5),
        ("offset=1.5e-03\n", -0.002),
        ("offset=0.000\n", 0.0),
        ("associd=0 status=0615 leap_none\n", None),
    ],
)
def test_the_system_offset_is_local_minus_ntp(text, offset):
    assert probe.parse_ntpq_system_offset(text) == offset


def test_clock_facts_read_the_system_offset_not_a_peer_sample():
    assert probe.clock_facts(Commands()) == {
        "clock_synced": True,
        "clock_daemon": "ntpd",
        "clock_sources": 1,
        "clock_offset_ms": -0.412,
    }
    jittery = probe.clock_facts(Commands(peers=NTPQ_JITTERY, system="offset=-0.7\n"))
    assert jittery["clock_offset_ms"] == 0.7
    assert probe.clock_problems(jittery) == []


def test_without_ntpd_there_is_no_discipline():
    facts = probe.clock_facts(Commands(synced="no\n", peers=None, system=None))
    assert facts == {
        "clock_synced": False,
        "clock_daemon": None,
        "clock_sources": None,
        "clock_offset_ms": None,
    }


GOOD = {"clock_synced": True, "clock_daemon": "ntpd", "clock_sources": 1, "clock_offset_ms": 0.4}


@pytest.mark.parametrize(
    "changes, problem",
    [
        ({"clock_synced": False}, "NTPSynchronized"),
        ({"clock_synced": None}, "NTPSynchronized"),
        ({"clock_daemon": None}, "ntpsec's ntpd does not answer"),
        ({"clock_daemon": "chrony"}, "ntpsec's ntpd does not answer"),
        ({"clock_sources": 0}, "no selected NTP source"),
        ({"clock_offset_ms": None}, "could not be read"),
        ({"clock_offset_ms": 100.01}, "100.0 ms ahead of NTP time, beyond 100 ms"),
        ({"clock_offset_ms": -250.0}, "250.0 ms behind NTP time"),
    ],
)
def test_each_lapse_of_discipline_is_named(changes, problem):
    problems = probe.clock_problems(dict(GOOD, **changes))
    assert any(problem in p for p in problems), problems


def test_a_disciplined_clock_has_no_problem():
    assert probe.clock_problems(GOOD) == []
    assert probe.clock_problems(dict(GOOD, clock_offset_ms=-100.0)) == []


def run_check(argv, facts=GOOD, uptime=lambda: 86400.0):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = check_clock.main(argv, facts=facts, uptime=uptime)
    return code, buffer.getvalue()


def test_check_clock_prints_the_expected_line_and_exit_status():
    assert run_check([]) == (
        0,
        "clock ok: ntpd with 1 selected source, offset +0.400 ms (local minus NTP, limit "
        "100 ms), NTPSynchronized=yes\n",
    )
    assert run_check(["--quiet"]) == (0, "")
    code, out = run_check([], facts=dict(GOOD, clock_sources=0))
    assert code == 1 and out.startswith("clock NOT OK: ntpd has no selected NTP source")
    assert run_check(["--max-offset-ms", "0.1"])[0] == 1


def test_check_clock_reports_json():
    code, out = run_check(["--json"], facts=dict(GOOD, clock_synced=False))
    report = json.loads(out)
    assert code == 1 and report["ok"] is False and report["clock_daemon"] == "ntpd"


def test_the_boot_grace_passes_only_shortly_after_a_boot():
    bad = dict(GOOD, clock_sources=0)
    code, out = run_check(["--boot-grace", "900"], facts=bad, uptime=lambda: 120.0)
    assert code == 0 and out.startswith("clock check skipped: up 120 s")
    assert run_check(["--boot-grace", "900", "--quiet"], facts=bad, uptime=lambda: 120.0) == (0, "")
    assert run_check(["--boot-grace", "900"], facts=bad, uptime=lambda: 901.0)[0] == 1
    # Without the option a fresh boot is judged like any other moment.
    assert run_check([], facts=bad, uptime=lambda: 120.0)[0] == 1


def test_the_clock_limit_follows_consensus_timing():
    # A third of the 300 ms minimum block interval (gen-zerostate.fif ConfigParam 30).
    assert probe.MAX_CLOCK_OFFSET_MS == 100.0
    assert probe.CLOCK_DAEMONS == ("ntpd",)


def test_enable_elections_refuses_an_undisciplined_clock():
    text = (SCRIPTS / "enable-elections.sh").read_text()
    check = text.index('python3 "$HERE/check-clock.py"')
    # Before anything is configured or started.
    assert check < text.index("tosctl config elections stake-policy")
    assert check < text.index("systemctl restart")
    assert "|| die" in text[check : text.index("\n", check) + 200]
