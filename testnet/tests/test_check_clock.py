"""The clock discipline checks: check-host-disk.py's readers, check-clock.py's verdict
and the refusal in enable-elections.sh.

The command outputs below are the formats ntpsec's `ntpq -pn`, chrony's
`chronyc -n sources` and `chronyc -n tracking` print.
"""

import importlib.util
import subprocess

import pytest
from conftest import SCRIPTS

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
CHRONY_SOURCES = """\
MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* 162.159.200.1                 3   6   377    35   -213us[ -245us] +/-   12ms
^- 185.125.190.57                2   6   377    34   +1350us[+1350us] +/-   63ms
"""
CHRONY_TRACKING = """\
Reference ID    : A29FC801 (162.159.200.1)
Stratum         : 4
System time     : 0.000183421 seconds slow of NTP time
Last offset     : -0.000021385 seconds
"""


class Commands:
    """A stand-in for subprocess.run: command name -> (returncode, stdout)."""

    def __init__(self, **answers):
        self.answers = answers

    def __call__(self, argv, **kwargs):
        answer = self.answers.get(argv[0])
        if answer is None:
            raise FileNotFoundError(argv[0])
        code, out = answer
        return subprocess.CompletedProcess(argv, code, out, "")


def test_ntpq_gives_the_selected_peer_and_its_offset():
    assert probe.parse_ntpq(NTPQ) == (1, -0.412)
    assert probe.parse_ntpq(NTPQ_NO_SOURCE) == (0, None)


def test_chrony_gives_the_selected_source_and_a_signed_offset():
    assert probe.parse_chrony_sources(CHRONY_SOURCES) == 1
    assert probe.parse_chrony_tracking(CHRONY_TRACKING) == -0.183
    fast = CHRONY_TRACKING.replace("slow", "fast")
    assert probe.parse_chrony_tracking(fast) == 0.183
    assert probe.parse_chrony_tracking("Stratum : 4\n") is None


def test_clock_facts_prefer_ntpsec_and_fall_back_to_chrony():
    ntpsec = Commands(timedatectl=(0, "yes\n"), ntpq=(0, NTPQ))
    assert probe.clock_facts(ntpsec) == {
        "clock_synced": True,
        "clock_daemon": "ntpd",
        "clock_sources": 1,
        "clock_offset_ms": -0.412,
    }
    chrony = Commands(
        timedatectl=(0, "yes\n"), chronyc=(0, CHRONY_SOURCES + "\n" + CHRONY_TRACKING)
    )
    facts = probe.clock_facts(chrony)
    assert facts["clock_daemon"] == "chrony" and facts["clock_sources"] == 1
    none = Commands(timedatectl=(0, "no\n"))
    assert probe.clock_facts(none) == {
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
        ({"clock_daemon": None}, "no ntpsec (ntpd) or chrony"),
        ({"clock_daemon": "timesyncd"}, "no ntpsec (ntpd) or chrony"),
        ({"clock_sources": 0}, "no selected NTP source"),
        ({"clock_offset_ms": None}, "could not be read"),
        ({"clock_offset_ms": 100.01}, "+100.0 ms from NTP time, beyond 100 ms"),
        ({"clock_offset_ms": -250.0}, "-250.0 ms"),
    ],
)
def test_each_lapse_of_discipline_is_named(changes, problem):
    problems = probe.clock_problems(dict(GOOD, **changes))
    assert any(problem in p for p in problems), problems


def test_a_disciplined_clock_has_no_problem():
    assert probe.clock_problems(GOOD) == []
    assert probe.clock_problems(dict(GOOD, clock_offset_ms=-100.0)) == []


def test_check_clock_prints_the_expected_line_and_exit_status(capsys):
    assert check_clock.main([], facts=GOOD) == 0
    out = capsys.readouterr().out
    assert out == (
        "clock ok: ntpd with 1 selected source, offset +0.400 ms (limit 100 ms), "
        "NTPSynchronized=yes\n"
    )
    assert check_clock.main(["--quiet"], facts=GOOD) == 0
    assert capsys.readouterr().out == ""
    assert check_clock.main([], facts=dict(GOOD, clock_sources=0)) == 1
    assert capsys.readouterr().out.startswith("clock NOT OK: ntpd has no selected NTP source")
    assert check_clock.main(["--max-offset-ms", "0.1"], facts=GOOD) == 1


def test_check_clock_reports_json():
    import json

    def run(argv):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = check_clock.main(argv, facts=dict(GOOD, clock_synced=False))
        return code, json.loads(buffer.getvalue())

    code, report = run(["--json"])
    assert code == 1 and report["ok"] is False and report["clock_daemon"] == "ntpd"


def test_the_clock_limit_follows_consensus_timing():
    # A third of the 300 ms minimum block interval (gen-zerostate.fif ConfigParam 30).
    assert probe.MAX_CLOCK_OFFSET_MS == 100.0


def test_enable_elections_refuses_an_undisciplined_clock():
    text = (SCRIPTS / "enable-elections.sh").read_text()
    check = text.index('python3 "$HERE/check-clock.py"')
    # Before anything is configured or started.
    assert check < text.index("tosctl config elections stake-policy")
    assert check < text.index("systemctl restart")
    assert "|| die" in text[check : text.index("\n", check) + 200]
