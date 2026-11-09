"""T3 drill logic shared by t3-run.sh, t3-preflight.sh and the tests (standard library only).

Pure functions: the scenario table, the time-window gates, the handover verdict check, the
host pre-check parser, the partition and heal commands, the log classification and the
verdict of the public-testnet T3 plan (sections 4, 5 and 5.1). Nothing here talks to a
host. Command-line use, for the shell scripts:

  python3 t3_lib.py classify-ok CLASSIFY.json BOUNDARY
  python3 t3_lib.py gate TERM.json SCENARIO HANDOVER_ROOT [--lead SECONDS]
  python3 t3_lib.py check-pre SCENARIO NODE PRE-NODE.txt
  python3 t3_lib.py pins-ok PINS DEPLOY
"""

from __future__ import annotations

import datetime
import json
import re
import sys
import time
from pathlib import Path

VALIDATORS = ("node-1", "node-2", "node-3", "node-4")
# Observation tunnels on the coordinator, each to its host's loopback JSON-RPC.
PORT = {"node-1": 18081, "node-2": 38081, "node-3": 28081, "node-4": 48084}
ALL_PORTS = tuple(PORT.values())
# The rejoin check's two reference ports per restarted node (validator-step-now.sh).
REJOIN_PEERS = {
    "node-1": (38081, 28081),
    "node-2": (18081, 28081),
    "node-3": (18081, 38081),
    "node-4": (18081, 28081),
}
RATE_PORTS = (18081, 38081)
SAMPLER_LEAD = 120
SAMPLER_TAIL = 600
SELF_HEAL = "12min"
TABLE = "t3part"

S4_SIDES = {
    "node-1": ("node-3", "node-4"),
    "node-2": ("node-3", "node-4"),
    "node-3": ("node-1", "node-2"),
    "node-4": ("node-1", "node-2"),
}
S5_SIDES = {
    "node-4": ("node-1", "node-2", "node-3"),
    "node-1": ("node-4",),
    "node-2": ("node-4",),
    "node-3": ("node-4",),
}

# kind: "continue" (3 of 4 sign: the chain must go on) or "halt" (2 of 4: it must stop).
SCENARIOS = {
    "S1": dict(
        kind="continue",
        budget=900,
        abort=1200,
        mute=["node-4"],
        mute_min=20,
        targets=["node-4"],
        live=list(RATE_PORTS),
        frozen=[],
        partition=None,
        title="clean stop, 1 down",
    ),
    "S2": dict(
        kind="continue",
        budget=900,
        abort=1200,
        mute=["node-3"],
        mute_min=20,
        targets=["node-3"],
        live=list(RATE_PORTS),
        frozen=[],
        partition=None,
        title="unclean kill, 1 down",
    ),
    "S3": dict(
        kind="halt",
        budget=1500,
        abort=1500,
        mute=[],
        mute_min=25,
        targets=["node-4", "node-3"],
        live=list(RATE_PORTS),
        frozen=[],
        partition=None,
        title="2 down: halt, then resume",
    ),
    "S4": dict(
        kind="halt",
        budget=1500,
        abort=1500,
        mute=[],
        mute_min=25,
        targets=[],
        live=list(ALL_PORTS),
        frozen=[],
        partition=S4_SIDES,
        title="2-2 partition, then heal",
    ),
    "S5": dict(
        kind="continue",
        budget=900,
        abort=1200,
        mute=["node-4"],
        mute_min=20,
        targets=[],
        live=list(RATE_PORTS),
        frozen=[48084],
        partition=S5_SIDES,
        title="1-3 partition (optional)",
    ),
}

DOUBLE_SIGN_KINDS = {
    "ConflictingVotes",
    "ConflictingCandidateAndCertificate",
    "ConflictingCandidates(V-019)",
}
LOG_GREP = (
    "signing ledger|signing decision log|consensus: own signature|MISBEHAVIOR|conflicts with"
    "|fence|torn|is full|untrusted|unknown history"
)
STAMP = re.compile(r"\[(20\d\d-\d\d-\d\d \d\d:\d\d:\d\d)")
ADDR_REF = re.compile(r"\$\(addr (node-[1-4])\)")


# ------------------------------------------------------------------ time and gates


def utc(t: float) -> str:
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def handover_dir(root: Path | str, boundary: int) -> Path:
    d = datetime.datetime.fromtimestamp(boundary, datetime.timezone.utc)
    return Path(root) / f"handover-{d:%Y%m%d}-{d:%H}18"


def classify_problems(c: dict, result_txt: str | None, boundary: int | None) -> list[str]:
    """Why a handover CLASSIFY.json is not a PASS (empty list: PASS)."""
    p = []
    if c.get("verify") != "PASS":
        p.append(f"verify {c.get('verify')!r}")
    if c.get("failures") != 0:
        p.append(f"failures {c.get('failures')!r}")
    if c.get("final_agree") is not True:
        p.append("final_agree is not true")
    if c.get("alert"):
        p.append(f"alert {c.get('alert')!r}")
    if sorted(c.get("rounds") or {}) != list(VALIDATORS):
        p.append(f"sources {sorted(c.get('rounds') or {})}")
    if not (isinstance(c.get("certificates"), int) and c["certificates"] > 0):
        p.append("no certificates")
    if boundary is not None and c.get("boundary") != boundary:
        p.append(f"boundary {c.get('boundary')} != {boundary}")
    if result_txt is None or "sources=18081,38081,28081,48084" not in result_txt:
        p.append("RESULT.txt missing or not four sources 18081,38081,28081,48084")
    return p


def handover_problems(root: Path | str, boundary: int) -> list[str]:
    d = handover_dir(root, boundary)
    try:
        c = json.loads((d / "CLASSIFY.json").read_text())
    except (OSError, ValueError) as e:
        return [f"{d.name}/CLASSIFY.json unreadable or pending: {e.__class__.__name__}"]
    try:
        result = (d / "RESULT.txt").read_text()
    except OSError:
        result = None
    return [f"{d.name}: {x}" for x in classify_problems(c, result, boundary)]


def gate_problems(
    term: dict, scenario: str, handover_root, now: float, lead: int = SAMPLER_LEAD
) -> list[str]:
    """The term, election and handover-window gates (plan 2.7, 1.4; remote-lane window rule)."""
    s = SCENARIOS[scenario]
    p = []
    since, until = int(term["since"]), int(term["until"])
    if term.get("total") != 4:
        p.append(f"validator set total {term.get('total')} != 4")
    if not since <= now < until:
        p.append("now is outside the current term")
    need = 3600 + s["budget"] + 780
    if until - now < need:
        p.append(f"term left {until - now:.0f}s < {need}s")
    abort_end = now + lead + s["abort"]
    if abort_end > until - 3600:
        p.append(
            f"hard abort {utc(abort_end)} would reach the election opening {utc(until - 3600)}"
        )
    quiet_stop = until - 367  # odd-hour :12:00, the next handover's collection
    if abort_end > quiet_stop:
        p.append(
            f"hard abort {utc(abort_end)} would cross the next handover window {utc(quiet_stop)}"
        )
    if now < since + 540:
        p.append(f"the {utc(since)} handover verdict is still pending (until {utc(since + 540)})")
    p += handover_problems(handover_root, since)
    return p


# ------------------------------------------------------------------ host pre-check


def sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("== "):
            cur = line[3:].strip()
            out[cur] = []
        elif cur is not None:
            out[cur].append(line)
    return out


def pre_problems(scenario: str, node: str, text: str, revision: str = "76af11250") -> list[str]:
    """Refusals from one host's t3-host-check.sh output (plan section 4)."""
    sec = sections(text)
    p = []
    want = ["active", "active"] + (["active"] if node == "node-1" else [])
    if [x.strip() for x in sec.get("is-active", [])] != want:
        p.append(f"units not all active: {sec.get('is-active')}")
    if not any(revision in x for x in sec.get("version", [])):
        p.append(f"host is not on {revision}")
    restart = {k: v for k, _, v in (x.partition("=") for x in sec.get("restart", []))}
    if restart.get("Restart") != "on-failure" or restart.get("RestartUSec") not in ("10s", "10"):
        p.append(f"validator unit restart policy {restart} (S2 needs on-failure, 10s)")
    if not re.fullmatch(r"\d+ \d+", (sec.get("ledger") or [""])[0].strip()):
        p.append("ledger binding not read")
    if any(TABLE in x for x in sec.get("tables", [])):
        p.append("a partition table is already present")
    if SCENARIOS[scenario]["partition"]:
        tools = [x.strip() for x in sec.get("tools", [])]
        if not any(x.endswith("/nft") for x in tools) or not any(
            x.endswith("/systemd-run") for x in tools
        ):
            p.append(f"nft or systemd-run missing ({tools}): partition scenarios are INCONCLUSIVE")
        if "/usr/sbin/nft" not in tools:
            p.append("nft is not /usr/sbin/nft, which the self-heal timer calls")
        udp = sec.get("udp", [])
        if not udp:
            p.append("no ADNL/QUIC listener seen")
        if any("[" in x or "*:" in x for x in udp):
            p.append("an ADNL/QUIC socket listens on IPv6: an IPv4 partition would leak")
    if not re.fullmatch(r"\d+", (sec.get("allegations") or [""])[0].strip()):
        p.append("allegation baseline not counted")
    return p


def ledger_binding(text: str) -> str:
    dev, ino = (sections(text).get("ledger") or [""])[0].split()
    return f"{int(dev)}:{int(ino)}"


# ------------------------------------------------------------------ host commands


def node_cmd(node: str, mode: str, *extra: str) -> str:
    return " ".join(["python3", "/root/t3-node.py", node, mode, *extra])


def partition_cmd(node: str, drops, run: str) -> str:
    """The section-5 nft rule, with the self-heal armed first. Addresses are `$(addr X)`
    references, resolved in memory only when the command is executed."""
    for x in drops:
        assert x in VALIDATORS and x != node, (node, drops)
    s = ", ".join(f"$(addr {x})" for x in drops)
    return (
        f"systemd-run --unit=t3-heal-{run} --on-active={SELF_HEAL} "
        f"/usr/sbin/nft delete table inet {TABLE} && nft -f - <<'T3EOF'\n"
        f"table inet {TABLE} {{\n"
        f"  chain i {{ type filter hook input priority -50; ip saddr {{ {s} }} drop; }}\n"
        f"  chain o {{ type filter hook output priority -50; ip daddr {{ {s} }} drop; }}\n"
        f"}}\nT3EOF"
    )


def heal_cmd(run: str) -> str:
    """Idempotent: exits 0 only when the table is gone."""
    return (
        f"nft delete table inet {TABLE} 2>/dev/null; systemctl stop t3-heal-{run}.timer 2>/dev/null; "
        f"! nft list table inet {TABLE} >/dev/null 2>&1"
    )


def verify_cmd() -> str:
    return f"nft list table inet {TABLE}"


def partition_loaded(output: str) -> bool:
    return f"table inet {TABLE}" in output and output.count("drop") >= 2


def log_cmd() -> str:
    return f"grep -ahE '{LOG_GREP}' /var/log/tos/validator/node.log*"


def resolve(cmd: str, addr) -> str:
    """Replace `$(addr X)` with addr(X), checked to be an IPv4 address."""
    import ipaddress

    def one(m):
        a = addr(m[1]).strip()
        ipaddress.IPv4Address(a)
        return a

    return ADDR_REF.sub(one, cmd)


# ------------------------------------------------------------------ logs


def line_time(line: str) -> float | None:
    m = STAMP.search(line)
    if not m:
        return None
    d = datetime.datetime.strptime(m[1], "%Y-%m-%d %H:%M:%S")
    return d.replace(tzinfo=datetime.timezone.utc).timestamp()


def lines_since(text: str, t0: float) -> list[str]:
    t0 = int(t0)
    return [x for x in text.splitlines() if (t := line_time(x)) is not None and t >= t0]


def classify_log(lines: list[str]) -> tuple[list[str], list[str]]:
    """(fail reasons, inconclusive reasons) from a host's marker lines since t0."""
    fail, inc = [], []
    for line in lines:
        m = re.search(r"MISBEHAVIOR DETECTED kind=(\S+)", line)
        if m:
            if m[1] in DOUBLE_SIGN_KINDS:
                fail.append(f"double-sign allegation {m[1]}")
            else:
                inc.append(f"allegation {m[1]}")
        if "conflicts with a decision already recorded" in line:
            fail.append("ledger conflict refusal")
        if re.search(r"signing decision log .* is full", line):
            fail.append("signing decision log is full")
        if re.search(r"unknown history|untrusted", line, re.I):
            fail.append("untrusted ledger / unknown history")
    return fail, inc


# ------------------------------------------------------------------ verdict


def _ok_samples(samples, ports, a, b):
    return [
        s
        for s in samples
        if s.get("port") in ports and s.get("seqno") is not None and a <= s["t"] <= b
    ]


def coverage_gaps(samples, ports, a, b, max_gap=10.0) -> list[str]:
    out = []
    for port in ports:
        ts = sorted(s["t"] for s in _ok_samples(samples, [port], a - max_gap, b + max_gap))
        if not ts:
            out.append(f"port {port}: no samples")
            continue
        edges = [a] + [t for t in ts if a <= t <= b] + [b]
        if ts[0] > a or ts[-1] < b:
            out.append(f"port {port}: samples do not span the window")
            continue
        gap = max(y - x for x, y in zip(edges, edges[1:]))
        if gap > max_gap:
            out.append(f"port {port}: a {gap:.0f}s sampler gap")
    return out


def longest_stall(samples, ports, a, b) -> float:
    """Longest time in [a, b] without a new masterchain block on any of `ports`."""
    rows = sorted(_ok_samples(samples, ports, a, b), key=lambda s: s["t"])
    if not rows:
        return b - a
    best, since, worst, prev = rows[0]["seqno"], a, 0.0, a
    for s in rows:
        if s["t"] - prev > 10:
            # A sampler gap is not a stall: coverage_gaps reports it (INCONCLUSIVE).
            since = s["t"]
        prev = s["t"]
        if s["seqno"] > best:
            worst = max(worst, s["t"] - since)
            best, since = s["seqno"], s["t"]
    return max(worst, b - since)


def advance(samples, port, a, b) -> int | None:
    rows = _ok_samples(samples, [port], a, b)
    if not rows:
        return None
    seq = [s["seqno"] for s in rows]
    return max(seq) - min(seq)


def compute_verdict(
    scenario: str, *, r0: float, samples: list[dict], events: dict, node_results: dict, logs: dict
) -> dict:
    """Section 5.1 without the next handover, which stays pending.

    events: t0, outage_end (S1/S2/S5), halt_from/halt_to (S3/S4), end (rejoined),
    deadlines {name: bool}, partition_confirmed (S4/S5), rates_during [..], rate_post,
    outside_abort (str or None). node_results: {node: t3-node.py JSON of the restart}.
    logs: {node: marker lines since t0, or None when the pull failed}.
    """
    s = SCENARIOS[scenario]
    fail: list[str] = []
    inc: list[str] = []
    checks: dict = {}
    t0 = events["t0"]
    end = events.get("end") or events.get("outage_end") or events.get("halt_to") or t0
    if events.get("outside_abort"):
        inc.append(f"gate failed mid-scenario: {events['outside_abort']}")
    partitioned = s["partition"] is not None
    confirmed = events.get("partition_confirmed") if partitioned else True
    if partitioned and confirmed is not True:
        inc.append("partition not confirmed on all 4 hosts")
    gaps = coverage_gaps(samples, s["live"], t0, end)
    checks["sampler_gaps"] = gaps
    if gaps:
        inc.append("missing sampler window: " + "; ".join(gaps))

    if s["kind"] == "continue" and confirmed:
        oe = events.get("outage_end", end)
        stall = longest_stall(samples, s["live"], t0, oe)
        checks["longest_stall_s"] = round(stall, 1)
        if stall >= 30:
            fail.append(f"chain stalled {stall:.0f}s with 3 of 4 up")
        rates = [r for r in events.get("rates_during") or [] if r is not None]
        if not rates or not r0:
            inc.append("no outage rate measured")
        else:
            ratio = min(rates) / r0
            checks["outage_rate_ratio"] = round(ratio, 3)
            if ratio < 0.50:
                fail.append(f"outage rate {ratio:.2f} x R0 < 0.50")
            elif ratio < 0.70:
                inc.append(f"outage rate {ratio:.2f} x R0 in 0.50-0.70")
        for port in s["frozen"]:
            a = advance(samples, port, t0 + 20, oe)
            checks[f"isolated_{port}_advance"] = a
            if a is None or a > 1:
                inc.append(f"isolated port {port} not frozen (advance {a})")
    if s["kind"] == "halt" and confirmed:
        hf, ht = events.get("halt_from"), events.get("halt_to")
        if hf is None or ht is None:
            inc.append("halt window not recorded")
        else:
            for port in s["live"]:
                a = advance(samples, port, hf, ht)
                checks[f"halt_{port}_advance"] = a
                if a is None:
                    inc.append(f"no samples on {port} in the halt window")
                elif a > 1:
                    fail.append(f"{a} blocks on {port} while only 2 of 4 could sign")

    for name, met in (events.get("deadlines") or {}).items():
        if met is not True:
            fail.append(f"no resume by the deadline: {name}")
    for node in events.get("restarted") or []:
        r = (node_results.get(node) or {}).get("result")
        if r == "TRUSTED-RESIGNED":
            continue
        if r in (
            "UNTRUSTED-FENCED",
            "STOPPED-UNEXPECTED-LEDGER-STATE",
            "UNEXPECTED-LEDGER-STATE",
            "LEDGER-REPLACED",
        ):
            fail.append(f"{node}: {r} after a clean stop or a kill")
        else:
            inc.append(f"{node}: no trusted re-sign marker ({r})")
    for node in VALIDATORS:
        lines = logs.get(node)
        if lines is None:
            inc.append(f"{node}: missing log window")
            continue
        f, i = classify_log(lines)
        fail += [f"{node}: {x}" for x in sorted(set(f))]
        inc += [f"{node}: {x}" for x in sorted(set(i))]
    post = events.get("rate_post")
    if post is None or not r0:
        inc.append("no post rate measured")
    else:
        checks["post_rate_ratio"] = round(post / r0, 3)
        if post < 0.9 * r0:
            inc.append(f"post rate {post / r0:.2f} x R0 < 0.90")

    verdict = "FAIL" if fail else "INCONCLUSIVE" if inc else "PASS"
    return dict(
        scenario=scenario,
        verdict=verdict,
        final="pending-next-handover" if verdict == "PASS" else verdict,
        fail=fail,
        inconclusive=inc,
        checks=checks,
        next_handover=dict(status="pending"),
    )


def load_samples(path: Path) -> list[dict]:
    rows = []
    try:
        text = Path(path).read_text()
    except OSError:
        return rows
    for line in text.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if "port" in d and "t" in d:
            rows.append(d)
    return rows


# ------------------------------------------------------------------ pins


def pin_problems(pins: Path | str, deploy: Path | str) -> list[str]:
    """Each pinned outside script must exist with its recorded sha256."""
    import hashlib

    p = []
    for line in Path(pins).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        want, path = line.split(None, 1)
        if path.startswith("DEPLOY/"):
            path = str(Path(deploy) / path[len("DEPLOY/") :])
        try:
            got = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        except OSError as e:
            p.append(f"{path}: unreadable ({e.__class__.__name__})")
            continue
        if got != want:
            p.append(f"{path}: sha256 {got[:12]} is not the pinned {want[:12]}")
    return p


# ------------------------------------------------------------------ command line


def main(argv: list[str]) -> int:
    if argv[:1] == ["classify-ok"] and len(argv) == 3:
        path = Path(argv[1])
        try:
            c = json.loads(path.read_text())
            result = (path.parent / "RESULT.txt").read_text()
        except (OSError, ValueError) as e:
            print(f"STOP: {path}: {e.__class__.__name__}")
            return 3
        p = classify_problems(c, result, int(argv[2]))
        for x in p:
            print(f"STOP: {path.parent.name}: {x}")
        return 3 if p else 0
    if argv[:1] == ["gate"] and len(argv) in (4, 6):
        lead = int(argv[5]) if len(argv) == 6 and argv[4] == "--lead" else SAMPLER_LEAD
        term = json.loads(Path(argv[1]).read_text())
        p = gate_problems(term, argv[2], argv[3], time.time(), lead)
        for x in p:
            print(f"STOP: {x}")
        return 3 if p else 0
    if argv[:1] == ["check-pre"] and len(argv) == 4:
        p = pre_problems(argv[1], argv[2], Path(argv[3]).read_text())
        for x in p:
            print(f"STOP: {argv[2]}: {x}")
        return 4 if p else 0
    if argv[:1] == ["pins-ok"] and len(argv) == 3:
        p = pin_problems(argv[1], argv[2])
        for x in p:
            print(f"STOP: pinned script changed or missing: {x}")
        return 3 if p else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
