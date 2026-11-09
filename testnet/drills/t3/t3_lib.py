"""T3 drill logic shared by t3-run.sh, t3-preflight.sh, t3_run.py and the tests.

Pure functions (standard library only): the scenario table, the time-window and term gates,
the handover verdict check, the host pre-check parser and its redaction, the timer checks,
the partition, counter and heal commands, the log classification, the sampled-interval
progress measures and the verdict of the public-testnet T3 plan v2 (sections 4, 5, 5.1).
Nothing here talks to a host. Command-line use, for the shell scripts:

  python3 t3_lib.py classify-ok CLASSIFY.json BOUNDARY
  python3 t3_lib.py pins-ok PINS DEPLOY
  python3 t3_lib.py quarantines EVIDENCE_ROOT
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import math
import re
import sys
from pathlib import Path

VALIDATORS = ("node-1", "node-2", "node-3", "node-4")
# Observation tunnels on the coordinator, each to its host's loopback JSON-RPC.
PORT = {"node-1": 18081, "node-2": 38081, "node-3": 28081, "node-4": 48084}
NODE_OF_PORT = {p: n for n, p in PORT.items()}
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
SELF_HEAL_S = 720
TABLE = "t3part"
EQUAL_WEIGHT = 1 << 58
# Head age bound: a head older than this is not fresh progress (about 70 slots at 400 ms).
MAX_HEAD_AGE = 30.0
# Clock bound: |host - coordinator| after half the round trip. The verdict's time windows
# have a 2 s sample period and the halt has a 30 s settling interval, so a skew of half a
# second cannot move a block across a window edge by more than a sample.
MAX_CLOCK_SKEW = 0.5
SETTLE_BASE = 30.0  # the four-slot pipeline's drain after a cut
HEAL_ARGV = f"argv[]=/usr/sbin/nft delete table inet {TABLE}"
RESTORE_ARGV = "argv[]=/usr/bin/systemctl start tos-testnet-validator"

S4_SIDES = {
    "node-1": ("node-3", "node-4"),
    "node-2": ("node-3", "node-4"),
    "node-3": ("node-1", "node-2"),
    "node-4": ("node-1", "node-2"),
}

# kind: "continue" (3 of 4 sign: the chain must go on) or "halt" (2 of 4: it must stop).
# One scenario per window (plan v2, section 3); S5 was dropped.
SCENARIOS = {
    "S1": dict(
        kind="continue",
        budget=900,
        abort=1200,
        mute=["node-4"],
        mute_min=20,
        targets=["node-4"],
        live=list(RATE_PORTS),
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
        partition=None,
        title="unclean restart (SIGKILL), 1 down",
    ),
    "S3": dict(
        kind="halt",
        budget=1500,
        abort=1500,
        mute=[],
        mute_min=25,
        targets=["node-4", "node-3"],
        live=list(RATE_PORTS),
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
        partition=S4_SIDES,
        title="2-2 partition, then heal",
    ),
}
RESTORE_AT = 900  # S3: each stopped host's own restore timer fires at t0+15 min

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
ADDR6_REF = re.compile(r"\$\(addr6 (node-[1-4])\)")
SCOPE = (
    "T3 observes availability (fresh head progress on the observation tunnels) and the "
    "safety refusals and allegations the engines log. It does not authenticate the fault "
    "interval: the next handover's offline verify checks certificates around the boundary, "
    "not the blocks of the fault window."
)


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


def recovery_deadline(term: dict) -> int:
    """Even-hour :05:07: 13 min before the election opens at until - 3600."""
    return int(term["until"]) - 3600 - 780


def window_problems(term: dict, scenario: str, now: float, lead: int = SAMPLER_LEAD) -> list[str]:
    """Term and window gates (plan v2 2.7): the FULL hard-abort budget must fit before the
    recovery deadline and before the next odd-hour :12 handover collection."""
    s = SCENARIOS[scenario]
    p = []
    since, until = int(term["since"]), int(term["until"])
    if not since <= now < until:
        p.append("now is outside the current term")
    need = 3600 + s["budget"] + 780
    if until - now < need:
        p.append(f"term left {until - now:.0f}s < {need}s")
    abort_end = now + lead + s["abort"]
    if abort_end > recovery_deadline(term):
        p.append(
            f"hard abort {utc(abort_end)} is after the recovery deadline "
            f"{utc(recovery_deadline(term))}"
        )
    quiet_stop = until - 367  # odd-hour :12:00, the next handover's collection
    if abort_end > quiet_stop:
        p.append(
            f"hard abort {utc(abort_end)} would cross the next handover window {utc(quiet_stop)}"
        )
    if now < since + 540:
        p.append(f"the {utc(since)} handover verdict is still pending (until {utc(since + 540)})")
    return p


def set_problems(term: dict) -> list[str]:
    """The current weighted set: 4 validators, 4 main, 4 equal weights."""
    p = []
    vals = term.get("validators") or []
    if term.get("total") != 4 or term.get("main") != 4 or len(vals) != 4:
        p.append(f"set is not 4 of 4 (total {term.get('total')}, main {term.get('main')})")
    weights = [v.get("weight") for v in vals]
    if weights != [EQUAL_WEIGHT] * 4:
        p.append(f"weights are not four equal {EQUAL_WEIGHT}: {weights}")
    return p


def election_problems(cp36_answer: dict, election_answer: dict) -> list[str]:
    """ConfigParam 36 absent and active_election_id 0 (validator-step.sh:30-37)."""
    p = []
    if not ("error" in cp36_answer and "CONFIG_PARAM_ABSENT" in str(cp36_answer["error"])):
        p.append("ConfigParam 36 is present (a next set is published)")
    try:
        r = election_answer["result"]
        if r["exit_code"] != 0 or int(r["stack"][0][1], 0) != 0:
            p.append("an election is active")
    except (KeyError, IndexError, TypeError, ValueError):
        p.append("active_election_id not read")
    return p


def heads_problems(first: dict, second: dict) -> list[str]:
    """Two reads of every port some seconds apart: answering, within 5, advancing, fresh.

    Each value: {"seqno": int, "utime": int, "t": local time}."""
    p = []
    for port in ALL_PORTS:
        a, b = first.get(port), second.get(port)
        if not a or not b:
            p.append(f"port {port} did not answer")
            continue
        if b["seqno"] <= a["seqno"]:
            p.append(f"port {port} head did not advance ({a['seqno']} -> {b['seqno']})")
        if b["t"] - b["utime"] > MAX_HEAD_AGE:
            p.append(f"port {port} head is {b['t'] - b['utime']:.0f}s old")
    seq = [second[x]["seqno"] for x in ALL_PORTS if second.get(x)]
    if seq and max(seq) - min(seq) > 5:
        p.append(f"heads are not within 5 blocks: {seq}")
    return p


def clock_offset(before: float, host: float, after: float) -> tuple[float, float]:
    """(offset, uncertainty): host minus the round trip's midpoint, and half the round trip."""
    return host - (before + after) / 2, (after - before) / 2


def clock_problems(offsets: dict) -> list[str]:
    p = []
    for node, (off, half) in offsets.items():
        if abs(off) - half > MAX_CLOCK_SKEW or half > 2.0:
            p.append(f"{node} clock offset {off:+.3f}s (+-{half:.3f}s) beyond {MAX_CLOCK_SKEW}s")
    return p


def settle_seconds(offsets: dict) -> float:
    """The halt's settling interval: the pipeline drain plus the worst measured skew."""
    worst = max([abs(o) + h for o, h in offsets.values()] or [0.0])
    return SETTLE_BASE + math.ceil(worst)


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


def units_of(node: str) -> list[str]:
    return ["tos-testnet-validator", "tos-testnet-elections"] + (
        ["tos-testnet-dht"] if node == "node-1" else []
    )


def address_family(token: str) -> str:
    """'v4', 'v6', 'v4mapped', 'any', 'v4any', 'loopback' or 'unknown' of an ss token."""
    host = token.rsplit(":", 1)[0].strip("[]")
    if host in ("*", "::"):
        return "any"
    if host == "0.0.0.0":
        return "v4any"
    host = host.split("%", 1)[0]
    try:
        a = ipaddress.ip_address(host)
    except ValueError:
        return "unknown"
    if a.is_loopback:
        return "loopback"
    if a.version == 6 and a.ipv4_mapped is not None:
        return "v4mapped"
    return f"v{a.version}"


def socket_summary(lines: list[str]) -> list[dict]:
    """validator-engine sockets with families and local ports only, never an address."""
    out = []
    for line in lines:
        f = line.split()
        if len(f) < 6 or "validator-engi" not in line:
            continue
        local, peer = f[4], f[5]
        out.append(
            dict(
                proto=f[0],
                state=f[1],
                local=address_family(local),
                port=local.rsplit(":", 1)[-1],
                peer=address_family(peer),
            )
        )
    return out


def v6_globals(lines: list[str]) -> list[str]:
    """Global IPv6 addresses from `ip -6 -o addr show scope global` (kept in memory only)."""
    out = []
    for line in lines:
        m = re.search(r"\binet6 ([0-9a-fA-F:]+)/\d+", line)
        if m:
            a = ipaddress.IPv6Address(m[1])
            if not (a.is_link_local or a.is_loopback):
                out.append(str(a))
    return out


def needs_v6(summary: list[dict]) -> bool:
    return any(s["local"] in ("v6", "any") or s["peer"] == "v6" for s in summary)


def pre_problems(scenario: str, node: str, text: str, revision: str = "76af11250") -> list[str]:
    """Refusals from one host's t3-host-check.sh output (plan v2 section 4)."""
    sec = sections(text)
    p = []
    want = [f"{u} rc=0" for u in units_of(node)]
    got = [x.strip() for x in sec.get("units", [])]
    if got != want:
        p.append(f"units not each active (rc per unit): {got}")
    if not any(revision in x for x in sec.get("version", [])):
        p.append(f"host is not on {revision}")
    restart = {k: v for k, _, v in (x.partition("=") for x in sec.get("restart", []))}
    if restart.get("Restart") != "on-failure" or restart.get("RestartUSec") not in ("10s", "10"):
        p.append(f"validator unit restart policy {restart} is not on-failure, 10s")
    if not re.fullmatch(r"\d+ \d+", (sec.get("ledger") or [""])[0].strip()):
        p.append("ledger binding not read")
    if any(TABLE in x for x in sec.get("tables", [])):
        p.append("a partition table is already present")
    if [x for x in sec.get("t3-units", []) if x.strip()]:
        p.append(f"a t3 timer or service is already present: {sec.get('t3-units')}")
    tools = [x.strip() for x in sec.get("tools", [])]
    if scenario in ("S3", "S4") and "/usr/bin/systemd-run" not in tools:
        p.append("systemd-run is not /usr/bin/systemd-run")
    if SCENARIOS[scenario]["partition"]:
        if "/usr/sbin/nft" not in tools:
            p.append("nft is not /usr/sbin/nft, which the self-heal timer calls")
        if not socket_summary(sec.get("sockets", [])):
            p.append("no validator-engine socket inventoried")
        if not any(x.startswith("listen ") for x in sec.get("config", [])):
            p.append("no listen address in config.json")
    if not re.fullmatch(r"\d+", (sec.get("allegations") or [""])[0].strip()):
        p.append("allegation baseline not counted")
    return p


def redact_pre(text: str) -> str:
    """The pre-check record with address-bearing sections replaced by summaries."""
    sec = sections(text)
    out = []
    for name, lines in sec.items():
        out.append(f"== {name}")
        if name == "sockets":
            out += [json.dumps(s) for s in socket_summary(lines)]
        elif name == "v6":
            out.append(f"global IPv6 addresses: {len(v6_globals(lines))}")
        elif name == "udp":
            for f in (x.split() for x in lines):
                if len(f) >= 5:
                    out.append(f"{f[0]} {address_family(f[4])}:{f[4].rsplit(':', 1)[-1]}")
        else:
            out += lines
    return "\n".join(out) + "\n"


def ledger_binding(text: str) -> str:
    dev, ino = (sections(text).get("ledger") or [""])[0].split()
    return f"{int(dev)}:{int(ino)}"


def identities(texts: dict[str, str], term: dict) -> dict:
    """Host -> validator id, from config.json ADNL ids matched to ConfigParam 34, with the
    custody log line as a fallback. Unresolved or ambiguous hosts get None."""
    by_adnl = {v["adnl"].lower(): v["id"].lower() for v in term.get("validators") or []}
    out = {}
    for node, text in texts.items():
        sec = sections(text)
        ids = {x.split()[1].lower() for x in sec.get("config", []) if x.startswith("adnlid ")}
        hits = {by_adnl[i] for i in ids if i in by_adnl}
        custody = None
        for x in sec.get("custody", []):
            m = re.search(r"custody of validator ([0-9A-Fa-f]{64})", x)
            if m:
                custody = m[1].lower()
        vid = hits.pop() if len(hits) == 1 else None
        if vid is None and custody in by_adnl.values():
            vid = custody
        out[node] = dict(validator=vid, custody=custody)
    vids = [v["validator"] for v in out.values() if v["validator"]]
    if len(set(vids)) != len(vids):
        out = {n: dict(v, validator=None) for n, v in out.items()}
    return out


# ------------------------------------------------------------------ host commands


def node_cmd(node: str, mode: str, *extra: str) -> str:
    return " ".join(["python3", "/root/t3-node.py", node, mode, *extra])


def timespan(text: str) -> float:
    """Seconds of a systemd timespan such as '1d 4h 13min 50.843801s'."""
    unit = {
        "y": 31557600,
        "month": 2629800,
        "w": 604800,
        "d": 86400,
        "h": 3600,
        "min": 60,
        "s": 1,
        "ms": 1e-3,
        "us": 1e-6,
    }
    pat = r"([\d.]+)\s*(month|min|ms|us|y|w|d|h|s)\b"
    parts = re.findall(pat, text)
    if not parts or re.sub(pat, "", text).strip():
        raise ValueError(f"not a timespan: {text!r}")
    return sum(float(n) * unit[u] for n, u in parts)


def timer_report_cmd(unit: str) -> str:
    """Key=value facts of a transient timer and its service, each on its own line."""
    return (
        f'echo "timer=$(systemctl is-active {unit}.timer)"; '
        f'echo "next=$(systemctl show -p NextElapseUSecMonotonic --value {unit}.timer)"; '
        "echo \"mono=$(python3 -c 'import time; print(time.monotonic())')\"; "
        f'echo "exec=$(systemctl show -p ExecStart --value {unit}.service)"'
    )


def arm_heal_cmd(run: str) -> str:
    """Arm the self-heal BEFORE any rule exists, then report it for verification."""
    unit = f"t3-heal-{run}"
    return (
        f"systemd-run --unit={unit} --on-active={SELF_HEAL_S}s /usr/sbin/nft delete table inet "
        f'{TABLE} >/dev/null 2>&1; echo "armed_rc=$?"; test -x /usr/sbin/nft; '
        f'echo "nft_x=$?"; {timer_report_cmd(unit)}'
    )


def timer_problems(
    output: str,
    argv: str,
    want_left: float,
    tolerance: float = 60.0,
    need: tuple = ("armed_rc", "nft_x"),
) -> list[str]:
    kv = {}
    for line in output.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            kv[k.strip()] = v.strip()
    p = []
    for k in need:
        if kv.get(k) != "0":
            p.append(f"{k}={kv.get(k)}")
    if kv.get("timer") != "active":
        p.append(f"timer is {kv.get('timer')}")
    if argv not in kv.get("exec", ""):
        p.append("timer runs something else than " + argv)
    try:
        left = timespan(kv["next"]) - float(kv["mono"])
        if not want_left - tolerance <= left <= want_left + 5:
            p.append(f"timer fires in {left:.0f}s, not about {want_left:.0f}s")
    except (KeyError, ValueError):
        p.append("timer deadline not read")
    return p


def rule_lines(direction: str, drops, v6: bool) -> list[str]:
    key = "saddr" if direction == "i" else "daddr"
    out = [f'    ip {key} $(addr {x}) counter drop comment "{x}"' for x in drops]
    if v6:
        out += [f'    ip6 {key} $(addr6 {x}) counter drop comment "{x} v6"' for x in drops]
    return out


def load_cmd(node: str, drops, v6: bool) -> str:
    """The section-5 rule with one counted rule per peer and direction. `$(addr X)` and
    `$(addr6 X)` references are resolved in memory only when executed (an `$(addr6 X)` line
    becomes one rule per global IPv6 address of X, or none)."""
    for x in drops:
        assert x in VALIDATORS and x != node, (node, drops)
    lines = ["nft -f - <<'T3EOF'", f"table inet {TABLE} {{"]
    for d, hook in (("i", "input"), ("o", "output")):
        lines.append(f"  chain {d} {{")
        lines.append(f"    type filter hook {hook} priority -50;")
        lines += rule_lines(d, drops, v6)
        lines.append("  }")
    lines += ["}", "T3EOF", f"nft list table inet {TABLE} >/dev/null"]
    return "\n".join(lines)


def heal_cmd(run: str) -> str:
    """Idempotent: exits 0 only when the table is gone."""
    return (
        f"nft delete table inet {TABLE} 2>/dev/null; systemctl stop t3-heal-{run}.timer "
        f"2>/dev/null; ! nft list table inet {TABLE} >/dev/null 2>&1"
    )


def verify_cmd() -> str:
    return f"nft list table inet {TABLE}"


def counters(output: str) -> dict:
    """{peer: {"in": packets, "out": packets}} from `nft list table`; addresses are dropped."""
    out: dict = {}
    chain = None
    for line in output.splitlines():
        m = re.search(r"chain (\w+) \{", line)
        if m:
            chain = m[1]
            continue
        m = re.search(r'counter packets (\d+) bytes \d+ drop comment "(node-[1-4])( v6)?"', line)
        if m and chain in ("i", "o"):
            d = out.setdefault(m[2], {"in": 0, "out": 0})
            d["in" if chain == "i" else "out"] += int(m[1])
    return out


def partition_loaded(output: str, drops) -> bool:
    c = counters(output)
    return f"table inet {TABLE}" in output and all(x in c for x in drops)


def counter_problems(per_host: dict, sides: dict) -> list[str]:
    """Every cross-cut pair must show dropped packets in both directions."""
    p = []
    for node, drops in sides.items():
        c = per_host.get(node)
        if c is None:
            p.append(f"{node}: counters not read")
            continue
        for x in drops:
            got = c.get(x, {"in": 0, "out": 0})
            if got["in"] <= 0 or got["out"] <= 0:
                p.append(f"{node}<->{x}: drops in {got['in']}, out {got['out']}")
    return p


def log_cmd() -> str:
    return f"grep -ahE '{LOG_GREP}' /var/log/tos/validator/node.log*"


def resolve(cmd: str, addr, addr6=lambda node: []) -> str:
    """Replace `$(addr X)` with addr(X), checked IPv4, and expand `$(addr6 X)` lines."""

    def one(m):
        a = addr(m[1]).strip()
        ipaddress.IPv4Address(a)
        return a

    lines = []
    for line in cmd.split("\n"):
        m = ADDR6_REF.search(line)
        if m:
            for a in addr6(m[1]):
                ipaddress.IPv6Address(a)
                lines.append(ADDR6_REF.sub(a, line))
            continue
        lines.append(ADDR_REF.sub(one, line))
    return "\n".join(lines)


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


def safety_events(node: str, lines: list[str]) -> list[dict]:
    """Double-sign allegations (with the alleged validator) and conflict refusals."""
    out = []
    for line in lines:
        m = re.search(r"MISBEHAVIOR DETECTED kind=(\S+)(?: validator=([0-9A-Fa-f]+))?", line)
        if m and m[1] in DOUBLE_SIGN_KINDS:
            out.append(dict(kind=m[1], reporter=node, validator=(m[2] or "").lower() or None))
        if "conflicts with a decision already recorded" in line:
            out.append(dict(kind="conflict-refusal", reporter=node, implicated=node))
    return out


def implicated_hosts(events: list[dict], ids: dict) -> tuple[list[str], list[str]]:
    """(hosts to quarantine, unresolved validator ids)."""
    by_vid = {v["validator"]: n for n, v in ids.items() if v.get("validator")}
    hosts, unresolved = set(), set()
    for e in events:
        if e.get("implicated"):
            hosts.add(e["implicated"])
        elif e.get("validator") in by_vid:
            hosts.add(by_vid[e["validator"]])
        else:
            unresolved.add(e.get("validator") or "unknown")
    return sorted(hosts), sorted(unresolved)


def classify_log(lines: list[str]) -> tuple[list[str], list[str], list[str]]:
    """(safety, fail, inconclusive) reasons from a host's marker lines since t0."""
    safety, fail, inc = [], [], []
    for line in lines:
        m = re.search(r"MISBEHAVIOR DETECTED kind=(\S+)", line)
        if m:
            if m[1] in DOUBLE_SIGN_KINDS:
                safety.append(f"double-sign allegation {m[1]}")
            else:
                inc.append(f"allegation {m[1]}")
        if "conflicts with a decision already recorded" in line:
            safety.append("ledger conflict refusal")
        if re.search(r"signing decision log .* is full", line):
            fail.append("signing decision log is full")
        if re.search(r"unknown history|untrusted", line, re.I):
            fail.append("untrusted ledger / unknown history")
    return safety, fail, inc


def session_loads(lines: list[str]) -> dict:
    """Per-session load lines after a restart: admitted and fenced counts (masterchain too)."""
    out = dict(admitted=0, fenced=0, masterchain_admitted=0)
    for line in lines:
        m = re.search(r"signing ledger: session \S+ of (\S+) catchain \d+: (admitted|fenced)", line)
        if m:
            out[m[2]] += 1
            if m[2] == "admitted" and m[1].startswith("(-1,"):
                out["masterchain_admitted"] += 1
    return out


# ------------------------------------------------------------------ sampled progress


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
        if ts[0] > a or ts[-1] < b:
            out.append(f"port {port}: samples do not span the window")
            continue
        edges = [a] + [t for t in ts if a <= t <= b] + [b]
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


def interval_rate(samples, ports, a, b, min_rows=3) -> float | None:
    """Fresh blocks per second inside [a, b]: the slowest port's seqno advance over its own
    sampled span, only if it advanced and its heads were fresh (age <= MAX_HEAD_AGE) in at
    least 90 % of the samples. None when that cannot be shown. No block history is used."""
    rates = []
    for port in ports:
        rows = sorted(_ok_samples(samples, [port], a, b), key=lambda s: s["t"])
        if len(rows) < min_rows or rows[-1]["t"] - rows[0]["t"] < (b - a) / 2:
            return None
        fresh = [
            r
            for r in rows
            if r.get("last_block_utime") is not None
            and r["t"] - r["last_block_utime"] <= MAX_HEAD_AGE
        ]
        if len(fresh) < 0.9 * len(rows) or rows[-1]["seqno"] <= rows[0]["seqno"]:
            return None
        rates.append((rows[-1]["seqno"] - rows[0]["seqno"]) / (rows[-1]["t"] - rows[0]["t"]))
    return min(rates) if rates else None


def advance(samples, port, a, b) -> int | None:
    rows = _ok_samples(samples, [port], a, b)
    if not rows:
        return None
    seq = [s["seqno"] for s in rows]
    return max(seq) - min(seq)


# ------------------------------------------------------------------ verdict


def compute_verdict(
    scenario: str, *, samples: list[dict], events: dict, node_results: dict, logs: dict
) -> dict:
    """Section 5.1 (plan v2) without the next handover, which stays pending.

    events: t0; r0_from/r0_to (the sampler lead); outage_from/outage_to (S1/S2);
    halt_from/halt_to and settle (S3/S4); end (all rejoined); post_from; deadlines
    {name: bool}; restarted [nodes]; partition_confirmed and partition_counters (S4);
    safety [events]; quarantined [nodes]; election_end [problems]; outside_abort.
    node_results: {node: t3-node.py JSON of the restart}. logs: {node: lines since t0 or None}.
    """
    s = SCENARIOS[scenario]
    safety: list[str] = []
    fail: list[str] = []
    inc: list[str] = []
    checks: dict = {}
    t0 = events["t0"]
    end = events.get("end") or events.get("outage_to") or events.get("halt_to") or t0
    if events.get("outside_abort"):
        inc.append(f"gate or step failed for an outside reason: {events['outside_abort']}")
    r0 = interval_rate(
        samples, RATE_PORTS, events.get("r0_from", t0 - 115), events.get("r0_to", t0)
    )
    checks["r0"] = r0
    if not r0:
        inc.append("R0 not shown by fresh progress in the sampler lead")
    partitioned = s["partition"] is not None
    confirmed = events.get("partition_confirmed") if partitioned else True
    if partitioned and confirmed is not True:
        inc.append("partition not confirmed on all 4 hosts")
    if partitioned and confirmed is True:
        cp = counter_problems(events.get("partition_counters") or {}, s["partition"])
        checks["counter_problems"] = cp
        if cp:
            inc.append("INCOMPLETE: no drops counted on every cross-cut pair: " + "; ".join(cp))
    gaps = coverage_gaps(samples, s["live"], t0, end)
    checks["sampler_gaps"] = gaps
    if gaps:
        inc.append("missing sampler window: " + "; ".join(gaps))

    if s["kind"] == "continue":
        a, b = events.get("outage_from", t0), events.get("outage_to", end)
        stall = longest_stall(samples, s["live"], t0, b)
        checks["longest_stall_s"] = round(stall, 1)
        if stall >= 30:
            fail.append(f"chain stalled {stall:.0f}s with 3 of 4 up")
        rate = interval_rate(samples, s["live"], a, b)
        if rate is None or not r0:
            inc.append("no fresh outage rate measured")
        else:
            ratio = rate / r0
            checks["outage_rate_ratio"] = round(ratio, 3)
            if ratio < 0.50:
                fail.append(f"outage rate {ratio:.2f} x R0 < 0.50")
            elif ratio < 0.70:
                inc.append(f"outage rate {ratio:.2f} x R0 in 0.50-0.70")
    if s["kind"] == "halt" and confirmed:
        hf, ht = events.get("halt_from"), events.get("halt_to")
        settle = events.get("settle", SETTLE_BASE)
        checks["settle_s"] = settle
        if hf is None or ht is None or ht <= hf + settle:
            inc.append("halt window not recorded")
        else:
            for port in s["live"]:
                checks[f"settling_{port}_advance"] = advance(samples, port, hf, hf + settle)
                a = advance(samples, port, hf + settle, ht)
                checks[f"halt_{port}_advance"] = a
                if a is None:
                    inc.append(f"no samples on {port} in the halt window")
                elif a > 0:
                    fail.append(f"{a} blocks on {port} after settling while only 2 of 4 could sign")

    for name, met in (events.get("deadlines") or {}).items():
        if met is not True:
            fail.append(f"deadline missed: {name}")
    for node in events.get("restarted") or []:
        r = (node_results.get(node) or {}).get("result")
        if r == "SAFETY-QUARANTINED":
            safety.append(f"{node}: unsafe ledger marker, quarantined")
        elif r in ("UNTRUSTED-FENCED", "LEDGER-REPLACED"):
            fail.append(f"{node}: {r} after a clean stop or a kill")
        elif r != "TRUSTED-RESIGNED":
            inc.append(f"{node}: no trusted re-sign marker ({r})")
        loads = session_loads(logs.get(node) or [])
        checks[f"{node}_session_loads"] = loads
        if loads["fenced"]:
            fail.append(f"{node}: {loads['fenced']} session(s) fenced after the restart")
        elif not loads["masterchain_admitted"]:
            inc.append(f"{node}: no masterchain session load line after the restart")
    for node in VALIDATORS:
        lines = logs.get(node)
        if lines is None:
            inc.append(f"{node}: missing log window")
            continue
        sf, f, i = classify_log(lines)
        safety += [f"{node}: {x}" for x in sorted(set(sf))]
        fail += [f"{node}: {x}" for x in sorted(set(f))]
        inc += [f"{node}: {x}" for x in sorted(set(i))]
    for e in events.get("safety") or []:
        safety.append(f"safety event {e.get('kind')} reported by {e.get('reporter')}")
    if events.get("election_end"):
        inc.append(
            "an election opened or a next set was published during the run: verify "
            "the host's accepted submission and the next set: " + "; ".join(events["election_end"])
        )
    post_from = events.get("post_from", end)
    post = interval_rate(samples, s["live"], post_from, post_from + 300)
    if post is None or not r0:
        inc.append("no fresh post rate measured")
    else:
        checks["post_rate_ratio"] = round(post / r0, 3)
        if post < 0.9 * r0:
            inc.append(f"post rate {post / r0:.2f} x R0 < 0.90")
    if scenario == "S2":
        checks["torn_tail_exercised"] = (
            "unobservable: the engine truncates a torn tail without logging it, so this run "
            "shows an unclean restart, not a torn-tail recovery"
        )

    safety = sorted(set(safety))
    verdict = "SAFETY_FAIL" if safety else "FAIL" if fail else "INCONCLUSIVE" if inc else "PASS"
    return dict(
        scenario=scenario,
        verdict=verdict,
        final="pending-next-handover" if verdict == "PASS" else verdict,
        safety=safety,
        fail=fail,
        inconclusive=inc,
        checks=checks,
        quarantined=events.get("quarantined") or [],
        scope=SCOPE,
        next_handover=dict(status="pending", note="finalized by the coordinator by hand"),
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


# ------------------------------------------------------------------ pins and quarantine


def pin_problems(pins: Path | str, deploy: Path | str) -> list[str]:
    """Each pinned outside script must exist with its recorded sha256."""
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


def open_quarantines(evidence: Path | str) -> list[str]:
    """QUARANTINE-node-N files under any run without a matching CLEARED-node-N."""
    out = []
    for q in sorted(Path(evidence).glob("*/QUARANTINE-node-*")):
        if not (q.parent / q.name.replace("QUARANTINE-", "CLEARED-")).exists():
            out.append(f"{q.parent.name}/{q.name}")
    return out


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
    if argv[:1] == ["pins-ok"] and len(argv) == 3:
        p = pin_problems(argv[1], argv[2])
        for x in p:
            print(f"STOP: pinned script changed or missing: {x}")
        return 3 if p else 0
    if argv[:1] == ["quarantines"] and len(argv) == 2:
        p = open_quarantines(argv[1])
        for x in p:
            print(f"STOP: quarantine without clearance: {x}")
        return 3 if p else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
