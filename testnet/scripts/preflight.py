#!/usr/bin/env python3
"""Check hosts before a node is prepared on them, and prove they can reach each other.

  preflight.py --inventory hosts.json [--json] [--accept-new-host-keys] [--install-tools]

Run it from the coordinator's machine. It logs in to every host over SSH and
changes nothing there (unless --install-tools installs a missing tcpdump).

Per host, against network/profile.json `host_requirements`:
  ssh       the host answers as the inventory user
  os        Ubuntu 24.04 on x86_64 or aarch64
  cpu       enough CPUs; on x86_64 the x86-64-v2 instructions the build targets
  memory    MemTotal at or above the role's floor
  disk      free space for /var/lib at or above the role's floor
  address   the inventory address is on an interface (WARN if not: NAT then
            needs UDP forwarding and, for two nodes behind one NAT, hairpinning)
  time      the clock is NTP-synchronised
  ufw       when active, the role's UDP ports are allowed and the console port
            is not
  ports     no other program already listens on the role's UDP ports

Across hosts, for every role port of every host:
  udp       every other host's probe reaches it. Each target captures with
            tcpdump while every other host sends UDP probes to it. tcpdump sees
            a packet before the host firewall, so a probe that never appears was
            dropped outside the VM: a provider security group, an ACL or
            routing. That was the first deployment's failure: the provider's
            stateful group admitted only SSH, and every validator stayed at
            height 0.

Each probe carries "PROB:<sender>:<port>" in its payload, so a sender behind
NAT is still recognised. Exit status: 0 if nothing failed, 1 if any check
failed, 2 for a usage error.

Inventory (keep it outside the repository; it names real addresses and keys):

  {"hosts": [
    {"name": "node-1", "address": "203.0.113.10", "roles": ["validator", "dht"],
     "ssh_user": "root", "ssh_key": "~/.ssh/testnet.pem", "ssh_port": 22}
  ]}

A host below a role floor can carry a recorded per-host waiver, only for the
memory, cpu or disk check, each with a non-empty reason naming the decision:

  "waive": {"memory": "owner 2026-11-17: 3.9 GB host, validator capped by install-node.sh resources"}

A waived check that fails reports WAIVED with its measured value and the reason,
and does not fail the run; one that passes says the waiver was not needed. Every
other check, and an unknown or reasonless waiver, is refused.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testnet_lib as lib  # noqa: E402

ROLES = ("validator", "fullnode", "dht")
X86_64_V2 = ("cx16", "lahf_lm", "popcnt", "sse4_1", "sse4_2", "ssse3")
PROBE_REPEATS = 3
CAPTURE_SECONDS = 20
PROBE_MAGIC_BPF = "udp[8:4] = 0x50524f42"  # "PROB" at the start of the UDP payload

# Read-only facts, one key=value per line.
FACTS_SCRIPT = r"""
. /etc/os-release 2>/dev/null
echo "os_id=$ID"
echo "os_version=$VERSION_ID"
echo "arch=$(uname -m)"
echo "cpus=$(nproc)"
echo "cpu_model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
echo "cpu_flags=$(grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2-)"
echo "mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
d=/var/lib; [ -d /var/lib/tos ] && d=/var/lib/tos
echo "disk_free_kib=$(df -Pk "$d" | awk 'NR==2 {print $4}')"
echo "ipv4=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"
echo "ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
# The kernel flag alone can stay "yes" while the daemon has no server at all (seen with ntpsec
# preferring unreachable IPv6 servers), so also count the daemon's selected source.
if command -v ntpq >/dev/null; then
  echo "ntp_source=ntpd:$(ntpq -pn 2>/dev/null | grep -c '^\*')"
elif command -v chronyc >/dev/null; then
  echo "ntp_source=chrony:$(chronyc -n sources 2>/dev/null | grep -c '^\^\*')"
elif systemctl is-active --quiet systemd-timesyncd; then
  echo "ntp_source=timesyncd:$(timedatectl timesync-status 2>/dev/null | grep -c 'Server:')"
else
  echo "ntp_source=none:0"
fi
echo "ufw=$( (ufw status 2>/dev/null || echo 'Status: absent') | tr '\n' '|')"
echo "udp_listen=$(ss -H -lunp 2>/dev/null | awk '{print $4 "@" $NF}' | tr '\n' ' ')"
echo "tcpdump=$(command -v tcpdump || true)"
echo "python3=$(command -v python3 || true)"
"""


@dataclass
class Host:
    name: str
    address: str
    roles: list[str]
    ssh_user: str = "root"
    ssh_key: str = ""
    ssh_port: int = 22
    waive: dict[str, str] = dataclass_field(default_factory=dict)


@dataclass
class Result:
    host: str
    check: str
    status: str  # PASS, WARN, WAIVED or FAIL
    detail: str


# Only the role floors can be waived, each per host with a recorded reason. A waived
# floor still reports its measured value; it just does not fail the run.
WAIVABLE = ("memory", "cpu", "disk")


def load_waivers(entry: dict) -> dict[str, str]:
    waive = entry.get("waive", {})
    if not isinstance(waive, dict):
        raise lib.TestnetError(f"{entry.get('name')}: waive must be an object")
    unknown = sorted(set(waive) - set(WAIVABLE))
    if unknown:
        raise lib.TestnetError(
            f"{entry.get('name')}: only {list(WAIVABLE)} can be waived, not {unknown}"
        )
    for check, reason in waive.items():
        if not isinstance(reason, str) or not reason.strip():
            raise lib.TestnetError(
                f"{entry.get('name')}: the {check} waiver needs a reason (who decided it, where)"
            )
    return {check: reason.strip() for check, reason in waive.items()}


Runner = Callable[[Host, str, int], subprocess.CompletedProcess]


# ---------------------------------------------------------------- inventory and profile


def load_inventory(path: Path) -> list[Host]:
    data = json.loads(Path(path).read_text())
    hosts = []
    for entry in data.get("hosts", []):
        roles = entry.get("roles", [])
        if not roles or any(r not in ROLES for r in roles):
            raise lib.TestnetError(f"{entry.get('name')}: roles must be a subset of {ROLES}")
        ipaddress.IPv4Address(entry["address"])
        hosts.append(
            Host(
                name=entry["name"],
                address=entry["address"],
                roles=list(roles),
                ssh_user=entry.get("ssh_user", "root"),
                ssh_key=str(Path(entry["ssh_key"]).expanduser()) if entry.get("ssh_key") else "",
                ssh_port=int(entry.get("ssh_port", 22)),
                waive=load_waivers(entry),
            )
        )
    if not hosts:
        raise lib.TestnetError("the inventory names no hosts")
    for field in ("name", "address"):
        values = [getattr(h, field) for h in hosts]
        if len(set(values)) != len(values):
            raise lib.TestnetError(f"two inventory hosts share one {field}")
    return hosts


def role_udp_ports(roles: list[str], profile: dict) -> list[int]:
    ports = profile["ports"]
    out = set()
    if "validator" in roles or "fullnode" in roles:
        out.update({ports["adnl_udp"], ports["adnl_udp"] + ports["quic_udp_offset"]})
    if "dht" in roles:
        out.add(ports["dht_udp"])
    return sorted(out)


def role_floor(roles: list[str], profile: dict) -> dict:
    """The strictest floor among a host's roles."""
    table = profile["host_requirements"]["roles"]
    floor = {"min_cpus": 0, "min_memory_gib": 0, "min_disk_free_gib": 0}
    for role in roles:
        for key in floor:
            floor[key] = max(floor[key], table[role][key])
    return floor


# ---------------------------------------------------------------- remote execution


def ssh_argv(host: Host, accept_new: bool) -> list[str]:
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(host.ssh_port)]
    if accept_new:
        argv += ["-o", "StrictHostKeyChecking=accept-new"]
    if host.ssh_key:
        argv += ["-i", host.ssh_key]
    return argv + [f"{host.ssh_user}@{host.address}"]


def make_runner(accept_new: bool) -> Runner:
    def run(host: Host, command: str, timeout: int) -> subprocess.CompletedProcess:
        return subprocess.run(
            ssh_argv(host, accept_new) + [command], capture_output=True, text=True, timeout=timeout
        )

    return run


def parse_facts(text: str) -> dict[str, str]:
    facts = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            facts[key.strip()] = value.strip()
    return facts


def parse_ufw(text: str) -> tuple[str, list[str]]:
    """(state, rule lines) from `ufw status` joined with '|'."""
    lines = [line.strip() for line in text.split("|") if line.strip()]
    state = "absent"
    for line in lines:
        if line.startswith("Status:"):
            state = line.split(":", 1)[1].strip()
    rules = [line for line in lines if "ALLOW" in line or "DENY" in line or "REJECT" in line]
    return state, rules


def ufw_allows(rules: list[str], port: int, proto: str) -> bool:
    for rule in rules:
        target = rule.split()[0]
        if "(v6)" in rule or "ALLOW" not in rule:
            continue
        if target in (f"{port}/{proto}", str(port)):
            return True
    return False


# ---------------------------------------------------------------- per-host checks


def evaluate_host(host: Host, facts: dict[str, str], profile: dict) -> list[Result]:
    req = profile["host_requirements"]
    floor = role_floor(host.roles, profile)
    out = []

    def add(check: str, ok: bool, detail: str, warn: bool = False, waivable: bool = True) -> None:
        reason = host.waive.get(check)
        if reason is not None and not waivable and not ok:
            detail += "; not waivable"
        elif reason is not None:
            if ok:
                detail += "; waiver not needed"
            else:
                out.append(Result(host.name, check, "WAIVED", f"{detail}; waived: {reason}"))
                return
        out.append(Result(host.name, check, "PASS" if ok else ("WARN" if warn else "FAIL"), detail))

    os_ok = (
        facts.get("os_id") == req["os"]["id"] and facts.get("os_version") == req["os"]["version_id"]
    )
    add("os", os_ok, f"{facts.get('os_id')} {facts.get('os_version')} {facts.get('arch')}")
    arch = facts.get("arch", "")
    add("arch", arch in req["architectures"], arch)

    cpus = int(facts.get("cpus") or 0)
    cpu_detail = f"{cpus} CPUs, {facts.get('cpu_model', '?')}"
    if arch == "x86_64":
        flags = set(facts.get("cpu_flags", "").split())
        missing = [f for f in X86_64_V2 if f not in flags]
        if missing:
            cpu_detail += f"; missing x86-64-v2 flags {missing}"
        # A cpu waiver covers the CPU count only: a host without the instructions the
        # build targets cannot run the binaries, whatever was decided about its size.
        add(
            "cpu",
            cpus >= floor["min_cpus"] and not missing,
            cpu_detail + f" (need {floor['min_cpus']})",
            waivable=not missing,
        )
    else:
        add("cpu", cpus >= floor["min_cpus"], cpu_detail + f" (need {floor['min_cpus']})")

    mem_gib = int(facts.get("mem_kib") or 0) / 1048576
    add(
        "memory",
        mem_gib >= floor["min_memory_gib"],
        f"{mem_gib:.1f} GiB (need {floor['min_memory_gib']})",
    )
    disk_gib = int(facts.get("disk_free_kib") or 0) / 1048576
    add(
        "disk",
        disk_gib >= floor["min_disk_free_gib"],
        f"{disk_gib:.0f} GiB free (need {floor['min_disk_free_gib']})",
    )

    on_interface = host.address in facts.get("ipv4", "").split()
    add(
        "address",
        on_interface,
        f"{host.address} on interface"
        if on_interface
        else f"{host.address} not on any interface ({facts.get('ipv4', '').strip()}): behind NAT, forward the UDP ports",
        warn=True,
    )
    daemon, _, selected = facts.get("ntp_source", "none:0").partition(":")
    has_source = selected.isdigit() and int(selected) > 0
    add(
        "time",
        facts.get("ntp") == "yes" and has_source,
        f"NTPSynchronized={facts.get('ntp')}, {daemon} selected sources={selected or 0}"
        + (
            ""
            if has_source
            else " (no server in use: check the daemon's servers and IPv4/IPv6 reachability)"
        ),
    )

    ports = role_udp_ports(host.roles, profile)
    state, rules = parse_ufw(facts.get("ufw", ""))
    if state == "active":
        missing = [p for p in ports if not ufw_allows(rules, p, "udp")]
        console = profile["ports"]["console_tcp"]
        console_open = ufw_allows(rules, console, "tcp")
        detail = "active"
        if missing:
            detail += f"; UDP not allowed: {missing}"
        if console_open:
            detail += f"; console TCP {console} is allowed from outside"
        add("ufw", not missing and not console_open, detail)
    else:
        add("ufw", False, f"{state}: no host firewall; apply firewall/tos-testnet.nft", warn=True)

    listeners = facts.get("udp_listen", "").split()
    busy = []
    for port in ports:
        for entry in listeners:
            addr, _, proc = entry.partition("@")
            # ss shows at most 15 characters of a process name: "validator-engin".
            if addr.rsplit(":", 1)[-1] == str(port) and not re.search(
                r'"(validator-engin|dht-server)', proc
            ):
                busy.append(f"{port} by {proc}")
    add("ports", not busy, "free or held by a TOS node" if not busy else f"in use: {busy}")
    return out


# ---------------------------------------------------------------- UDP reachability


def capture_command(ports: list[int], seconds: int) -> str:
    port_expr = " or ".join(f"dst port {p}" for p in ports)
    return (
        f"timeout {seconds} tcpdump -n -l -A -i any "
        f"'udp and ({port_expr}) and {PROBE_MAGIC_BPF}' 2>/dev/null; true"
    )


def probe_command(sender: str, targets: list[tuple[str, int]]) -> str:
    pairs = " ".join(f"{addr}:{port}" for addr, port in targets)
    code = (
        "import socket,sys,time\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
        f"for _ in range({PROBE_REPEATS}):\n"
        "  for t in sys.argv[2:]:\n"
        "    a,p=t.rsplit(':',1)\n"
        "    s.sendto(('PROB:%s:%s' % (sys.argv[1], p)).encode(), (a, int(p)))\n"
        "  time.sleep(0.3)\n"
    )
    return f'python3 -c "{code}" {sender} {pairs}'


def received_probes(capture: str) -> set[tuple[str, int]]:
    """(sender, port) pairs whose probe payload appears in a tcpdump -A capture."""
    return {
        (m.group(1), int(m.group(2))) for m in re.finditer(r"PROB:([A-Za-z0-9_.-]+):(\d+)", capture)
    }


def check_udp(hosts: list[Host], profile: dict, run: Runner) -> list[Result]:
    captures: dict[str, str] = {}
    lock = threading.Lock()

    def capture(target: Host) -> None:
        ports = role_udp_ports(target.roles, profile)
        proc = run(target, capture_command(ports, CAPTURE_SECONDS), CAPTURE_SECONDS + 20)
        with lock:
            captures[target.name] = proc.stdout

    threads = [threading.Thread(target=capture, args=(h,)) for h in hosts]
    for thread in threads:
        thread.start()
    time.sleep(4)  # let every capture start before the first probe
    with ThreadPoolExecutor(max_workers=len(hosts)) as pool:
        for sender in hosts:
            targets = [
                (t.address, p)
                for t in hosts
                if t is not sender
                for p in role_udp_ports(t.roles, profile)
            ]
            if targets:
                pool.submit(run, sender, probe_command(sender.name, targets), 30)
    for thread in threads:
        thread.join()

    out = []
    for target in hosts:
        got = received_probes(captures.get(target.name, ""))
        for port in role_udp_ports(target.roles, profile):
            missing = [s.name for s in hosts if s is not target and (s.name, port) not in got]
            if missing:
                detail = f"UDP {port} not reached from {missing}: dropped before the host (provider security group, ACL or routing)"
            else:
                detail = f"UDP {port} reached from every other host"
            out.append(Result(target.name, f"udp:{port}", "FAIL" if missing else "PASS", detail))
    return out


# ---------------------------------------------------------------- main


def run_preflight(
    hosts: list[Host], profile: dict, run: Runner, install_tools: bool
) -> list[Result]:
    results: list[Result] = []
    facts: dict[str, dict[str, str]] = {}

    def gather(host: Host) -> None:
        try:
            proc = run(host, FACTS_SCRIPT, 60)
        except subprocess.TimeoutExpired:
            results.append(Result(host.name, "ssh", "FAIL", "timed out"))
            return
        if proc.returncode != 0 and not proc.stdout:
            results.append(
                Result(host.name, "ssh", "FAIL", (proc.stderr.strip() or "no answer")[:200])
            )
            return
        results.append(Result(host.name, "ssh", "PASS", f"{host.ssh_user}@{host.address}"))
        facts[host.name] = parse_facts(proc.stdout)

    with ThreadPoolExecutor(max_workers=len(hosts)) as pool:
        list(pool.map(gather, hosts))

    reachable = [h for h in hosts if h.name in facts]
    for host in reachable:
        if not facts[host.name].get("tcpdump") and install_tools:
            run(
                host,
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump >/dev/null 2>&1",
                300,
            )
            facts[host.name]["tcpdump"] = "installed"
        results.extend(evaluate_host(host, facts[host.name], profile))

    lacking = [
        h.name
        for h in reachable
        if not facts[h.name].get("tcpdump") or not facts[h.name].get("python3")
    ]
    if lacking:
        results.append(
            Result(
                ",".join(lacking),
                "udp",
                "FAIL",
                "tcpdump or python3 missing; rerun with --install-tools",
            )
        )
    elif len(reachable) >= 2:
        results.extend(check_udp(reachable, profile, run))
    return results


def report(results: list[Result]) -> str:
    order = {"FAIL": 0, "WAIVED": 1, "WARN": 2, "PASS": 3}
    lines = []
    for r in sorted(results, key=lambda r: (r.host, order[r.status], r.check)):
        lines.append(f"{r.status:4}  {r.host:<12} {r.check:<10} {r.detail}")
    counts = {s: sum(r.status == s for r in results) for s in order}
    summary = f"\n{counts['PASS']} passed, {counts['WARN']} warnings, {counts['FAIL']} failed"
    if counts["WAIVED"]:
        summary += f", {counts['WAIVED']} waived"
    lines.append(summary)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--profile", type=Path, default=lib.PROFILE_PATH)
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    parser.add_argument(
        "--accept-new-host-keys",
        action="store_true",
        help="accept a first-seen SSH host key (a changed key is still refused)",
    )
    parser.add_argument(
        "--install-tools", action="store_true", help="install tcpdump where it is missing"
    )
    args = parser.parse_args(argv)
    try:
        profile = lib.load_profile(args.profile)
        hosts = load_inventory(args.inventory)
    except (lib.TestnetError, KeyError, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    results = run_preflight(
        hosts, profile, make_runner(args.accept_new_host_keys), args.install_tools
    )
    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        print(report(results))
    return 1 if any(r.status == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
