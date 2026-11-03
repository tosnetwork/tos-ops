#!/usr/bin/env python3
"""Bounded host/contact supervision; never restart a payment, validator or host."""

import argparse
import fcntl
import json
import os
import pwd
import subprocess
import tempfile
import time
from pathlib import Path

SYSTEM_UNITS = (
    "systemd-networkd.service",
    "systemd-resolved.service",
    "ssh.service",
    "tailscaled.service",
    "tos-nic-watchdog.service",
)
USER_UNITS = (
    "con01-tun-node1.service",
    "con01-tun-node3.service",
    "con01-tun-node5-8081.service",
    "e6-br1-proof-tunnel.service",
)
OBSERVE_USER_UNITS = ("e6-br1-public-pilot.timer", "e6-br1-public-pilot.service")
MAX_OUTPUT = 256 * 1024


def command(argv, timeout=10):
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        if len(result.stdout) > MAX_OUTPUT:
            return 125, ""
        return result.returncode, result.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return 124, ""
    except OSError:
        return 126, ""


def unit_status(prefix, unit):
    rc, text = command(
        [*prefix, "show", unit, "-p", "ActiveState", "-p", "UnitFileState"]
    )
    fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    return dict(
        active=fields.get("ActiveState", "unknown"),
        enabled=fields.get("UnitFileState", "unknown"),
        query_exit=rc,
    )


def user_control(user):
    account = pwd.getpwnam(user)
    runtime = f"/run/user/{account.pw_uid}"
    return [
        "/usr/sbin/runuser",
        "-u",
        user,
        "--",
        "/usr/bin/env",
        f"XDG_RUNTIME_DIR={runtime}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus",
        "/usr/bin/systemctl",
        "--user",
    ]


def recovery_action(unit, status, last, now, *, overlay_failures=0):
    """Only stopped contact services start; unhealthy local overlay API may restart."""
    allowed = set(SYSTEM_UNITS) | set(USER_UNITS)
    manager = (
        unit.startswith("user@") and unit.endswith(".service") and unit[5:-8].isdigit()
    )
    if unit not in allowed and not manager:
        return None
    if now - last < 120:
        return None
    if status["active"] in {"inactive", "failed"}:
        return "start"
    if (
        unit == "tailscaled.service"
        and status["active"] == "active"
        and overlay_failures >= 3
    ):
        return "restart"
    return None


def overlay_status():
    rc, text = command(["/usr/bin/tailscale", "status", "--json"], timeout=8)
    try:
        result = json.loads(text) if rc == 0 else {}
        state = result.get("BackendState", "unavailable")
        online = result.get("Self", {}).get("Online", False)
        # Do not retain peers, IPs, login URLs, users, tokens or raw stderr.
        return dict(
            query_exit=rc,
            state=state,
            online=online is True,
            locally_unhealthy=rc != 0 or state == "Stopped",
        )
    except (ValueError, AttributeError):
        return dict(
            query_exit=125, state="unavailable", online=False, locally_unhealthy=True
        )


def netcheck():
    rc, text = command(["/usr/bin/tailscale", "netcheck", "--format=json"], timeout=12)
    try:
        value = json.loads(text) if rc == 0 else {}
        latencies = value.get("RegionLatency", {})
        return dict(
            query_exit=rc,
            udp=value.get("UDP") is True,
            ipv4=value.get("IPv4") is True,
            relay_reachable=isinstance(latencies, dict) and bool(latencies),
        )
    except (ValueError, AttributeError):
        return dict(query_exit=125, udp=False, ipv4=False, relay_reachable=False)


def metrics():
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in {"MemTotal", "MemAvailable"}:
            memory[key] = int(value.split()[0]) * 1024
    disks = {}
    for name in ("/", "/tos", "/datax"):
        if Path(name).exists():
            st = os.statvfs(name)
            disks[name] = dict(
                available=st.f_bavail * st.f_frsize, total=st.f_blocks * st.f_frsize
            )
    temperatures = []
    for path in Path("/sys/class/hwmon").glob("hwmon*/temp*_input"):
        try:
            value = int(path.read_text()) / 1000
            if 0 < value < 150:
                temperatures.append(value)
        except (OSError, ValueError):
            pass
    return dict(
        memory=memory,
        disks=disks,
        load=os.getloadavg(),
        max_temperature_c=max(temperatures, default=None),
        uptime_seconds=float(Path("/proc/uptime").read_text().split()[0]),
    )


def atomic_json(path, value, mode):
    fd, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            os.fchmod(output.fileno(), mode)
            json.dump(value, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def poll(user, state, *, dry_run=False, probe=False):
    now = time.monotonic()
    account = pwd.getpwnam(user)
    manager = f"user@{account.pw_uid}.service"
    controls = {"system": ["/usr/bin/systemctl"], "user": user_control(user)}
    overlay = overlay_status()
    state["overlay_failures"] = (
        state.get("overlay_failures", 0) + 1 if overlay["locally_unhealthy"] else 0
    )
    observations, repairs = {}, []
    watches = [("system", u) for u in (*SYSTEM_UNITS, manager)] + [
        ("user", u) for u in USER_UNITS
    ]
    for scope, unit in watches:
        prefix = controls[scope]
        status = unit_status(prefix, unit)
        observations[unit] = status
        action = recovery_action(
            unit,
            status,
            state.setdefault("last", {}).get(unit, -1e12),
            now,
            overlay_failures=state["overlay_failures"],
        )
        if action:
            state["last"][unit] = now
            rc, _ = (
                command([*prefix, action, unit], timeout=20) if not dry_run else (0, "")
            )
            repairs.append(dict(unit=unit, action=action, exit=rc, dry_run=dry_run))
    for unit in OBSERVE_USER_UNITS:
        observations[unit] = unit_status(controls["user"], unit)
    healthy = all(
        s["active"] == "active"
        for u, s in observations.items()
        if u not in OBSERVE_USER_UNITS
    )
    resource = metrics()
    warnings = []
    mem = resource["memory"]
    if mem.get("MemAvailable", 0) < mem.get("MemTotal", 0) * 0.05:
        warnings.append("available_memory_below5percent")
    if any(d["available"] < d["total"] * 0.10 for d in resource["disks"].values()):
        warnings.append("disk_available_below10percent")
    if (resource["max_temperature_c"] or 0) >= 90:
        warnings.append("temperature_at_least90C")
    return dict(
        checked_utc=time.time(),
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        contact_services_healthy=healthy,
        overlay=overlay,
        netcheck=netcheck() if probe else None,
        metrics=resource,
        warnings=warnings,
        units=observations,
        repairs=repairs,
        value_jobs_observed_only=True,
        host_reboot_action=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user", required=True)
    parser.add_argument(
        "--state-dir", type=Path, default=Path("/var/lib/tos-host-monitor")
    )
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not 10 <= args.interval <= 300:
        parser.error("interval must be10..300seconds")
    args.state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    with (args.state_dir / "monitor.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state, previous_boot, number = {}, None, 0
        previous = args.state_dir / "status.json"
        if previous.exists():
            previous_boot = json.loads(previous.read_text()).get("boot_id")
        while True:
            value = poll(args.user, state, dry_run=args.dry_run, probe=number % 4 == 0)
            value["boot_changed"] = previous_boot not in (None, value["boot_id"])
            previous_boot = value["boot_id"]
            atomic_json(previous, value, 0o644)
            if value["repairs"] or value["boot_changed"] or number % 4 == 0:
                print(json.dumps(value, sort_keys=True), flush=True)
            if args.once:
                return
            number += 1
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
