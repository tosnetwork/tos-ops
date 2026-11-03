#!/usr/bin/env python3
"""Install a reviewed root snapshot and enable existing contact units without restarts."""

import argparse
import hashlib
import os
import pwd
import shutil
import subprocess
from pathlib import Path


def run(*args):
    subprocess.run(list(args), check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--user", required=True)
    p.add_argument("--source-sha256", required=True)
    p.add_argument("--unit-sha256", required=True)
    a = p.parse_args()
    assert os.geteuid() == 0, "root installer required"
    account = pwd.getpwnam(a.user)
    assert account.pw_uid > 0 and a.user.replace("-", "").replace("_", "").isalnum()
    root = Path(__file__).resolve().parent
    source = root / "host-monitor.py"
    unit = root / "tos-host-monitor.service"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == a.source_sha256
    assert hashlib.sha256(unit.read_bytes()).hexdigest() == a.unit_sha256
    target = Path("/usr/local/lib/tos-host-monitor")
    target.mkdir(mode=0o755, exist_ok=True)
    installed = target / "host-monitor.py"
    system_unit = Path("/etc/systemd/system/tos-host-monitor.service")
    assert not installed.exists() and not system_unit.exists(), (
        "existing deployment: review upgrade separately"
    )
    shutil.copyfile(source, installed)
    installed.chmod(0o755)
    with system_unit.open("x") as output:
        output.write(unit.read_text().replace("@USER@", a.user))
    system_unit.chmod(0o644)
    state = Path("/var/lib/tos-host-monitor")
    state.mkdir(mode=0o755, exist_ok=True)
    run("loginctl", "enable-linger", a.user)
    run(
        "systemctl",
        "enable",
        "ssh.service",
        "tailscaled.service",
        "systemd-networkd.service",
        "systemd-resolved.service",
        "tos-nic-watchdog.service",
    )
    runtime = f"/run/user/{account.pw_uid}"
    user = [
        "runuser",
        "-u",
        a.user,
        "--",
        "env",
        f"XDG_RUNTIME_DIR={runtime}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus",
        "systemctl",
        "--user",
    ]
    run(
        *user,
        "enable",
        "con01-tun-node1.service",
        "con01-tun-node3.service",
        "con01-tun-node5-8081.service",
        "e6-br1-proof-tunnel.service",
    )
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", "tos-host-monitor.service")


if __name__ == "__main__":
    main()
