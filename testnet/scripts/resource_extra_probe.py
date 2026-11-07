"""Read-only resource baselines; intentionally no environments or command lines."""

from pathlib import Path  # noqa: I001 -- import order kept from the deployed probe
import json
import os
import subprocess
import time

unit = "tos-testnet-validator.service"
rows = subprocess.check_output(
    [
        "systemctl",
        "show",
        unit,
        "-p",
        "ActiveState",
        "-p",
        "MainPID",
        "-p",
        "NRestarts",
        "-p",
        "ControlGroup",
    ],
    text=True,
    timeout=10,
)
props = dict(row.split("=", 1) for row in rows.splitlines())
if props["ActiveState"] != "active" or int(props["MainPID"]) <= 0:
    # An inactive validator is an observation the watcher records, not a failed read.
    print(
        json.dumps(
            {
                "utc_unix": time.time(),
                "unit": unit,
                "unit_active": props["ActiveState"],
                "main_pid": int(props["MainPID"]),
                "unit_restarts": int(props["NRestarts"]),
                "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "host_oom_kill": int(
                    dict(row.split() for row in Path("/proc/vmstat").read_text().splitlines())[
                        "oom_kill"
                    ]
                ),
            }
        )
    )
    raise SystemExit(0)
pid = props["MainPID"]
cgroup = Path("/sys/fs/cgroup") / props["ControlGroup"].lstrip("/")
assert cgroup.resolve().is_relative_to(Path("/sys/fs/cgroup"))
events = dict(row.split() for row in (cgroup / "memory.events").read_text().splitlines())
vm = dict(row.split() for row in Path("/proc/vmstat").read_text().splitlines())
process = Path("/proc") / pid
stat_fields = (process / "stat").read_text().rsplit(")", 1)[1].split()
filesystems = {}
for name in ["/var/lib/tos", "/var/log/tos", "/tmp"]:
    filesystem = os.statvfs(name)
    filesystems[name] = {
        "free_bytes": filesystem.f_bavail * filesystem.f_frsize,
        "free_inodes": filesystem.f_favail,
        "total_inodes": filesystem.f_files,
    }
print(
    json.dumps(
        {
            "utc_unix": time.time(),
            "unit": unit,
            "unit_active": props["ActiveState"],
            "main_pid": int(pid),
            "unit_restarts": int(props["NRestarts"]),
            "start_ticks": int(stat_fields[19]),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "open_fd_count": sum(1 for _ in (process / "fd").iterdir()),
            "cgroup_memory_events": {key: int(value) for key, value in events.items()},
            "host_oom_kill": int(vm["oom_kill"]),
            "filesystems": filesystems,
        }
    )
)
