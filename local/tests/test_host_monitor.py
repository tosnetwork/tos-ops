"""Contact recovery decisions; all service/network calls are mocked."""

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "host_monitor", Path(__file__).resolve().parents[1] / "host-monitor/host-monitor.py"
)
h = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = h
spec.loader.exec_module(h)


class Recovery(unittest.TestCase):
    def test_failed_contact_units_start(self):
        for unit in (*h.SYSTEM_UNITS, *h.USER_UNITS, "user@1000.service"):
            self.assertEqual(
                h.recovery_action(unit, {"active": "failed"}, 0, 200), "start"
            )

    def test_healthy_services_never_restart(self):
        for unit in (*h.SYSTEM_UNITS, *h.USER_UNITS):
            self.assertIsNone(h.recovery_action(unit, {"active": "active"}, 0, 200))

    def test_overlay_needs_three_local_failures(self):
        self.assertIsNone(
            h.recovery_action(
                "tailscaled.service", {"active": "active"}, 0, 200, overlay_failures=2
            )
        )
        self.assertEqual(
            h.recovery_action(
                "tailscaled.service", {"active": "active"}, 0, 200, overlay_failures=3
            ),
            "restart",
        )

    def test_cooldown_applies_to_start_and_restart(self):
        for active in ("active", "failed"):
            self.assertIsNone(
                h.recovery_action(
                    "tailscaled.service",
                    {"active": active},
                    100,
                    200,
                    overlay_failures=3,
                )
            )

    def test_payments_validators_and_pilot_timer_never_recovered(self):
        for unit in (
            "e6-br1-public-pilot.service",
            "e6-br1-public-pilot.timer",
            "tos-validator.service",
            "reboot.target",
            "other.service",
            "user@bad.service",
        ):
            self.assertIsNone(
                h.recovery_action(
                    unit, {"active": "failed"}, 0, 200, overlay_failures=99
                )
            )

    def test_starting_stopping_unknown_services_are_not_disturbed(self):
        for state in ("activating", "deactivating", "unknown"):
            self.assertIsNone(
                h.recovery_action("ssh.service", {"active": state}, 0, 200)
            )

    def test_overlay_drops_sensitive_fields(self):
        with patch.object(
            h,
            "command",
            return_value=(
                0,
                '{"BackendState":"Running","Self":{"Online":true,"TailscaleIPs":["sensitive"]},"Peer":{"secret":"ignored"}}',
            ),
        ):
            data = h.overlay_status()
        self.assertEqual(
            set(data), {"query_exit", "state", "online", "locally_unhealthy"}
        )
        self.assertNotIn("sensitive", str(data))
        self.assertFalse(data["locally_unhealthy"])

    def test_login_requirement_never_restarts_or_enrolls_overlay(self):
        with patch.object(
            h,
            "command",
            return_value=(0, '{"BackendState":"NeedsLogin","AuthURL":"secret"}'),
        ):
            data = h.overlay_status()
        self.assertFalse(data["locally_unhealthy"])
        self.assertNotIn("secret", str(data))

    def test_netcheck_failure_does_not_trigger_overlay_restart(self):
        with patch.object(h, "command", return_value=(1, "")):
            data = h.netcheck()
        self.assertFalse(data["relay_reachable"])
        self.assertIsNone(
            h.recovery_action(
                "tailscaled.service", {"active": "active"}, 0, 200, overlay_failures=0
            )
        )

    def test_dry_run_never_executes_repairs_and_only_observes_payments(self):
        def status(prefix, unit):
            return {
                "active": "failed" if unit == "ssh.service" else "active",
                "enabled": "enabled",
                "query_exit": 0,
            }

        resource = dict(
            memory={"MemAvailable": 100, "MemTotal": 100},
            disks={},
            max_temperature_c=40,
            uptime_seconds=100,
            load=(0, 0, 0),
        )
        with (
            patch.object(h, "unit_status", side_effect=status),
            patch.object(
                h, "overlay_status", return_value={"locally_unhealthy": False}
            ),
            patch.object(h, "metrics", return_value=resource),
            patch.object(h, "command") as command,
        ):
            result = h.poll("root", {}, dry_run=True)
        command.assert_not_called()
        self.assertEqual(
            result["repairs"],
            [{"unit": "ssh.service", "action": "start", "exit": 0, "dry_run": True}],
        )

    def test_atomic_snapshot_survives_complete_replace(self):
        import tempfile
        import json

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "status.json"
            h.atomic_json(path, {"boot_id": "before"}, 0o644)
            h.atomic_json(path, {"boot_id": "after"}, 0o644)
            self.assertEqual(json.loads(path.read_text()), {"boot_id": "after"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)


class Installer(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "monitor_installer",
            Path(__file__).resolve().parents[1] / "host-monitor/install.py",
        )
        self.installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.installer)

    def test_verified_snapshot_is_installed_after_source_path_changes(self):
        import hashlib
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            target = Path(directory) / "target"
            source.write_bytes(b"reviewed bytes")
            data = self.installer.verified_bytes(
                source, hashlib.sha256(b"reviewed bytes").hexdigest()
            )
            source.write_bytes(b"changed after approval")
            self.installer.install_bytes(target, data, 0o755)
            self.assertEqual(target.read_bytes(), b"reviewed bytes")

    def test_install_refuses_existing_file_or_symlink(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "existing"
            source.write_bytes(b"keep")
            link = Path(directory) / "link"
            link.symlink_to(source)
            for path in (source, link):
                with self.assertRaises(FileExistsError):
                    self.installer.install_bytes(path, b"replace", 0o755)
            self.assertEqual(source.read_bytes(), b"keep")

    def test_unreviewed_input_bytes_refuse(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"changed")
            with self.assertRaisesRegex(AssertionError, "SHA mismatch"):
                self.installer.verified_bytes(source, "0" * 64)


if __name__ == "__main__":
    unittest.main()
