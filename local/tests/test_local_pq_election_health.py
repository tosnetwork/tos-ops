import importlib.util
import json
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
spec = importlib.util.spec_from_file_location(
    "health", SCRIPTS.joinpath("check-local-pq-elections.py")
)
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)
NOW = 1800000000


def fixture(directory):
    (directory / "status.json").write_text(
        json.dumps(dict(at=NOW, healthy=True, activation_since=NOW - 100))
    )
    (directory / f"activation-{NOW - 100}.json").write_text(
        json.dumps(dict(config34=dict(utime_until=NOW + 500)))
    )
    for index in (1, 2, 3, 4, 7):
        (directory / f"wallet-{index}.json").write_text(
            json.dumps(dict(deployed=True, checked_at=NOW, balance=10**9, returned_stake=0))
        )


def test_healthy_persistent_driver(tmp_path):
    fixture(tmp_path)
    value = health.check(tmp_path, NOW)
    assert value["healthy"] and not value["warnings"]


@pytest.mark.parametrize(
    "fault", ["stale", "failure", "expired_set", "missing", "old_wallet", "undeployed", "future"]
)
def test_liveness_failures_are_visible(tmp_path, fault):
    fixture(tmp_path)
    if fault in ("stale", "failure"):
        (tmp_path / "status.json").write_text(
            json.dumps(dict(at=NOW - 181 if fault == "stale" else NOW, healthy=fault != "failure"))
        )
    if fault == "expired_set":
        (tmp_path / f"activation-{NOW - 100}.json").write_text(
            json.dumps(dict(config34=dict(utime_until=NOW - 1)))
        )
    if fault == "missing":
        (tmp_path / "wallet-7.json").unlink()
    if fault in ("old_wallet", "undeployed", "future"):
        row = json.loads((tmp_path / "wallet-1.json").read_text())
        if fault == "old_wallet":
            row["checked_at"] = NOW - health.WALLET_OBSERVATION_MAX_AGE - 1
        elif fault == "future":
            row["checked_at"] = NOW + 10
        else:
            row["deployed"] = False
        (tmp_path / "wallet-1.json").write_text(json.dumps(row))
    assert not health.check(tmp_path, NOW)["healthy"]


def test_a_returned_stake_awaiting_recovery_is_not_a_fault(tmp_path):
    fixture(tmp_path)
    row = json.loads((tmp_path / "wallet-1.json").read_text())
    row["returned_stake"] = 11 * 10**12
    (tmp_path / "wallet-1.json").write_text(json.dumps(row))
    result = health.check(tmp_path, NOW)
    assert result["healthy"] and not result["warnings"]
