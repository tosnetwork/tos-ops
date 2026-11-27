"""The operator incident resolution: one latched incident, archived only when the
checker's current report is fresh, consistent and clear, with a hashed record."""

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest
from test_check_settlement import NOW, fixture, monitor

SPEC = importlib.util.spec_from_file_location(
    "incident_resolver",
    Path(
        os.environ.get(
            "TOS_SETTLEMENT_RESOLVE",
            Path(__file__).parents[1] / "scripts/resolve-settlement-incident.py",
        )
    ),
)
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)

PAUSED = "usdt:token_paused"
DESTROYED = "usdc:destroyed_funds"
REASON = "issuer unpaused at source block 812; reviewed by the operator"


class Monitor:
    """A checker state built by the real checker: two latched incidents."""

    def __init__(self, tmp_path, monkeypatch):
        self.tmp = tmp_path
        self.state = tmp_path / "state"
        self.policy_file = tmp_path / "policy.json"
        self.snapshot_file = tmp_path / "snapshot.json"
        self.record = tmp_path / "evidence" / "resolution.json"
        self.record.parent.mkdir()
        self.policy, self.snapshot = fixture()
        self.policy_file.write_text(json.dumps(self.policy))
        self.height = 100
        monkeypatch.setattr(monitor.time, "time", lambda: NOW)
        monkeypatch.setattr(resolver.time, "time", lambda: NOW)
        assert self.sample(initialize=True) == 2
        assert self.sample() == 0
        self.snapshot["assets"][1]["paused"] = True
        self.snapshot["assets"][0]["destroy_events"] = 1
        assert self.sample() == 1
        assert sorted(self.incidents()) == [DESTROYED, PAUSED]

    def sample(self, initialize=False):
        self.snapshot["checkpoint"].update(height=self.height, hash=f"{self.height:064x}")
        self.height += 1
        self.snapshot_file.write_text(json.dumps(self.snapshot))
        args = ["--policy", str(self.policy_file), "--snapshot", str(self.snapshot_file)]
        args += ["--state-dir", str(self.state)]
        return monitor.main(args + (["--initialize-baseline"] if initialize else []))

    def clear(self):
        self.snapshot["assets"][1]["paused"] = False
        self.snapshot["assets"][0]["destroy_events"] = 0
        assert self.sample() == 1  # still latched

    def incidents(self):
        return monitor.read_json(self.state / "incidents.json")

    def edit(self, name, change):
        path = self.state / name
        value = monitor.read_json(path)
        change(value)
        path.write_text(json.dumps(value, sort_keys=True) + "\n")

    def resolve(self, incident=PAUSED, reason=REASON, record=None):
        return resolver.main(
            [
                "--state-dir",
                str(self.state),
                "--policy",
                str(self.policy_file),
                "--incident",
                incident,
                "--reason",
                reason,
                "--record",
                str(record or self.record),
            ]
        )


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_resolution_removes_only_the_named_incident_and_records_both_hashes(
    tmp_path, monkeypatch, capsys
):
    m = Monitor(tmp_path, monkeypatch)
    m.clear()
    before = sha256(m.state / "incidents.json")
    report = sha256(m.state / "report.json")
    capsys.readouterr()
    assert m.resolve() == 0
    printed = json.loads(capsys.readouterr().out)
    record = monitor.read_json(m.record)
    assert record == printed
    assert record["schema"] == "tos-settlement-incident-resolution/1"
    assert record["incident"] == PAUSED
    assert record["removed"]["alarm"]["code"] == "token_paused"
    assert record["incidents_sha256_before"] == before
    assert record["incidents_sha256_after"] == sha256(m.state / "incidents.json") != before
    assert record["report_sha256"] == report
    assert record["report_checkpoint"]["height"] == m.height - 1
    assert record["reason"] == REASON and record["time_unix"] == NOW
    assert record["remaining_incidents"] == [DESTROYED]
    assert sorted(m.incidents()) == [DESTROYED]
    # The checker keeps the other asset's latch and pause hook.
    capsys.readouterr()
    assert m.sample() == 1
    report = json.loads(capsys.readouterr().out)
    assert report["latched_incidents"] == [DESTROYED]
    assert report["provider_pause_assets"] == ["usdc"]
    # The second incident resolves in turn; the checker is clear again.
    assert m.resolve(DESTROYED, record=tmp_path / "evidence/second.json") == 0
    assert m.incidents() == {}
    assert m.sample() == 0


def test_a_recurring_condition_latches_again_after_resolution(tmp_path, monkeypatch):
    m = Monitor(tmp_path, monkeypatch)
    m.clear()
    assert m.resolve() == 0
    m.snapshot["assets"][1]["paused"] = True
    assert m.sample() == 1
    assert PAUSED in m.incidents()


def hold_lock(m, monkeypatch):
    # Another holder of the monitor lock, as a running checker would be.
    m.held = open(m.state / "monitor.lock", "a")
    fcntl.flock(m.held, fcntl.LOCK_EX | fcntl.LOCK_NB)


REFUSALS = {
    "reason-empty": (lambda m, mp: None, dict(reason=" "), "reason is empty"),
    "reason-control": (lambda m, mp: None, dict(reason="ok\nforged: yes"), "control characters"),
    "not-private": (lambda m, mp: m.state.chmod(0o755), {}, "not private"),
    "record-exists": (lambda m, mp: m.record.write_text("{}"), {}, "record exists"),
    "record-in-state": (
        lambda m, mp: None,
        dict(record="STATE/resolution.json"),
        "outside the monitor state",
    ),
    "lock-held": (hold_lock, {}, "Resource temporarily unavailable"),
    "absent": (lambda m, mp: None, dict(incident="usdt:bridge_frozen"), "not latched"),
    "key-mismatch": (
        lambda m, mp: m.edit("incidents.json", lambda v: v.update({"usdt:x": v[PAUSED]})),
        dict(incident="usdt:x"),
        "does not match its alarm",
    ),
    "not-emergency": (
        lambda m, mp: m.edit(
            "incidents.json",
            lambda v: v.update(
                {
                    "usdt:transfer_fee": dict(
                        v[PAUSED], alarm=dict(asset="usdt", code="transfer_fee")
                    )
                }
            ),
        ),
        dict(incident="usdt:transfer_fee"),
        "not an emergency latch",
    ),
    "stale": (
        lambda m, mp: m.edit("report.json", lambda v: v.update(status="STALE")),
        {},
        "stale or incomplete",
    ),
    "baseline": (
        lambda m, mp: m.edit("report.json", lambda v: v.update(baseline=True)),
        {},
        "checked no interval",
    ),
    "inconsistent": (
        lambda m, mp: m.edit("report.json", lambda v: v.update(latched_incidents=[PAUSED])),
        {},
        "predates incidents",
    ),
    "too-old": (
        lambda m, mp: mp.setattr(resolver.time, "time", lambda: NOW + 121),
        {},
        "too old",
    ),
    "precedes": (
        lambda m, mp: m.edit(
            "incidents.json", lambda v: v[PAUSED]["checkpoint"].update(height=m.height)
        ),
        {},
        "does not follow the incident",
    ),
    "still-alarmed": (
        lambda m, mp: (m.snapshot["assets"][1].update(paused=True), m.sample()),
        {},
        "still alarmed",
    ),
}


@pytest.mark.parametrize("label", sorted(REFUSALS))
def test_each_refusal_changes_nothing(tmp_path, monkeypatch, capsys, label):
    setup, overrides, message = REFUSALS[label]
    m = Monitor(tmp_path, monkeypatch)
    m.clear()
    setup(m, monkeypatch)
    if overrides.get("record") == "STATE/resolution.json":
        overrides = dict(record=m.state / "resolution.json")
    incidents = (m.state / "incidents.json").read_bytes()
    report = (m.state / "report.json").read_bytes()
    capsys.readouterr()
    code = m.resolve(**overrides)
    out = json.loads(capsys.readouterr().out)
    assert code == 2 and out["result"] == "refused", "refusal did not refuse: " + label
    assert message in out["reason"], "wrong refusal: " + out["reason"]
    assert (m.state / "incidents.json").read_bytes() == incidents
    assert (m.state / "report.json").read_bytes() == report
    assert not (m.state / "resolution.json").exists()
    if label != "record-exists":
        assert not m.record.exists()
