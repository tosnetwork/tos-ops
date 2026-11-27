"""The operator incident resolution: one latched incident, archived only when the
checker's current report is fresh, consistent and clear, with a hashed record."""

import errno
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

    def race(self):
        # A competing writer creates the record once the checks have passed.
        if not self.record.exists():
            self.record.write_text("{}")
        return NOW

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
        lambda m: dict(record=m.state / "resolution.json"),
        "outside the monitor state",
    ),
    "record-dir-missing": (
        lambda m, mp: None,
        lambda m: dict(record=m.record.parent / "missing" / "resolution.json"),
        "missing or not writable",
    ),
    "record-dir-unwritable": (
        lambda m, mp: m.record.parent.chmod(0o500),
        {},
        "missing or not writable",
    ),
    # The record appears after the existence check, before the exclusive create.
    "record-race": (lambda m, mp: mp.setattr(resolver.time, "time", m.race), {}, "File exists"),
    "incidents-not-object": (
        lambda m, mp: (m.state / "incidents.json").write_text("[]\n"),
        {},
        "not an object",
    ),
    "report-missing": (
        lambda m, mp: (m.state / "report.json").rename(m.tmp / "report.moved"),
        {},
        "no current report",
    ),
    "report-schema": (
        lambda m, mp: m.edit("report.json", lambda v: v.update(schema="tos-settlement-report/2")),
        {},
        "schema differs",
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
    if callable(overrides):
        overrides = overrides(m)
    incidents = (m.state / "incidents.json").read_bytes()
    report = m.state / "report.json"
    report_bytes = report.read_bytes() if report.exists() else None
    capsys.readouterr()
    code = m.resolve(**overrides)
    out = json.loads(capsys.readouterr().out)
    assert code == 2 and out["result"] == "refused", "refusal did not refuse: " + label
    assert message in out["reason"], "wrong refusal: " + out["reason"]
    assert (m.state / "incidents.json").read_bytes() == incidents
    assert (report.read_bytes() if report.exists() else None) == report_bytes
    assert not (m.state / "resolution.json").exists()
    if label in ("record-exists", "record-race"):
        assert m.record.read_text() == "{}", "an existing record was overwritten"
    else:
        assert not m.record.exists()
    assert list(m.record.parent.iterdir()) == ([m.record] if m.record.exists() else [])


def enospc(*_args, **_kwargs):
    raise OSError(errno.ENOSPC, "No space left on device")


def half_then_enospc(fd, data):
    os.write(fd, data[: len(data) // 2])
    enospc()


def test_a_failed_record_write_changes_nothing(tmp_path, monkeypatch, capsys):
    m = Monitor(tmp_path, monkeypatch)
    m.clear()
    incidents = (m.state / "incidents.json").read_bytes()
    monkeypatch.setattr(resolver, "write_all", half_then_enospc)
    capsys.readouterr()
    assert m.resolve() == 2
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "refused" and "No space left" in out["reason"]
    assert (m.state / "incidents.json").read_bytes() == incidents, "incident removed first"
    assert not m.record.exists(), "partial record left behind"


def test_a_record_that_cannot_be_cleaned_up_is_partial(tmp_path, monkeypatch, capsys):
    m = Monitor(tmp_path, monkeypatch)
    m.clear()
    incidents = (m.state / "incidents.json").read_bytes()
    unlink = os.unlink

    def refuse_record(path, *args, **kwargs):
        if Path(path) == m.record:
            enospc()
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(resolver, "write_all", half_then_enospc)
    monkeypatch.setattr(resolver.os, "unlink", refuse_record)
    capsys.readouterr()
    assert m.resolve() == 3
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "partial" and "partial file was left" in out["what"]
    assert out["record"] == str(m.record)
    assert (m.state / "incidents.json").read_bytes() == incidents


def test_a_replace_that_fails_before_replacing_withdraws_the_record(tmp_path, monkeypatch, capsys):
    m = Monitor(tmp_path, monkeypatch)
    m.clear()
    incidents = (m.state / "incidents.json").read_bytes()
    monkeypatch.setattr(resolver.monitor, "atomic", enospc)
    capsys.readouterr()
    assert m.resolve() == 2
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "refused" and "No space left" in out["reason"]
    assert (m.state / "incidents.json").read_bytes() == incidents
    assert not m.record.exists(), "record of an unapplied resolution was kept"


def test_a_failure_after_the_replace_is_partial_not_refused(tmp_path, monkeypatch, capsys):
    m = Monitor(tmp_path, monkeypatch)
    m.clear()
    atomic = resolver.monitor.atomic

    def replace_then_fail(path, value):
        atomic(path, value)
        raise OSError(errno.EIO, "directory fsync failed")

    monkeypatch.setattr(resolver.monitor, "atomic", replace_then_fail)
    capsys.readouterr()
    code = m.resolve()
    out = json.loads(capsys.readouterr().out)
    assert code == 3 and out["result"] == "partial", "a change was reported as refused"
    assert "was replaced" in out["what"] and "directory fsync failed" in out["error"]
    record = monitor.read_json(m.record)
    current = sha256(m.state / "incidents.json")
    assert out["incidents_sha256_current"] == current == record["incidents_sha256_after"]
    assert sorted(m.incidents()) == [DESTROYED]


def test_a_replace_that_does_not_read_back_is_partial(tmp_path, monkeypatch, capsys):
    m = Monitor(tmp_path, monkeypatch)
    m.clear()
    atomic = resolver.monitor.atomic

    def replace_with_other(path, value):
        atomic(path, dict(value, other={}))

    monkeypatch.setattr(resolver.monitor, "atomic", replace_with_other)
    capsys.readouterr()
    assert m.resolve() == 3
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "partial" and "does not read back" in out["what"]
    assert out["incidents_sha256_after"] == monitor.read_json(m.record)["incidents_sha256_after"]
    assert out["incidents_sha256_current"] != out["incidents_sha256_after"]
