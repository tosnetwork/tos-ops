"""Poll/capture horizon rejection must precede signing and acquisition."""

import importlib.util
import threading
from types import SimpleNamespace

import pytest
import testnet_lib as lib
from conftest import SCRIPTS

spec = importlib.util.spec_from_file_location(
    "native_poll_elections", SCRIPTS / "testnet-elections.py"
)
elections = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elections)


@pytest.mark.parametrize(
    "duration,interval,expected",
    [
        (120, None, (2, 460)),
        (120, 0.5, (0.5, 1540)),
        (259200, 0.5, (0.5, 519700)),
        (259200, None, (2, 130000)),
    ],
)
def test_capture_budget_matches_poll_cadence(duration, interval, expected):
    assert elections.native_capture_policy(duration, interval) == expected


@pytest.mark.parametrize(
    "duration,interval",
    [
        (True, 0.5),
        (0, 0.5),
        (-1, 0.5),
        (float("nan"), 0.5),
        (120, True),
        (120, 0),
        (120, 0.09),
        (120, 11),
        (120, float("nan")),
        (120, float("inf")),
    ],
)
def test_invalid_poll_policy_refused(duration, interval):
    with pytest.raises(lib.TestnetError, match="native poll"):
        elections.native_capture_policy(duration, interval)


@pytest.mark.parametrize("duration,interval", [(259200, 0.1), (1e308, 0.5)])
def test_unsupported_horizon_is_rejected_not_clamped(duration, interval):
    with pytest.raises(lib.TestnetError, match="capture-count budget"):
        elections.native_capture_policy(duration, interval)


def test_poll_option_without_native_mode_refused_before_other_arguments():
    with pytest.raises(lib.TestnetError, match="native options"):
        elections.check_load_args(SimpleNamespace(native_finality=False, native_poll_seconds=0.5))


@pytest.mark.parametrize("cutoff", [None, "not-offered"])
def test_factory_passes_same_cadence_to_worker_and_collector(tmp_path, monkeypatch, cutoff):
    import load_finality_collector
    import load_native_observer

    received, order = {}, []

    def collector(**fields):
        received["collector"] = fields
        return object()

    class Observer:
        def __init__(self, _collector, _record, _halt, **fields):
            received["worker"] = fields

        def bootstrap(self):
            order.append("baseline")

        def start(self):
            order.append("start")

    monkeypatch.setattr(load_finality_collector, "NativeCollector", collector)
    monkeypatch.setattr(load_native_observer, "NativeObserver", Observer)
    obj = object.__new__(elections.LoadDriver)
    obj.args = SimpleNamespace(
        duration=120,
        native_poll_seconds=0.5,
        native_verifier="helper",
        native_verifier_sha256="11" * 32,
        native_anchor="anchor",
        native_anchor_sha256="22" * 32,
        native_liteserver="lite",
        native_wallet_code_hash="33" * 32,
        rpc="rpc",
        confirm_rpc="confirm-rpc",
    )
    obj.args.native_cutoff_policy = cutoff
    obj.args.native_slo_population = "fixed-stage" if cutoff else None
    obj.global_id = 2
    obj.qualification = SimpleNamespace(
        guard=threading.RLock(),
        run=tmp_path,
        halt=lambda _: None,
        event=lambda *a, **k: None,
        attach_native=lambda _: order.append("attach"),
    )
    obj.start_native_observer("public-wallet")
    assert received["collector"]["confirm_rpc"] == "confirm-rpc"
    assert received["collector"]["max_captures"] == 1540
    assert received["worker"]["interval"] == 0.5
    assert received["worker"]["cutoff_policy"] == (cutoff or "fail")
    assert order == ["baseline", "attach", "start"]


def test_slo_option_without_native_mode_refused():
    with pytest.raises(lib.TestnetError, match="native options"):
        elections.check_load_args(
            SimpleNamespace(native_finality=False, native_slo_population="fixed-stage")
        )


def test_cutoff_option_requires_native_fixed_population():
    with pytest.raises(lib.TestnetError, match="native options"):
        elections.check_load_args(
            SimpleNamespace(native_finality=False, native_cutoff_policy="not-offered")
        )
    with pytest.raises(lib.TestnetError, match="requires fixed-stage"):
        elections.check_load_args(
            SimpleNamespace(native_finality=True, duration=120, native_cutoff_policy="not-offered")
        )
