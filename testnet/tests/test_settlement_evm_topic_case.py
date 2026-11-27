"""Valid hex letter case cannot hide an issuer event."""

import importlib.util
import os
from pathlib import Path

import pytest

SOURCE = Path(
    os.environ.get(
        "TOS_SETTLEMENT_COLLECTOR",
        Path(__file__).resolve().parents[1] / "scripts/collect-settlement-evm.py",
    )
)
SPEC = importlib.util.spec_from_file_location("source_event_cases", SOURCE)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


@pytest.mark.parametrize(
    "kind,data,counts",
    [
        ("Pause", "0x", (1, 0)),
        ("DestroyedBlackFunds", "0x" + "00" * 12 + "cd" * 20 + "00" * 31 + "01", (0, 1)),
    ],
)
def test_valid_uppercase_event_topic_is_not_ignored(kind, data, counts):
    token, bridge = "0x" + "ab" * 20, "0x" + "cd" * 20
    topic = "0x" + collector.TOPICS[kind][2:].upper()
    events, pauses, destroys = collector.asset_events(
        [dict(address=token, topics=[topic], data=data)], token, bridge
    )
    assert not events
    assert (pauses, destroys) == counts, "valid uppercase event topic ignored"
