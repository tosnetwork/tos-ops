"""Composition state machine only; fake codec/callback do not prove signatures."""

import json
from copy import deepcopy

import pytest
from load_finality import HistoryError
from load_finality_replay import RetainedPrefix, block_identity


class Codec:
    def serialize(self, _schema, obj):
        return json.dumps(obj, sort_keys=True).encode()

    def deserialize(self, raw):
        return json.loads(raw), len(raw)


def block(seqno, digest=None):
    return {
        "workchain": -1,
        "shard": "8000000000000000",
        "seqno": seqno,
        "root_hash": digest or f"{seqno:064x}",
        "file_hash": f"{seqno + 100:064x}",
    }


def step(a, b, key=True):
    return {
        "@type": "liteServer.blockLinkForward",
        "from": block(a),
        "to": block(b),
        "to_key_block": key,
    }


def response(*steps):
    part = {
        "@type": "liteServer.partialBlockProof",
        "complete": True,
        "from": steps[0]["from"],
        "to": steps[-1]["to"],
        "steps": list(steps),
    }
    return Codec().serialize(part["@type"], part)


def verified(target):
    return {
        "status": "verified",
        "mode": "historical",
        "anchor": block(0),
        "start": block(0),
        "target": block(target),
    }


def advance(cache, start, target, *steps, callback=None):
    return cache.advance(
        [response(*steps)],
        start=block(start),
        target=block(target),
        verify=callback or (lambda _: verified(target)),
    )


def test_prefix_extends_across_key_blocks_without_caching_nonkey_targets():
    c = RetainedPrefix(Codec(), block(0))
    advance(c, 0, 2, step(0, 1), step(1, 2, False))
    assert c.key_positions == {block_identity(block(0)): 0, block_identity(block(1)): 1}
    seen = []

    def verify(raw):
        parsed = [Codec().deserialize(part)[0] for part in raw]
        seen.extend(parsed[0]["steps"])
        return verified(4)

    advance(c, 1, 4, step(1, 3), step(3, 4, False), callback=verify)
    assert [(s["from"]["seqno"], s["to"]["seqno"]) for s in seen] == [(0, 1), (1, 3), (3, 4)]
    assert block_identity(block(3)) in c.key_positions
    assert block_identity(block(2)) not in c.key_positions
    assert block_identity(block(4)) not in c.key_positions


@pytest.mark.parametrize(
    "failure", ["refused", "wrong_target", "wrong_anchor", "live", "exception"]
)
def test_native_failure_cannot_advance_cached_prefix(failure):
    c = RetainedPrefix(Codec(), block(0))
    advance(c, 0, 1, step(0, 1))
    before = deepcopy((c.links, c.key_positions, c.last_target))

    def verify(_):
        d = verified(2)
        if failure == "exception":
            raise HistoryError("native process failed")
        if failure == "refused":
            d["status"] = "refused"
        if failure == "wrong_target":
            d["target"] = block(3)
        if failure == "wrong_anchor":
            d["anchor"] = block(0, "ab" * 32)
        if failure == "live":
            d["mode"] = "live"
        return d

    with pytest.raises(HistoryError):
        advance(c, 1, 2, step(1, 2), callback=verify)
    assert (c.links, c.key_positions, c.last_target) == before


def test_missing_prefix_is_not_filled_from_unverified_metadata():
    c = RetainedPrefix(Codec(), block(0))
    with pytest.raises(HistoryError, match="prefix missing"):
        advance(c, 1, 2, step(1, 2))


def test_capture_regression_and_same_height_replacement_refused():
    c = RetainedPrefix(Codec(), block(0))
    advance(c, 0, 2, step(0, 1), step(1, 2, False))
    with pytest.raises(HistoryError, match="regressed"):
        advance(c, 1, 1, step(1, 2))
    with pytest.raises(HistoryError, match="regressed"):
        c.advance(
            [response(step(1, 2))],
            start=block(1),
            target=block(2, "ab" * 32),
            verify=lambda _: verified(2),
        )


@pytest.mark.parametrize("bad", ["backward", "gap", "completion", "endpoint"])
def test_malformed_composition_never_calls_native_callback(bad):
    c = RetainedPrefix(Codec(), block(0))
    raw = response(step(0, 1), step(1, 2, False))
    obj = Codec().deserialize(raw)[0]
    if bad == "backward":
        obj["steps"][0]["@type"] = "liteServer.blockLinkBack"
    if bad == "gap":
        obj["steps"][1]["from"] = block(0)
    if bad == "completion":
        obj["complete"] = False
    if bad == "endpoint":
        obj["to"] = block(3)
    called = []
    with pytest.raises(HistoryError):
        c.advance(
            [Codec().serialize("", obj)],
            start=block(0),
            target=block(2),
            verify=lambda _: called.append(True),
        )
    assert not called and not c.links


def test_composition_packs_bounded_response_groups():
    c = RetainedPrefix(Codec(), block(0))
    steps = [step(i, i + 1) for i in range(40)]
    parts = c._encode(steps)
    assert len(parts) == 3
    assert [Codec().deserialize(p)[0]["complete"] for p in parts] == [False, False, True]
    with pytest.raises(HistoryError, match="link count"):
        c._encode(steps * 410)


def test_oversized_input_and_response_count_refused_before_decode():
    c = RetainedPrefix(Codec(), block(0))
    for responses in ([b"x" * ((8 << 20) + 1)], [b"x"] * 1025):
        with pytest.raises(HistoryError):
            c.advance(
                responses,
                start=block(0),
                target=block(1),
                verify=lambda _: pytest.fail("oversized"),
            )


def test_oversized_reencoded_link_refused_before_callback():
    c = RetainedPrefix(Codec(), block(0))
    item = step(0, 1)
    item["oversized_fake_codec_payload"] = "x" * (8 << 20)
    with pytest.raises(HistoryError, match="link size limit"):
        c._encode([item])


@pytest.mark.parametrize(
    "field,value",
    [
        ("seqno", True),
        ("workchain", 0),
        ("shard", True),
        ("root_hash", "aa"),
        ("file_hash", "ZZ" * 32),
    ],
)
def test_block_identity_is_bounded_and_exact(field, value):
    d = block(1)
    d[field] = value
    with pytest.raises(HistoryError):
        block_identity(d)
