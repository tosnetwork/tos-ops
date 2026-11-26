"""Tests for check-validator-keys.py, the pinned-key four-signer certificate gate.

The green fixture is one live capture (8 consecutive masterchain blocks, 3 sources) from the epoch-6 public testnet,
2026-11-10, plus the public epoch-6 zerostate. Every negative case must fail under the correct code.
check_validator_keys_mutants.py shows that each guard is needed: removing it turns this suite red.
"""

import base64
import gzip
import importlib.util
import json

import pytest
from testnet_support import DATA, SCRIPTS

D = DATA / "validator-keys"
spec = importlib.util.spec_from_file_location("check_validator_keys", SCRIPTS / "check-validator-keys.py")
cvk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cvk)
f = cvk.f


@pytest.fixture(scope="module")
def pinned():
    return cvk.genesis_members(json.loads((D / "global-config.json").read_text()), (D / "zerostate.boc").read_bytes())


@pytest.fixture(scope="module")
def verifier():
    return cvk.mldsa_raising()


@pytest.fixture()
def cap():
    with gzip.open(D / "capture.json.gz", "rt") as fh:
        return json.load(fh)


def last_gen(cap):
    host = next(iter(cap["sources"]))
    return cap["sources"][host]["blocks"][cap["seqnos"][-1]]["header"]["gen_utime"]


def run(cap, pinned, verifier, since=None, now=None, max_age=60, future=5):
    g = last_gen(cap)
    return cvk.evaluate(cap, pinned, verifier, g - 600 if since is None else since, g + 2 if now is None else now, max_age, future)


def key(seqnos):
    return str(seqnos)


def blocks(cap, host):
    """JSON round trip turns int keys into strings; map both ways."""
    b = cap["sources"][host]["blocks"]
    return b


@pytest.fixture(autouse=True)
def int_keys(cap):
    for s in cap["sources"].values():
        s["blocks"] = {int(k): v for k, v in s["blocks"].items()}
        s["configs"] = {int(k): v for k, v in s["configs"].items()}


# ---------------------------------------------------------------- green


def test_green_capture_passes(cap, pinned, verifier):
    v = run(cap, pinned, verifier)
    assert v["verdict"] == "PASS-FOUR-SIGNER-COVERAGE-PINNED-KEYS"
    assert all(s["signers"] == 4 for s in v["sources"].values())


def test_pinned_genesis_set_is_four_ml_dsa_members(pinned):
    assert len(pinned) == 4 and len(set(pinned.values())) == 4


# ---------------------------------------------------------------- the pin


def test_substituted_zero_state_record_fails():
    g = json.loads((D / "global-config.json").read_text())
    g["validator"]["zero_state"]["root_hash"] = base64.b64encode(b"\1" * 32).decode()
    with pytest.raises(cvk.Fail, match="not the pinned epoch-6 zero state"):
        cvk.genesis_members(g, (D / "zerostate.boc").read_bytes())


def test_zerostate_bytes_not_matching_the_pinned_file_hash_fail():
    data = bytearray((D / "zerostate.boc").read_bytes())
    data[-1] ^= 1
    with pytest.raises(cvk.Fail, match="file hash"):
        cvk.genesis_members(json.loads((D / "global-config.json").read_text()), bytes(data))


def test_wrong_global_id_fails(monkeypatch):
    real = cvk.lib.zero_state_config

    def other_network(boc):
        root, _gid, params = real(boc)
        return root, 3, params

    monkeypatch.setattr(cvk.lib, "zero_state_config", other_network)
    with pytest.raises(cvk.Fail, match="global id 3"):
        cvk.genesis_members(json.loads((D / "global-config.json").read_text()), (D / "zerostate.boc").read_bytes())


def test_genesis_member_count_other_than_four_fails(monkeypatch):
    real = cvk.shared.decode_set

    def three(cell):
        v = real(cell)
        v["validators"] = v["validators"][:3]
        return v

    monkeypatch.setattr(cvk.shared, "decode_set", three)
    with pytest.raises(cvk.Fail, match="3 members"):
        cvk.genesis_members(json.loads((D / "global-config.json").read_text()), (D / "zerostate.boc").read_bytes())


def test_swapped_key_mapping_fails(cap, pinned, verifier):
    ids = sorted(pinned)
    swapped = dict(pinned)
    swapped[ids[0]], swapped[ids[1]] = pinned[ids[1]], pinned[ids[0]]
    with pytest.raises(cvk.Fail, match="pinned genesis keys"):
        run(cap, swapped, verifier)


def test_unequal_weights_fail(cap, pinned, verifier, monkeypatch):
    # A skewed weight in the proven set itself is refused earlier by verify_link (validator-set hash). This
    # control feeds the gate's own equal-weight guard directly.
    real = cvk.governing_set

    def skewed(link):
        members, weights = real(link)
        return members, weights | {max(weights) + 1}

    monkeypatch.setattr(cvk, "governing_set", skewed)
    with pytest.raises(cvk.Fail, match="weights are not equal"):
        run(cap, pinned, verifier)


# ---------------------------------------------------------------- sources


def approved():
    return cvk.tunnel_inventory(D / "units", json.loads((D / "inventory.json").read_text()))


def test_inventory_resolves_each_host_to_its_tunnel():
    a = approved()
    assert a == {
        "node-1": "http://127.0.0.1:18081/jsonRPC",
        "node-2": "http://127.0.0.1:38081/jsonRPC",
        "node-3": "http://127.0.0.1:28081/jsonRPC",
        "node-4": "http://127.0.0.1:48084/jsonRPC",
    }


def test_two_tunnels_to_one_host_fail(tmp_path):
    units = tmp_path / "units"
    units.mkdir()
    for p in (D / "units").iterdir():
        (units / p.name).write_text(p.read_text())
    (units / "e6-tun-n2.service").write_text(
        "[Service]\nExecStart=/usr/bin/ssh -N -L 38081:127.0.0.1:8081 root@192.0.2.1\n"
    )
    with pytest.raises(cvk.Fail, match="more than one tunnel"):
        cvk.tunnel_inventory(units, json.loads((D / "inventory.json").read_text()))


def test_tunnel_to_a_host_outside_the_inventory_fails(tmp_path):
    units = tmp_path / "units"
    units.mkdir()
    for p in (D / "units").iterdir():
        (units / p.name).write_text(p.read_text())
    (units / "e6-tun-n3.service").write_text(
        "[Service]\nExecStart=/usr/bin/ssh -N -L 28081:127.0.0.1:8081 root@198.51.100.9\n"
    )
    with pytest.raises(cvk.Fail, match="not an inventory host"):
        cvk.tunnel_inventory(units, json.loads((D / "inventory.json").read_text()))


def test_duplicate_source_host_fails():
    with pytest.raises(cvk.Fail, match="duplicate source"):
        cvk.choose_sources(["node-1", "node-1", "node-2"], "node-4", approved())


def test_fewer_than_three_sources_fail():
    with pytest.raises(cvk.Fail, match="at least three"):
        cvk.choose_sources(["node-1", "node-2"], "node-4", approved())


def test_excluded_host_as_source_fails():
    with pytest.raises(cvk.Fail, match="host under test"):
        cvk.choose_sources(["node-1", "node-2", "node-4"], "node-4", approved())


def test_unapproved_source_host_fails():
    with pytest.raises(cvk.Fail, match="no approved tunnel"):
        cvk.choose_sources(["node-1", "node-2", "node-5"], "node-4", approved())


# ---------------------------------------------------------------- evidence


def test_sources_disagreeing_on_a_block_id_fail(cap, pinned, verifier):
    s = cap["seqnos"][3]
    host = list(cap["sources"])[1]
    cap["sources"][host]["blocks"][s]["header"]["id"]["root_hash"] = base64.b64encode(b"\2" * 32).decode()
    with pytest.raises(cvk.Fail, match="disagree"):
        run(cap, pinned, verifier)


def test_config_proof_of_another_key_block_fails(cap, pinned, verifier):
    host = next(iter(cap["sources"]))
    c = next(iter(cap["sources"][host]["configs"].values()))
    c["key_header"]["id"]["seqno"] -= 1
    with pytest.raises(cvk.Fail):
        run(cap, pinned, verifier)


def test_json_header_session_coordinates_disagreeing_with_the_proof_fail(cap, pinned, verifier):
    host = next(iter(cap["sources"]))
    cap["sources"][host]["blocks"][cap["seqnos"][0]]["header"]["catchain_seqno"] += 1
    with pytest.raises(cvk.Fail, match="JSON header disagrees"):
        run(cap, pinned, verifier)


def test_json_gen_utime_disagreeing_with_the_proof_fails(cap, pinned, verifier):
    host = next(iter(cap["sources"]))
    cap["sources"][host]["blocks"][cap["seqnos"][0]]["header"]["gen_utime"] += 1
    with pytest.raises(cvk.Fail, match="JSON header disagrees"):
        run(cap, pinned, verifier)


def test_proof_for_another_block_fails(cap, pinned, verifier):
    host = next(iter(cap["sources"]))
    b = cap["sources"][host]["blocks"]
    a, c = cap["seqnos"][0], cap["seqnos"][1]
    b[a]["proof_reply"], b[c]["proof_reply"] = b[c]["proof_reply"], b[a]["proof_reply"]
    with pytest.raises(cvk.Fail):
        run(cap, pinned, verifier)


def test_proof_for_another_block_with_identical_header_fields_fails(cap, pinned, verifier):
    # Two consecutive blocks in the same second share gen_utime, key block and session, so only the
    # "proof ends at the requested block" guard tells their proofs apart.
    host = next(iter(cap["sources"]))
    b = cap["sources"][host]["blocks"]

    def fields(s):
        h = b[s]["header"]
        return (h["gen_utime"], h["prev_key_block_seqno"], h["catchain_seqno"], h["validator_list_hash_short"])

    pairs = [(a, c) for a, c in zip(cap["seqnos"], cap["seqnos"][1:]) if fields(a) == fields(c)]
    assert pairs, "fixture has no two consecutive blocks with identical header fields"
    a, c = pairs[0]
    b[a]["proof_reply"], b[c]["proof_reply"] = b[c]["proof_reply"], b[a]["proof_reply"]
    with pytest.raises(cvk.Fail, match="does not end at block"):
        run(cap, pinned, verifier)


def test_envelope_end_and_reported_id_changed_together_fail(cap, pinned, verifier, monkeypatch):
    # Reviewer's reproduction: the reported file hash and the proof envelope's end are changed consistently on
    # every source, while the verified link (and its signatures) is untouched. The link's own destination must
    # bind them.
    other = base64.b64encode(b"\3" * 32).decode()
    real = cvk.f.forward_proof

    def outer_end_changed(data, allow_partial=False):
        start, end, links = real(data, allow_partial)
        return start, dict(end, file_hash=other), links

    for s in cap["sources"].values():
        for b in s["blocks"].values():
            b["header"]["id"]["file_hash"] = other
    monkeypatch.setattr(cvk.f, "forward_proof", outer_end_changed)
    with pytest.raises(cvk.Fail, match="does not end at block"):
        run(cap, pinned, verifier)


def test_envelope_start_other_than_the_key_block_fails(cap, pinned, verifier, monkeypatch):
    real = cvk.f.forward_proof

    def outer_start_changed(data, allow_partial=False):
        start, end, links = real(data, allow_partial)
        return dict(start, seqno=start["seqno"] - 1), end, links

    monkeypatch.setattr(cvk.f, "forward_proof", outer_start_changed)
    with pytest.raises(cvk.Fail, match="does not start at key block"):
        run(cap, pinned, verifier)


def test_term_upper_bound_is_exclusive(cap, pinned, verifier, monkeypatch):
    # verify_link calls gen_utime == utime_until "within_schedule"; the gate's term is half-open.
    real = cvk.verify_link

    def until_now(link, verify_signature, expected_source=None):
        r = real(link, verify_signature, expected_source=expected_source)
        return dict(r, validator_until=r["header"]["gen_utime"])

    monkeypatch.setattr(cvk, "verify_link", until_now)
    with pytest.raises(cvk.Fail, match="outside its set's term"):
        run(cap, pinned, verifier)


def test_term_lower_bound_is_inclusive_and_enforced(cap, pinned, verifier, monkeypatch):
    real = cvk.verify_link

    def since_later(link, verify_signature, expected_source=None):
        r = real(link, verify_signature, expected_source=expected_source)
        return dict(r, validator_since=r["header"]["gen_utime"] + 1)

    monkeypatch.setattr(cvk, "verify_link", since_later)
    with pytest.raises(cvk.Fail, match="outside its set's term"):
        run(cap, pinned, verifier)


def test_verdict_lists_each_members_verified_blocks(cap, pinned, verifier):
    v = run(cap, pinned, verifier)
    for s in v["sources"].values():
        assert sorted(s["signed_blocks"]) == sorted(k.hex() for k in pinned)
        assert all(s["signed_blocks"][k] for k in s["signed_blocks"])
        assert all(set(b) == {"seqno", "gen_utime"} for blocks in s["signed_blocks"].values() for b in blocks)


def test_a_flipped_signature_byte_fails(cap, pinned, verifier):
    host = next(iter(cap["sources"]))
    s = cap["seqnos"][0]
    raw = bytearray(f.D(cap["sources"][host]["blocks"][s]["proof_reply"]))
    _start, _end, links = f.forward_proof(bytes(raw))
    sig = f.D(links[0]["cert"]["signatures"][0]["signature"])
    at = bytes(raw).find(sig)
    assert at > 0
    raw[at + 100] ^= 1
    cap["sources"][host]["blocks"][s]["proof_reply"] = f.B(bytes(raw))
    with pytest.raises(cvk.Fail, match="does not verify"):
        run(cap, pinned, verifier)


def test_a_rejecting_verifier_fails(cap, pinned):
    def reject(pk, sig, msg):
        raise cvk.Refused("ML-DSA-44 signature does not verify")

    with pytest.raises(cvk.Fail, match="does not verify"):
        run(cap, pinned, reject)


# ---------------------------------------------------------------- freshness and signers


def test_stale_block_fails(cap, pinned, verifier):
    g = last_gen(cap)
    with pytest.raises(cvk.Fail, match="old"):
        run(cap, pinned, verifier, now=g + 61 + len(cap["seqnos"]) * 3)


def test_future_block_fails(cap, pinned, verifier):
    g = last_gen(cap)
    with pytest.raises(cvk.Fail, match="future"):
        run(cap, pinned, verifier, now=g - 30)


def test_block_before_since_is_retryable(cap, pinned, verifier):
    g = last_gen(cap)
    with pytest.raises(cvk.Retry, match="predates --since"):
        run(cap, pinned, verifier, since=g + 1)


def test_fewer_than_four_signers_across_the_window_is_retryable(cap, pinned, verifier):
    # Keep only the blocks whose certificates together miss one member.
    host = next(iter(cap["sources"]))
    first = cap["seqnos"][0]
    _s, _e, links = f.forward_proof(f.D(cap["sources"][host]["blocks"][first]["proof_reply"]))
    if len(links[0]["cert"]["signatures"]) == 4:
        pytest.skip("first block already carries all four signers")
    cap["seqnos"] = [first]
    with pytest.raises(cvk.Retry, match="of 4 signers"):
        run(cap, pinned, verifier)


def test_non_consecutive_window_fails(cap, pinned, verifier):
    cap["seqnos"] = cap["seqnos"][:2] + cap["seqnos"][3:]
    with pytest.raises(cvk.Fail, match="consecutive"):
        run(cap, pinned, verifier)


# ---------------------------------------------------------------- the wait loop (main)


def main_args(tmp_path, wait):
    return [
        "check-validator-keys.py",
        "--global-config", str(D / "global-config.json"),
        "--zerostate", str(D / "zerostate.boc"),
        "--inventory", str(D / "inventory.json"),
        "--unit-dir", str(D / "units"),
        "--source", "node-1", "--source", "node-2", "--source", "node-3",
        "--exclude", "node-4",
        "--since", "0",
        "--wait", str(wait),
        "--out", str(tmp_path / "out"),
    ]


def bounded_sleep(limit=20):
    """A sleep stub that fails the test instead of letting a broken deadline loop forever."""
    calls = {"n": 0}

    def sleep(_seconds):
        calls["n"] += 1
        if calls["n"] > limit:
            raise AssertionError("the wait loop did not stop at its deadline")

    return sleep


def test_wait_expiry_is_inconclusive(monkeypatch, tmp_path):
    clock = {"t": 1000.0}

    def monotonic():
        clock["t"] += 15
        return clock["t"]

    monkeypatch.setattr(cvk, "capture", lambda rpcs: {})
    monkeypatch.setattr(cvk, "evaluate", lambda *a, **k: (_ for _ in ()).throw(cvk.Retry("no eligible block yet")))
    monkeypatch.setattr(cvk.time, "sleep", bounded_sleep())
    monkeypatch.setattr(cvk.time, "monotonic", monotonic)
    monkeypatch.setattr("sys.argv", main_args(tmp_path, 60))
    assert cvk.main() == 2
    assert json.loads((tmp_path / "out/VERDICT.json").read_text())["verdict"] == "INCONCLUSIVE"


def test_zero_wait_does_not_retry(monkeypatch, tmp_path):
    monkeypatch.setattr(cvk, "capture", lambda rpcs: {})
    monkeypatch.setattr(cvk, "evaluate", lambda *a, **k: (_ for _ in ()).throw(cvk.Retry("no eligible block yet")))
    monkeypatch.setattr(cvk.time, "sleep", bounded_sleep(0))
    monkeypatch.setattr("sys.argv", main_args(tmp_path, 0))
    assert cvk.main() == 2
    assert json.loads((tmp_path / "out/VERDICT.json").read_text())["verdict"] == "INCONCLUSIVE"


def test_retry_then_eligible_block_passes(monkeypatch, tmp_path):
    calls = {"n": 0}

    def evaluate(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise cvk.Retry("no block yet at or after --since")
        return {"verdict": "PASS-FOUR-SIGNER-COVERAGE-PINNED-KEYS"}

    monkeypatch.setattr(cvk, "capture", lambda rpcs: {})
    monkeypatch.setattr(cvk, "evaluate", evaluate)
    monkeypatch.setattr(cvk.time, "sleep", lambda s: None)
    monkeypatch.setattr("sys.argv", main_args(tmp_path, 60))
    assert cvk.main() == 0 and calls["n"] == 2


def test_terminal_failure_is_not_retried(monkeypatch, tmp_path):
    calls = {"n": 0}

    def evaluate(*a, **k):
        calls["n"] += 1
        raise cvk.Fail("ML-DSA-44 signature does not verify")

    monkeypatch.setattr(cvk, "capture", lambda rpcs: {})
    monkeypatch.setattr(cvk, "evaluate", evaluate)
    monkeypatch.setattr(cvk.time, "sleep", lambda s: None)
    monkeypatch.setattr("sys.argv", main_args(tmp_path, 60))
    assert cvk.main() == 1 and calls["n"] == 1
