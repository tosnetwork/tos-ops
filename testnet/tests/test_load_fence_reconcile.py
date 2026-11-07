"""The gate-3 reconciler reads a closed qualified run without changing or revealing it.

Fixtures are written by the producer's own writers (Qualification, LoadDriver
.take_query_ids, Journal.append, write_new_json) in temporary directories, with
canaries in every key, carrier and signed-message field the helper must not read.
"""

import base64
import fcntl
import hashlib
import importlib.util
import json
import os
import resource
import time
from pathlib import Path
from types import SimpleNamespace

import load_fence_reconcile as lfr
import pytest
import testnet_lib as lib
import testnet_ops as ops
from conftest import SCRIPTS
from load_qualification import Qualification, atomic_json

CANARY = "CANARYc4n4ryZQXJ"
IDENTITY = {"global_id": 2, "genesis_root": "aa" * 32, "genesis_file": "bb" * 32}
OWNER = "0:" + "0f" * 32
OPERATOR = "0:" + "0e" * 32
PRE_RUN_TX = "77" * 32


def _te():
    spec = importlib.util.spec_from_file_location(
        "te_for_reconcile", SCRIPTS / "testnet-elections.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TE = _te()


class FakeNative:
    """The observer interface Qualification uses (attach_native, offer, summary)."""

    def __init__(self):
        self.offered = self.finalized = 0
        self.pending = 0

    def assert_healthy(self):
        pass

    def offer(self, hashes):
        self.offered += len(hashes)
        return {"boot_id": "test-boot", "monotonic_seconds": time.monotonic()}

    def summary(self):
        return {
            "offered": self.offered,
            "native_finalized": self.finalized,
            "native_pending": self.pending,
            "failure": None,
        }


def address_bytes(byte):
    return bytes([byte]) * 32 + (0).to_bytes(4, "big", signed=True)


def address_of(byte):
    return "0:" + f"{byte:02x}" * 32


def driver(state, q, start):
    drv = TE.LoadDriver.__new__(TE.LoadDriver)
    drv.state, drv.qualification = Path(state), q
    drv.saved = {"next_query_id": start, "wallet_timeout": 3600}
    return drv


class Producer:
    """One qualified run, driven through the producer's public methods."""

    def __init__(self, fx, start=None):
        self.fx = fx
        self.q = Qualification(fx.state, 10**15, 10**15, identity=IDENTITY)
        self.native = FakeNative()
        self.q.attach_native(self.native)
        if start is None:
            self.drv = fx.drv
            self.drv.qualification = self.q
        else:
            self.drv = fx.drv = driver(fx.state, self.q, start)

    def batch(self, relayer, count, *, terminal=True, archive_only=False):
        ids = self.drv.take_query_ids(count)
        seqno = self.fx.seqnos.get(relayer, 0)
        carrier = self.fx.tmp / f"ext-{relayer}-{seqno}-{ids[0]}.boc"
        carrier.write_bytes(f"signed-carrier-{CANARY}".encode())
        hashes = {q: hashlib.sha256(f"req{q}".encode()).hexdigest() for q in ids}
        if archive_only:
            original = self.q.event

            def fail(*args, **kwargs):
                raise OSError("offered journal write failed")

            self.q.event = fail
            with pytest.raises(OSError):
                self.q.offer(ids, carrier, hashes)
            self.q.event = original
            carrier.unlink()
            return ids
        self.q.offer(ids, carrier, hashes)
        carrier.unlink()
        self.fx.seqnos[relayer] = seqno + 1
        self.q.accept(ids)
        if terminal:
            for query in ids:
                self.q.terminal(query, True)
            self.native.finalized += len(ids)
            self.q.event(
                "native_checkpoint",
                checkpoint_seqno=len(ids),
                capture="capture",
                query_ids=ids,
                summary=self.native.summary(),
            )
        else:
            self.native.finalized += len(ids) - 1
            self.native.pending += 1
        return ids

    def fund(self, label, amount, destination, *, settle=True, fail=False):
        self.q.reserve_funding(amount, label)
        op_id = f"load-{label}-{time.strftime('%Y%m%dt%H%M%S', time.gmtime())}-{amount}"
        tx = self.fx.journal_op(
            op_id,
            OWNER,
            destination,
            amount,
            {"label": label, "purpose": "load"},
            settle=settle,
        )
        if fail:
            self.q.uncertain_funding()
            return
        if settle:
            self.q.funding_settled()
            self.fx.matches.append(
                {"transaction": tx, "label": label, "amount_nanotos": amount, "to": destination}
            )

    def finish(self, stamp):
        result = self.q.finish()
        lib.write_new_json(
            self.fx.state / f"summary-{stamp}.json",
            {"wallet": self.fx.highload, "qualification": result},
            0o600,
        )
        return result


class Fixture:
    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.state = self.tmp / "state"
        self.ceremony = self.tmp / "ceremony"
        self.public = self.tmp / "public"
        self.public.mkdir()
        self.journal = ops.Journal(self.ceremony)
        self.seqnos = {}
        self.matches = []
        self.highload = address_of(0xCE)
        self.relayers = [address_of(0xA0), address_of(0xA1)]
        self.counter = 0
        self.drv = None

    def journal_op(self, op_id, wallet, destination, value, extra, *, settle=True, state=None):
        params = {
            "kind": "owner-fund",
            "wallet": wallet,
            "destination": destination,
            "value": value,
            "bounce": False,
            "body_hash": "00" * 32,
            "state_init_hash": None,
            "name": "node-4",
            "subwallet": 698983191,
            **extra,
        }
        self.journal.append(op_id, dict(params, state="planned"))
        if state == "planned":
            return None
        boc = base64.b64encode(f"signed-message-{CANARY}".encode() * 4).decode()
        self.counter += 1
        self.journal.append(
            op_id,
            {
                "state": "signed",
                "boc": boc,
                "external_hash": f"{self.counter:064x}",
                "seqno": self.counter,
                "valid_until": 1,
                "boundary": None,
                "identity": None,
                "gate_witness": None,
            },
        )
        self.journal.append(op_id, {"state": "broadcast"})
        if not settle:
            return None
        tx = hashlib.sha256(op_id.encode()).hexdigest()
        self.journal.append(
            op_id,
            {"state": "settled", "evidence": {"wallet_tx": tx, "explains": [tx], "form": "a"}},
        )
        return tx

    def plant_secrets(self):
        s = self.state
        (s / "highload.key").write_bytes(f"key-{CANARY}".encode())
        (s / "highload.pub").write_bytes(f"pub-{CANARY}".encode())
        (s / "highload.addr").write_bytes(address_bytes(0xCE))
        (s / "highload.init.boc").write_bytes(f"init-{CANARY}".encode())
        (s / "gid.fif").write_text(f"2 constant {CANARY}\n")
        for index, byte in enumerate((0xA0, 0xA1)):
            (s / f"relayer-{index}.addr").write_bytes(address_bytes(byte))
            (s / f"relayer-{index}.pk").write_bytes(f"pk-{CANARY}".encode())
            (s / f"relayer-{index}-query.boc").write_bytes(f"query-{CANARY}".encode())
        dry = s / "dry-run-20261105T000000Z"
        dry.mkdir(mode=0o700)
        (dry / "dry-run.json").write_text(json.dumps({"secret": CANARY}))
        secret = self.ceremony / "secret"
        secret.mkdir(mode=0o700, parents=True, exist_ok=True)
        (secret / "pool-owner-node-4.pk").write_bytes(f"owner-{CANARY}".encode())
        sent = self.ceremony / "sent"
        sent.mkdir(mode=0o700, exist_ok=True)
        (sent / "20261105T000000Z-owner-node-4-seq1-x.boc").write_bytes(CANARY.encode())

    def public_files(self, result, events_sha=None, summary_sha=None, **overrides):
        run = self.state / result["run_directory"]
        summary = next(
            p
            for p in sorted(self.state.glob("summary-*.json"))
            if json.loads(p.read_text())["qualification"]["run_directory"]
            == result["run_directory"]
        )
        events = (run / "events.jsonl").read_bytes()
        reservations = [
            {
                "time_unix": e["time_unix"],
                "amount_nanotos": e["amount_nanotos"],
                "label": e["label"],
            }
            for e in map(json.loads, events.splitlines())
            if e["event"] == "funding_reserved"
        ]
        audit = {
            "offered": overrides.get("offered", result["offered"]),
            "not_offered": 0,
            "identity": {
                "events_sha256": events_sha or hashlib.sha256(events).hexdigest(),
                "summary_sha256": summary_sha or hashlib.sha256(summary.read_bytes()).hexdigest(),
                "global_id": 2,
                "wallet": self.highload,
            },
        }
        matches = {
            "count": len(self.matches),
            "total_nanotos": sum(m["amount_nanotos"] for m in self.matches),
            "matches": self.matches,
            "unmatched_owner_rows": [{"hash": overrides.get("pre_run_tx", PRE_RUN_TX)}],
        }
        for name, value in (
            ("closed-audit.json", audit),
            ("reservations.json", reservations),
            ("owner-matches.json", matches),
        ):
            path = self.public / name
            if path.exists():
                path.unlink()
            path.write_text(json.dumps(value))


def build(tmp_path, **opts):
    """A prior closed run and the target run, both through the producer's writers."""
    fx = Fixture(tmp_path)
    fx.state.mkdir(mode=0o700)
    fx.ceremony.mkdir(mode=0o700)
    with fx.journal.lock():  # the producer's own lock file (testnet_ops.py:912-927)
        pass
    pre = fx.journal_op("fund-op-runway", OWNER, OPERATOR, 60 * 10**9, {})
    assert pre is not None
    PRE_TX[0] = pre
    prior = Producer(fx, start=990)
    prior.batch(0, 5)
    prior.batch(1, 5)
    prior.finish("20261104T000000Z")
    fx.plant_secrets()
    if opts.get("old_open_op"):
        fx.journal_op("fund-op-stuck", OWNER, OPERATOR, 10**9, {}, state="planned")
    target = Producer(fx)
    target.fund("load-relayer-0", 4_000_000_000, fx.relayers[0])
    target.fund("load-relayer-1", 4_100_000_000, fx.relayers[1])
    target.batch(0, 20)
    target.batch(1, 20)
    if opts.get("not_offered_orphan"):
        target.batch(0, 3, archive_only=True)
    target.fund("load-refill-0", 1_500_000_000, fx.relayers[0], settle=not opts.get("inflight"))
    target.batch(1, 10, terminal=not opts.get("pending"))
    if opts.get("funding_unknown"):
        target.fund("load-refill-1", 1_000, fx.relayers[1], settle=False, fail=True)
    if opts.get("allocate_after"):
        fx.drv.take_query_ids(opts["allocate_after"])
    result = target.finish("20261105T034146Z")
    captures = fx.state / result["run_directory"] / "native-captures" / "capture-000000"
    captures.mkdir(mode=0o700, parents=True)
    (captures / "native-state.json").write_text(json.dumps({"material": CANARY}))
    fx.public_files(result, pre_run_tx=PRE_TX[0], **opts.get("public", {}))
    fx.result = result
    return fx


PRE_TX = [None]


def args_for(fx, out, **kw):
    return SimpleNamespace(
        state=str(fx.state),
        ceremony=str(fx.ceremony),
        run=kw.get("run", fx.result["run_directory"]),
        out=str(out),
        closed_audit=str(fx.public / "closed-audit.json"),
        reservations=str(fx.public / "reservations.json"),
        owner_matches=str(fx.public / "owner-matches.json"),
        funding_owner_address=OWNER,
        operator_wallet=[OPERATOR],
        global_id=2,
        genesis_root=IDENTITY["genesis_root"],
        genesis_file=IDENTITY["genesis_file"],
        min_query_id=kw.get("min_query_id", 1000),
        chain_reads=kw.get("chain_reads", True),
        source=kw.get("source", ["http://a/jsonRPC", "http://b/jsonRPC"]),
    )


def chain_for(fx, overrides=None):
    calls = []
    seqno = {fx.relayers[i]: n for i, n in fx.seqnos.items()}

    def rpc(url, method, /, **params):
        calls.append(method)
        if method == "getAddressInformation":
            return {"state": "active", "balance": "1"}
        if method == "runGetMethod":
            value = (overrides or {}).get((url, params["address"]), seqno[params["address"]])
            if value is None:
                raise lib.TestnetError("unavailable")
            return {"exit_code": 0, "stack": [["num", hex(value)]]}
        raise AssertionError(method)

    return rpc, calls


def tree(root):
    out = {}
    for path in sorted(Path(root).rglob("*")):
        info = path.lstat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        out[str(path)] = (info.st_ino, info.st_mtime_ns, info.st_mode, digest)
    return out


def flocked(path):
    """Whether any process holds a lock on `path`, from /proc/locks."""
    info = os.stat(path)
    held = lfr.proc_locks("/proc/locks")
    return (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino) in held


def reconcile(fx, tmp_path, rpc=None, proc="/proc/locks", name="out.json", **kw):
    out = tmp_path / "public" / name
    before = tree(tmp_path)
    if rpc is None:
        rpc, _calls = chain_for(fx)
    code, document = lfr.run(args_for(fx, out, **kw), rpc=rpc, proc_locks_path=proc)
    after = tree(tmp_path)
    created = set(after) - set(before)
    assert created <= {str(out)}
    # Only the output and its directory's own mtime may change.
    skip = {str(out), str(out.parent)}
    assert {k: v for k, v in after.items() if k not in skip} == {
        k: v for k, v in before.items() if k not in skip
    }
    if out.exists():
        assert CANARY not in out.read_text()
        assert "boc" not in out.read_text()
    assert not flocked(fx.state / "qualification.lock")
    assert not flocked(fx.ceremony / "operations" / ".lock")
    assert lfr.GUARD["violations"] == 0
    return code, document


def verdicts(document):
    return {k: v["verdict"] for k, v in document["populations"].items()}


# ---------------------------------------------------------------- happy path


def test_closed_run_reconciles_and_is_launch_eligible(tmp_path):
    fx = build(tmp_path)
    code, doc = reconcile(fx, tmp_path)
    assert code == 0, verdicts(doc)
    assert doc["verdict"] == lfr.ELIGIBLE and doc["launch_eligible"] is True
    assert set(verdicts(doc).values()) <= {lfr.RECONCILED, lfr.OBSERVED}
    ids = doc["populations"]["query_ids"]
    # 1000..1050 offered, 1023 does not exist (testnet-elections.py:2060-2068).
    assert (ids["min"], ids["max"], ids["gaps_structural_1023"], ids["gaps_other"]) == (
        1000,
        1050,
        1,
        0,
    )
    assert ids["expected_next"] == ids["counter"] == 1051
    assert ids["reconstructed_start"] == 1000
    assert doc["populations"]["offered"]["count"] == 50
    assert doc["populations"]["funding"]["reserved"] == 3
    assert doc["populations"]["funding_journal"]["matched"] == 3
    assert doc["populations"]["owner_pre_run_rows"]["unexplained"] == 0
    assert doc["locks"]["qualification_lock"] == lfr.LOCK_FREE
    assert doc["locks"]["statement"] == lfr.STATEMENT
    assert doc["addresses"]["highload_address"] == fx.highload
    assert doc["addresses"]["relayer_addresses"] == fx.relayers
    events = (fx.state / fx.result["run_directory"] / "events.jsonl").read_bytes()
    assert doc["hashes"]["events_sha256"] == hashlib.sha256(events).hexdigest()
    pairs = sorted(
        (q, hashlib.sha256(f"req{q}".encode()).hexdigest()) for q in range(1000, 1051) if q != 1023
    )
    serial = "".join(f"{q}:{h}\n" for q, h in pairs).encode()
    assert doc["hashes"]["signed_request_hashes_sha256"] == hashlib.sha256(serial).hexdigest()
    assert all(lfr.LOGICAL_ID.match(i) for i in doc["inputs_opened"])
    assert "run:outbox-listing" in doc["inputs_opened"]
    assert json.loads((tmp_path / "public" / "out.json").read_text()) == doc
    assert lfr.GUARD["core_at_first_open"] == 0


def test_core_dumps_are_disabled_before_the_first_open(tmp_path, monkeypatch):
    fx = build(tmp_path)
    order = []
    real_setrlimit, real_root = resource.setrlimit, lfr.Reader.root

    def setrlimit(kind, limits):
        order.append(("rlimit", kind, limits))
        return real_setrlimit(kind, limits)

    def root(self, path, input_id):
        order.append(("open", input_id))
        return real_root(self, path, input_id)

    monkeypatch.setattr(lfr.resource, "setrlimit", setrlimit)
    monkeypatch.setattr(lfr.Reader, "root", root)
    reconcile(fx, tmp_path)
    assert order[0] == ("rlimit", resource.RLIMIT_CORE, (0, 0))
    assert order[1][0] == "open"
    assert lfr.GUARD["core_at_first_open"] == 0


def test_mirrored_query_id_rule_matches_the_producer():
    for q in (0, 1021, 1022, 2046, 7733, 31515, (1 << 23) - 2, (1 << 23) - 1026):
        assert lfr.usable_query_id(q)
        assert lfr.next_query_id(q) == TE.next_query_id(q)


# ---------------------------------------------------------------- red controls


def test_pending_row_is_unreconciled(tmp_path):
    fx = build(tmp_path, pending=True)
    code, doc = reconcile(fx, tmp_path)
    assert code == 1 and doc["verdict"] == lfr.UNRECONCILED
    assert doc["populations"]["pending"]["verdict"] == lfr.UNRECONCILED
    assert doc["populations"]["pending"]["count"] == 10
    assert json.loads((fx.state / "qualification-active.json").read_text())["closed"] is False


def test_reservation_without_settlement_is_unreconciled(tmp_path):
    fx = build(tmp_path, inflight=True)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["funding"]["verdict"] == lfr.UNRECONCILED
    assert doc["populations"]["funding"]["inflight_at_end"] == 1
    assert doc["populations"]["open_operations"]["verdict"] == lfr.UNRECONCILED
    assert not doc["launch_eligible"]


def test_unknown_funding_is_unreconciled(tmp_path):
    fx = build(tmp_path, funding_unknown=True)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["funding"]["funding_unknown_events"] == 1
    assert doc["populations"]["funding"]["verdict"] == lfr.UNRECONCILED
    assert doc["verdict"] == lfr.UNRECONCILED


@pytest.mark.parametrize("which", ["qualification", "operations"])
def test_held_lock_is_producer_live_and_stays_held(tmp_path, which):
    fx = build(tmp_path)
    path = (
        fx.state / "qualification.lock"
        if which == "qualification"
        else fx.ceremony / "operations" / ".lock"
    )
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        code, doc = lfr.run(args_for(fx, tmp_path / "public" / "out.json"), rpc=chain_for(fx)[0])
        assert flocked(path)
    finally:
        os.close(fd)
    assert code == 1 and doc["verdict"] == lfr.UNKNOWN_PRODUCER_LIVE
    assert not doc["launch_eligible"]


def test_open_marker_over_clean_populations_is_fence_open_and_unchanged(tmp_path):
    fx = build(tmp_path)
    marker = fx.state / "qualification-active.json"
    atomic_json(marker, {"run": fx.result["run_directory"], "closed": False})
    before = marker.read_bytes()
    code, doc = reconcile(fx, tmp_path)
    assert code == 1 and doc["verdict"] == lfr.FENCE_OPEN
    assert doc["populations"]["fence"]["closed"] is False
    assert marker.read_bytes() == before


def test_counter_below_expected_is_unreconciled(tmp_path):
    fx = build(tmp_path)
    atomic_json(fx.state / "load-state.json", {"next_query_id": 1040, "wallet_timeout": 3600})
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["query_ids"]["counter_verdict"] == lfr.UNRECONCILED
    assert doc["verdict"] == lfr.UNRECONCILED


@pytest.mark.parametrize("value", [-1, 1 << 23, 2047, "1051"])
def test_counter_out_of_bounds_is_unknown(tmp_path, value):
    fx = build(tmp_path)
    atomic_json(fx.state / "load-state.json", {"next_query_id": value, "wallet_timeout": 3600})
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["query_ids"]["counter_verdict"] == lfr.UNKNOWN
    assert not doc["launch_eligible"]


def test_allocated_unlogged_ids_stay_unknown_with_matching_seqnos(tmp_path):
    fx = build(tmp_path, allocate_after=4)
    code, doc = reconcile(fx, tmp_path)
    ids = doc["populations"]["query_ids"]
    assert ids["allocated_unlogged"] == 4 and ids["allocated_unlogged_sample"] == [
        1051,
        1052,
        1053,
        1054,
    ]
    assert ids["verdict"] == lfr.UNKNOWN
    # Relayer seqnos agree with the archive, which does not clear them.
    assert doc["populations"]["chain_relayer_seqno"]["verdict"] == lfr.OBSERVED
    assert doc["verdict"] == lfr.UNKNOWN and not doc["launch_eligible"]


def test_archived_not_offered_carrier_is_never_success(tmp_path):
    fx = build(tmp_path, not_offered_orphan=True)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["outbox"]["archived_not_offered"] == 1
    assert doc["populations"]["outbox"]["verdict"] == lfr.UNKNOWN
    assert doc["populations"]["query_ids"]["gaps_other"] == 3
    assert not doc["launch_eligible"]


def test_torn_last_journal_line_is_unknown(tmp_path):
    fx = build(tmp_path)
    journal = next(p for p in sorted((fx.ceremony / "operations").glob("load-*.jsonl")))
    with journal.open("ab") as out:
        out.write(b'{"state": "settled", "boc": "' + CANARY.encode())
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["open_operations"]["verdict"] == lfr.UNKNOWN
    assert {"code": "torn_last_line"}.items() <= doc["errors"][0].items()
    assert doc["verdict"] == lfr.UNKNOWN


def test_events_hash_mismatch_is_unreconciled(tmp_path):
    fx = build(tmp_path, public={"events_sha": "00" * 32})
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["identity"]["verdict"] == lfr.UNRECONCILED
    assert doc["verdict"] == lfr.UNRECONCILED


def test_closed_audit_offered_mismatch_is_unreconciled(tmp_path):
    fx = build(tmp_path, public={"offered": 49})
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["offered"]["verdict"] == lfr.UNRECONCILED


def test_old_open_operation_is_found_without_a_time_window(tmp_path):
    fx = build(tmp_path, old_open_op=True)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["open_operations"]["open"] == 1
    assert doc["populations"]["open_operations"]["verdict"] == lfr.UNRECONCILED


def test_unexplained_pre_run_owner_row_is_unreconciled(tmp_path):
    fx = build(tmp_path)
    fx.public_files(fx.result, pre_run_tx="66" * 32)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["owner_pre_run_rows"]["verdict"] == lfr.UNRECONCILED


def test_missing_chain_reads_or_disagreeing_sources_are_unknown(tmp_path):
    fx = build(tmp_path)
    code, doc = reconcile(fx, tmp_path, chain_reads=False)
    assert doc["populations"]["chain_relayer_seqno"]["verdict"] == lfr.UNKNOWN
    assert not doc["launch_eligible"]
    rpc, calls = chain_for(fx, {("http://b/jsonRPC", fx.relayers[0]): 99})
    code, doc = reconcile(fx, tmp_path, rpc=rpc, name="out2.json")
    assert doc["populations"]["chain_relayer_seqno"]["verdict"] == lfr.UNKNOWN
    rpc, calls = chain_for(fx, {("http://a/jsonRPC", fx.relayers[1]): None})
    code, doc = reconcile(fx, tmp_path, rpc=rpc, name="out3.json")
    assert doc["populations"]["chain_relayer_seqno"]["verdict"] == lfr.UNKNOWN
    assert set(calls) <= lfr.READ_ONLY_RPC
    code, doc = reconcile(fx, tmp_path, name="out4.json", source=["http://a/jsonRPC"] * 2)
    assert doc["populations"]["chain_relayer_seqno"]["verdict"] == lfr.UNKNOWN


def test_unreadable_proc_locks_is_unstable(tmp_path):
    fx = build(tmp_path)
    code, doc = reconcile(fx, tmp_path, proc=str(tmp_path / "no-such-locks"))
    assert doc["verdict"] == lfr.UNKNOWN_UNSTABLE


def test_change_between_the_two_reads_is_unstable(tmp_path, monkeypatch):
    fx = build(tmp_path)
    original, calls = lfr.collect, []

    def collect(args, reader):
        facts = original(args, reader)
        calls.append(1)
        if len(calls) == 1:
            path = fx.state / fx.result["run_directory"] / "result.json"
            info = path.stat()
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1000))
        return facts

    monkeypatch.setattr(lfr, "collect", collect)
    out = tmp_path / "public" / "out.json"
    code, doc = lfr.run(args_for(fx, out), rpc=chain_for(fx)[0])
    assert doc["verdict"] == lfr.UNKNOWN_UNSTABLE and not doc["stable"]


def test_later_run_or_wrong_run_name_is_unreconciled(tmp_path):
    fx = build(tmp_path)
    prior = sorted(p.name for p in fx.state.glob("qualification-*") if p.is_dir())[0]
    code, doc = reconcile(fx, tmp_path, run=prior, min_query_id=990)
    assert doc["populations"]["identity"]["verdict"] == lfr.UNRECONCILED
    assert doc["populations"]["identity"]["later_runs_present"] is True


def test_symlinked_input_is_refused(tmp_path):
    fx = build(tmp_path)
    marker = fx.state / "qualification-active.json"
    real = fx.tmp / "marker-elsewhere.json"
    real.write_bytes(marker.read_bytes())
    marker.unlink()
    marker.symlink_to(real)
    code, doc = reconcile(fx, tmp_path)
    assert {"input": "state:qualification-active", "code": "unreadable"}.items() <= doc["errors"][
        0
    ].items()
    assert not doc["launch_eligible"]


def test_output_must_be_new_and_outside_the_inputs(tmp_path):
    fx = build(tmp_path)
    existing = tmp_path / "public" / "exists.json"
    existing.write_text("{}")
    with pytest.raises(lfr.Refused):
        lfr.run(args_for(fx, existing), rpc=chain_for(fx)[0])
    with pytest.raises(lfr.Refused):
        lfr.run(args_for(fx, fx.state / "out.json"), rpc=chain_for(fx)[0])
    with pytest.raises(lfr.Refused):
        lfr.run(args_for(fx, fx.ceremony / "out.json"), rpc=chain_for(fx)[0])
    assert not (fx.state / "out.json").exists()


# ---------------------------------------------------------------- projection boundary


def _line(**fields):
    return bytearray(json.dumps(fields, sort_keys=True).encode())


def test_projection_nulls_boc_in_place_before_decoding(monkeypatch):
    seen = []
    real_loads = json.loads

    def loads(text, *a, **k):
        seen.append(bytes(text) if not isinstance(text, str) else text.encode())
        return real_loads(text, *a, **k)

    monkeypatch.setattr(json, "loads", loads)
    buf = _line(state="signed", boc=CANARY * 3, seqno=7, external_hash="ab" * 32)
    doc = lfr.project_line(buf, 0, len(buf), "ops:journal[0]")
    assert doc == {"state": "signed", "seqno": 7, "external_hash": "ab" * 32}
    assert seen and all(CANARY.encode() not in s for s in seen)
    assert CANARY.encode() not in buf


@pytest.mark.parametrize(
    "raw",
    [
        b'{"boc": "' + CANARY.encode() + b'", "boc": "' + CANARY.encode() + b'"}',
        b'{"boc": ["' + CANARY.encode() + b'"]}',
        b'{"\\u0062oc": "' + CANARY.encode() + b'"}',
        b'{"state": "signed", "boc": "' + CANARY.encode() + b'"',
        b'{"state": "signed"} {"boc": "' + CANARY.encode() + b'"}',
        b'{"boc": "' + CANARY.encode() + b'", "x": tru}',
        b'["' + CANARY.encode() + b'"]',
    ],
)
def test_untokenizable_lines_are_wiped_and_never_decoded(monkeypatch, raw):
    decoded = []
    real_loads, real_decode = json.loads, json.JSONDecoder.decode

    def loads(text, *a, **k):
        decoded.append(bytes(text) if not isinstance(text, str) else text.encode())
        return real_loads(text, *a, **k)

    def decode(self, text, *a, **k):
        decoded.append(text.encode())
        return real_decode(self, text, *a, **k)

    monkeypatch.setattr(json, "loads", loads)
    monkeypatch.setattr(json.JSONDecoder, "decode", decode)
    buf = bytearray(raw)
    with pytest.raises(lfr.Refused) as caught:
        lfr.project_line(buf, 0, len(buf), "ops:journal[3]")
    assert all(CANARY.encode() not in d for d in decoded)
    assert CANARY.encode() not in buf
    assert str(caught.value).startswith("line_not_")
    assert CANARY not in str(caught.value) and caught.value.__suppress_context__


def test_decoder_never_sees_a_canary_in_a_full_run(tmp_path, monkeypatch):
    fx = build(tmp_path, allocate_after=2)
    # The allocation record itself carries a planted boc member (condition d).
    saved = json.loads((fx.state / "load-state.json").read_text())
    atomic_json(fx.state / "load-state.json", dict(saved, boc=CANARY * 4))
    inputs, buffers = [], []
    real_loads, real_decode = json.loads, json.JSONDecoder.decode
    real_read = lfr.Reader.read

    def loads(text, *a, **k):
        inputs.append(text if isinstance(text, str) else bytes(text).decode("latin-1"))
        return real_loads(text, *a, **k)

    def decode(self, text, *a, **k):
        inputs.append(text)
        return real_decode(self, text, *a, **k)

    def read(self, *a, **k):
        buf = real_read(self, *a, **k)
        buffers.append(buf)
        return buf

    monkeypatch.setattr(json, "loads", loads)
    monkeypatch.setattr(json.JSONDecoder, "decode", decode)
    monkeypatch.setattr(lfr.Reader, "read", read)
    code, doc = reconcile(fx, tmp_path)
    monkeypatch.undo()
    assert doc["populations"]["query_ids"]["allocated_unlogged"] == 2
    journal_inputs = [i for i in inputs if '"state"' in i]
    assert journal_inputs and all(CANARY not in i for i in inputs)
    assert buffers and all(CANARY.encode() not in b for b in buffers)
    assert all(not any(b) for b in buffers)  # every read buffer was wiped


def test_errors_and_excepthook_carry_no_content(tmp_path, monkeypatch, capsys):
    import sys

    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    err = lfr.Refused("ops:journal[1]", 42, "line_not_json")
    assert str(err) == "line_not_json input=ops:journal[1] offset=42"
    lfr.logical_excepthook(ValueError, ValueError(CANARY), None)
    lfr.logical_excepthook(lfr.Refused, err, None)
    printed = capsys.readouterr().err
    assert CANARY not in printed and "ValueError" in printed and "offset=42" in printed
    fx = build(tmp_path)

    def explode(args, reader):
        raise ValueError(CANARY)

    monkeypatch.setattr(lfr, "run", lambda args: explode(args, None))
    argv = []
    for key, value in vars(args_for(fx, tmp_path / "public" / "x.json")).items():
        flag = "--" + key.replace("_", "-")
        if isinstance(value, bool):
            argv += [flag] if value else []
        elif isinstance(value, list):
            for item in value:
                argv += [flag, item]
        else:
            argv += [flag, str(value)]
    assert lfr.main(argv) == 4
    printed = capsys.readouterr().err
    assert CANARY not in printed and printed.strip() == "load_fence_reconcile: ValueError"
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)


# ---------------------------------------------------------------- guard and scan


@pytest.mark.parametrize(
    "name",
    ["highload.key", "relayer-0.pk", "highload.init.boc", "relayer-0-query.boc", "gid.fif"],
)
def test_reader_refuses_denied_names(tmp_path, name):
    fx = build(tmp_path)
    reader = lfr.Reader()
    fd = reader.root(str(fx.state), "state:root")
    with pytest.raises(lfr.Refused) as caught:
        reader.read(fd, name, "state:x", 1 << 20)
    reader.close()
    assert caught.value.code == "denied_name"


@pytest.mark.parametrize(
    "relative",
    [
        "state/highload.key",
        "state/relayer-1.pk",
        "state/highload.init.boc",
        "ceremony/secret/pool-owner-node-4.pk",
        "ceremony/sent/20261105T000000Z-owner-node-4-seq1-x.boc",
        "state/dry-run-20261105T000000Z/dry-run.json",
        "state/qualification.lock",
    ],
)
def test_audit_hook_blocks_denied_opens_while_active(tmp_path, relative):
    fx = build(tmp_path)
    lfr.install_guard()
    lfr.GUARD.update(active=True, violations=0)
    try:
        with pytest.raises(PermissionError):
            os.open(tmp_path / relative, os.O_RDONLY)
        with pytest.raises(PermissionError):
            open(tmp_path / relative, "rb")
        with pytest.raises(PermissionError):
            os.open(tmp_path / "public" / "write.json", os.O_WRONLY | os.O_CREAT, 0o600)
        assert lfr.GUARD["violations"] == 3
    finally:
        lfr.GUARD.update(active=False, violations=0)
    assert fx is not None


def test_a_denied_open_inside_a_run_writes_nothing(tmp_path, monkeypatch):
    fx = build(tmp_path)
    original = lfr.collect

    def collect(args, reader):
        try:
            os.open(Path(args.state) / "relayer-0.pk", os.O_RDONLY)
        except PermissionError:
            pass
        return original(args, reader)

    monkeypatch.setattr(lfr, "collect", collect)
    out = tmp_path / "public" / "out.json"
    code, doc = lfr.run(args_for(fx, out), rpc=chain_for(fx)[0])
    assert (code, doc) == (3, None) and not out.exists()
    lfr.GUARD["violations"] = 0


@pytest.mark.parametrize(
    "document",
    [
        {"label": "A" * 48},
        {"events_sha256": "zz" * 32},
        {"count": "ab" * 33},
        {"highload_address": "0:" + "ab" * 31},
        {"boc_x": 1},
        {"note": "/private-load-state"},
        {"note": "highload.key"},
        {"note": "anything else"},
        {"value": 1.5},
    ],
)
def test_secret_scan_rejects_untyped_strings(document):
    assert lfr.scan(document)


def test_secret_scan_hit_writes_nothing(tmp_path, monkeypatch):
    fx = build(tmp_path)
    real = lfr.evaluate

    def evaluate(*a, **k):
        body = real(*a, **k)
        body["populations"]["offered"]["sample"] = [base64.b64encode(CANARY.encode() * 4).decode()]
        return body

    monkeypatch.setattr(lfr, "evaluate", evaluate)
    out = tmp_path / "public" / "out.json"
    code, doc = lfr.run(args_for(fx, out), rpc=chain_for(fx)[0])
    assert (code, doc) == (2, None) and not out.exists()
