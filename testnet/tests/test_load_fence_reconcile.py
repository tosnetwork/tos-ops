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
from load_finality_window import AdmissionClosed
from load_qualification import Qualification, atomic_json
from testnet_support import SCRIPTS

CANARY = "CANARYc4n4ryZQXJ"
IDENTITY = {"global_id": 2, "genesis_root": "aa" * 32, "genesis_file": "bb" * 32}
OWNER = "0:" + "0f" * 32
OPERATOR = "0:" + "0e" * 32
OPERATOR2 = "0:" + "0d" * 32
PRE_RUN_TX = "77" * 32


def _te():
    spec = importlib.util.spec_from_file_location(
        "te_for_reconcile", SCRIPTS / "testnet-elections.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TE = _te()

# The 62 R2 funding reservations total 329.255545444 TOS; three amounts with that sum.
AMOUNTS = (4_088_828_819, 4_359_939_132, 320_806_777_493)
assert sum(AMOUNTS) == 329_255_545_444


@pytest.fixture(autouse=True)
def system_tmp(monkeypatch):
    """pytest's base directory lives under the system-owned, sticky /tmp."""
    monkeypatch.setattr(lfr, "SYSTEM_PREFIXES", lfr.SYSTEM_PREFIXES | {"/tmp"})


class FakeNative:
    """The observer interface Qualification uses (attach_native, offer, summary)."""

    def __init__(self):
        self.offered = self.finalized = 0
        self.pending = 0
        self.closed = False

    def assert_healthy(self):
        pass

    def offer(self, hashes):
        if self.closed:
            raise AdmissionClosed("test-boot", time.monotonic(), time.monotonic())
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

    def batch(
        self, relayer, count, *, terminal=True, archive_only=False, not_offered=False, skip=False
    ):
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
        if not_offered:
            self.native.closed = True
            with pytest.raises(AdmissionClosed):
                self.q.offer(ids, carrier, hashes)
            self.native.closed = False
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
                query_ids=ids[:-1] if skip else ids,
                summary=self.native.summary(),
            )
        else:
            self.native.finalized += len(ids) - 1
            self.native.pending += 1
        return ids

    def fund(self, label, amount, destination, *, settle=True, fail=False, kind="owner-fund"):
        self.q.reserve_funding(amount, label)
        op_id = f"load-{label}-{time.strftime('%Y%m%dt%H%M%S', time.gmtime())}-{amount}"
        tx = self.fx.journal_op(
            op_id,
            OWNER,
            destination,
            amount,
            {"label": label, "purpose": "load", "kind": kind},
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
        # A literal canary inside the signed value, so any copy of it is detectable.
        boc = CANARY + base64.b64encode(f"signed-message-{op_id}".encode() * 4).decode()
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
            "addresses_by_label": overrides.get(
                "addresses_by_label", {m["label"]: m["to"] for m in self.matches}
            ),
            "count": len(self.matches),
            "total_nanotos": sum(m["amount_nanotos"] for m in self.matches),
            "matches": self.matches,
            "unmatched_owner_rows": [{"hash": overrides.get("pre_run_tx", PRE_RUN_TX)}],
        }
        for name, value in (
            ("closed-audit.json", audit),
            ("reservations.json", reservations),
            ("owner-matches.json", matches),
            (
                "expected-wallets.json",
                overrides.get(
                    "expected_wallets",
                    {
                        "highload": self.highload,
                        "funding_owner": OWNER,
                        "relayers": self.relayers,
                        "operators": [OPERATOR, OPERATOR2],
                    },
                ),
            ),
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
    if opts.get("gap_between_runs"):
        fx.drv.take_query_ids(2)
    target = Producer(fx)
    target.fund(
        "load-relayer-0",
        AMOUNTS[0],
        fx.relayers[1] if opts.get("wrong_destination") else fx.relayers[0],
        kind=opts.get("funding_kind", "owner-fund"),
    )
    target.fund("load-relayer-1", AMOUNTS[1], fx.relayers[1])
    target.batch(0, 20)
    if opts.get("mid_run_gap"):
        fx.drv.take_query_ids(3)
    target.batch(1, 20, skip=opts.get("native_skip", False))
    if opts.get("not_offered_orphan"):
        target.batch(0, 3, archive_only=True)
    if opts.get("not_offered"):
        target.batch(0, 3, not_offered=True)
    if opts.get("stray_load"):
        fx.journal_op(
            "load-load-refill-9-stray",
            OWNER,
            fx.relayers[0],
            5,
            {"label": "load-refill-9", "purpose": "load"},
        )
    if opts.get("open_op_wallet"):
        fx.journal_op(
            "fund-op-mixed-case", opts["open_op_wallet"], OPERATOR, 7, {}, state="planned"
        )
    target.fund("load-refill-0", AMOUNTS[2], fx.relayers[0], settle=not opts.get("inflight"))
    target.batch(1, 10, terminal=not opts.get("pending"))
    if opts.get("extra_accepted"):
        target.q.event("accepted", query_id=5000, offered_latency_seconds=0.1)
    if opts.get("empty_offer"):
        target.q.event("offered", query_ids=[], carrier_bytes=1, signed_request_hashes={})
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
        expected_wallets=str(fx.public / "expected-wallets.json"),
        expected_relayer_count=kw.get("expected_relayer_count", 2),
        expected_operator_count=kw.get("expected_operator_count", 2),
        global_id=2,
        genesis_root=IDENTITY["genesis_root"],
        genesis_file=IDENTITY["genesis_file"],
        min_query_id=kw.get("min_query_id", 1000),
        chain_reads=kw.get("chain_reads", True),
        source=kw.get("source", ["http://a/jsonRPC", "http://b/jsonRPC"]),
    )


def argv_for(args):
    argv = []
    for key, value in vars(args).items():
        flag = "--" + key.replace("_", "-")
        if isinstance(value, bool):
            argv += [flag] if value else []
        elif isinstance(value, list):
            for item in value:
                argv += [flag, item]
        else:
            argv += [flag, str(value)]
    return argv


def chain_for(fx, overrides=None):
    calls = []
    seqno = {fx.relayers[i]: n for i, n in fx.seqnos.items()}

    def rpc(url, method, /, **params):
        calls.append(method)
        if method == "getMasterchainInfo":
            return {"last": {"seqno": 1_460_923}}
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
    assert set(verdicts(doc).values()) == {lfr.RECONCILED}
    chain = doc["chain_observation"]
    assert chain["observation_only"] is True
    assert chain["sources"] == [
        {"index": 0, "masterchain_seqno": 1_460_923},
        {"index": 1, "masterchain_seqno": 1_460_923},
    ]
    assert chain["sources_agree"] is True and chain["outbox_consistent"] is True
    assert [r["matches_outbox"] for r in chain["relayers"]] == [True, True]
    assert doc["populations"]["funding"]["total_nanotos"] == 329_255_545_444
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
    assert doc["chain_observation"]["outbox_consistent"] is True
    assert doc["chain_observation"]["sources_agree"] is True
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


def test_chain_reads_are_observation_only(tmp_path):
    fx = build(tmp_path)
    # One source disagrees: reported, no verdict changes.
    rpc, calls = chain_for(fx, {("http://b/jsonRPC", fx.relayers[0]): 99})
    code, doc = reconcile(fx, tmp_path, rpc=rpc, name="out1.json")
    chain = doc["chain_observation"]
    assert chain["sources_agree"] is False and chain["relayers"][0]["sources_agree"] is False
    assert chain["relayers"][0]["observed"] == [2, 99]
    assert doc["verdict"] == lfr.ELIGIBLE and code == 0
    # Both sources agree on a seqno the archive does not explain: reported only.
    rpc, calls = chain_for(
        fx, {("http://a/jsonRPC", fx.relayers[0]): 99, ("http://b/jsonRPC", fx.relayers[0]): 99}
    )
    code, doc = reconcile(fx, tmp_path, rpc=rpc, name="out2.json")
    chain = doc["chain_observation"]
    assert chain["sources_agree"] is True and chain["outbox_consistent"] is False
    assert chain["relayers"][0]["matches_outbox"] is False
    assert doc["verdict"] == lfr.ELIGIBLE
    # An unavailable source: reported as null.
    rpc, calls = chain_for(fx, {("http://a/jsonRPC", fx.relayers[1]): None})
    code, doc = reconcile(fx, tmp_path, rpc=rpc, name="out3.json")
    assert doc["chain_observation"]["relayers"][1]["observed"] == [None, 3]
    assert doc["chain_observation"]["sources_agree"] is False
    assert doc["verdict"] == lfr.ELIGIBLE
    assert set(calls) <= lfr.READ_ONLY_RPC and "sendBoc" not in calls


def test_parse_requires_chain_reads_and_raw_addresses(tmp_path):
    fx = build(tmp_path)
    base = argv_for(args_for(fx, tmp_path / "public" / "x.json"))
    assert lfr.parse(base).funding_owner_address == OWNER
    with pytest.raises(SystemExit):
        lfr.parse([a for a in base if a != "--chain-reads"])
    with pytest.raises(SystemExit):
        lfr.parse([*base[: base.index("--source")], "--source", "http://a/jsonRPC"])
    bad = list(base)
    bad[bad.index("--funding-owner-address") + 1] = "EQ" + "A" * 46
    with pytest.raises(SystemExit):
        lfr.parse(bad)
    zero = list(base)
    zero[zero.index("--expected-operator-count") + 1] = "0"
    with pytest.raises(SystemExit):
        lfr.parse(zero)
    upper = list(base)
    upper[upper.index("--funding-owner-address") + 1] = OWNER.upper()
    assert lfr.parse(upper).funding_owner_address == OWNER


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
    assert lfr.main(argv_for(args_for(fx, tmp_path / "public" / "x.json"))) == 4
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


# ---------------------------------------------------------------- one red control per guard


def same_size_edit(path, old, new):
    """Change bytes in place, same length, with the old mtime: only a content
    digest can see it."""
    assert len(old) == len(new)
    info = path.stat()
    data = path.read_bytes()
    assert data.count(old) >= 1
    path.write_bytes(data.replace(old, new, 1))
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))


def between_reads(monkeypatch, action):
    original, calls = lfr.collect, []

    def collect(args, reader):
        facts = original(args, reader)
        calls.append(1)
        # The test, not the helper, changes the tree: outside the guard.
        lfr.GUARD["active"] = False
        try:
            action(len(calls))
        finally:
            lfr.GUARD["active"] = True
        return facts

    monkeypatch.setattr(lfr, "collect", collect)


def run_plain(fx, tmp_path, name="out.json", rpc=None, **kw):
    out = tmp_path / "public" / name
    return lfr.run(args_for(fx, out, **kw), rpc=rpc or chain_for(fx)[0])


def test_pending_run_also_fails_executed_and_closed_unsafe_fence(tmp_path):
    fx = build(tmp_path, pending=True)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["executed_unconfirmed"]["verdict"] == lfr.UNRECONCILED
    assert doc["populations"]["fence"]["verdict"] == lfr.RECONCILED  # open over unsafe
    atomic_json(
        fx.state / "qualification-active.json", {"run": fx.result["run_directory"], "closed": True}
    )
    code, doc = reconcile(fx, tmp_path, name="out2.json")
    assert doc["populations"]["fence"]["verdict"] == lfr.UNRECONCILED


def test_native_capture_missing_one_offered_id_is_unreconciled(tmp_path):
    fx = build(tmp_path, native_skip=True)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["native_finalized"]["missing"] == 1
    assert doc["populations"]["native_finalized"]["verdict"] == lfr.UNRECONCILED
    assert doc["verdict"] == lfr.UNRECONCILED


def test_public_reservation_pairs_must_match(tmp_path):
    fx = build(tmp_path)
    path = fx.public / "reservations.json"
    rows = json.loads(path.read_text())
    rows[0]["amount_nanotos"], rows[1]["amount_nanotos"] = (
        rows[1]["amount_nanotos"],
        rows[0]["amount_nanotos"],
    )
    path.write_text(json.dumps(rows))
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["funding"]["verdict"] == lfr.UNRECONCILED
    assert doc["verdict"] == lfr.UNRECONCILED


def test_owner_match_total_must_equal_the_reserved_total(tmp_path):
    fx = build(tmp_path)
    path = fx.public / "owner-matches.json"
    matches = json.loads(path.read_text())
    assert matches["total_nanotos"] == 329_255_545_444
    matches["total_nanotos"] += 1
    path.write_text(json.dumps(matches))
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["funding"]["verdict"] == lfr.UNRECONCILED


def test_ids_allocated_mid_run_but_never_offered_stay_unknown(tmp_path):
    fx = build(tmp_path, mid_run_gap=True)
    code, doc = reconcile(fx, tmp_path)
    ids = doc["populations"]["query_ids"]
    assert ids["gaps_other"] == 3 and ids["gaps_other_sample"] == [1020, 1021, 1022]
    assert ids["verdict"] == lfr.UNKNOWN
    assert doc["populations"]["outbox"]["verdict"] == lfr.RECONCILED
    assert doc["verdict"] == lfr.UNKNOWN and not doc["launch_eligible"]


def test_ids_burned_between_runs_leave_the_start_unknown(tmp_path):
    fx = build(tmp_path, gap_between_runs=True)
    code, doc = reconcile(fx, tmp_path, min_query_id=1002)
    ids = doc["populations"]["query_ids"]
    assert (ids["reconstructed_start"], ids["min"]) == (1000, 1002)
    assert ids["start_verdict"] == lfr.UNKNOWN and ids["verdict"] == lfr.UNKNOWN
    assert not doc["launch_eligible"]


def test_offers_below_the_declared_minimum_are_unreconciled(tmp_path):
    fx = build(tmp_path)
    code, doc = reconcile(fx, tmp_path, min_query_id=1001)
    assert doc["populations"]["query_ids"]["start_verdict"] == lfr.UNRECONCILED
    assert doc["verdict"] == lfr.UNRECONCILED


def test_a_reader_error_alone_blocks_eligibility(tmp_path):
    fx = build(tmp_path)
    (fx.state / "relayer-5.addr").write_bytes(b"short")
    code, doc = reconcile(fx, tmp_path)
    assert set(verdicts(doc).values()) == {lfr.RECONCILED}
    assert doc["errors"][0]["code"] == "not_an_address_file"
    assert doc["verdict"] == lfr.UNKNOWN and not doc["launch_eligible"]


def test_same_size_events_change_between_reads_is_unstable(tmp_path, monkeypatch):
    fx = build(tmp_path)
    events = fx.state / fx.result["run_directory"] / "events.jsonl"
    digest = hashlib.sha256(b"req1000").hexdigest().encode()
    flipped = digest[:-1] + (b"0" if digest[-1:] != b"0" else b"1")
    between_reads(monkeypatch, lambda n: n == 1 and same_size_edit(events, digest, flipped))
    code, doc = run_plain(fx, tmp_path)
    assert doc["verdict"] == lfr.UNKNOWN_UNSTABLE and not doc["stable"]


def test_same_size_journal_change_between_reads_is_unstable(tmp_path, monkeypatch):
    fx = build(tmp_path)
    journal = next(iter(sorted((fx.ceremony / "operations").glob("load-load-relayer-0-*"))))
    old = f'"value": {AMOUNTS[0]}'.encode()
    new = f'"value": {AMOUNTS[0] - 1}'.encode()
    between_reads(monkeypatch, lambda n: n == 1 and same_size_edit(journal, old, new))
    code, doc = run_plain(fx, tmp_path)
    assert doc["verdict"] == lfr.UNKNOWN_UNSTABLE


def test_same_size_identity_change_between_reads_is_unstable(tmp_path, monkeypatch):
    fx = build(tmp_path)
    identity = fx.state / "qualification-identity.json"
    between_reads(monkeypatch, lambda n: n == 1 and same_size_edit(identity, b'"aaaa', b'"aaab'))
    code, doc = run_plain(fx, tmp_path)
    assert doc["verdict"] == lfr.UNKNOWN_UNSTABLE


def test_archive_change_between_reads_is_unstable(tmp_path, monkeypatch):
    fx = build(tmp_path, not_offered_orphan=True)
    outbox = fx.state / fx.result["run_directory"] / "private-outbox"
    orphan = [p for p in outbox.iterdir() if p.name.startswith("ext-0-2-")]
    assert len(orphan) == 1
    between_reads(monkeypatch, lambda n: n == 1 and orphan[0].unlink())
    code, doc = run_plain(fx, tmp_path)
    assert doc["verdict"] == lfr.UNKNOWN_UNSTABLE


def test_summary_hash_must_match_the_closed_audit(tmp_path):
    fx = build(tmp_path, public={"summary_sha": "00" * 32})
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["identity"]["verdict"] == lfr.UNRECONCILED


def test_stray_load_funding_during_the_run_is_unreconciled(tmp_path):
    fx = build(tmp_path, stray_load=True)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["owner_during_run"]["load_unmatched"] == 1
    assert doc["populations"]["owner_during_run"]["verdict"] == lfr.UNRECONCILED
    assert doc["populations"]["funding_journal"]["verdict"] == lfr.RECONCILED
    assert doc["verdict"] == lfr.UNRECONCILED


def test_reservation_without_a_matching_owner_transaction_is_unreconciled(tmp_path):
    fx = build(tmp_path)
    fx.matches[0]["transaction"] = "55" * 32
    fx.public_files(fx.result, pre_run_tx=PRE_TX[0])
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["funding"]["verdict"] == lfr.RECONCILED
    assert doc["populations"]["funding_journal"]["unmatched"] == 1
    assert doc["populations"]["funding_journal"]["verdict"] == lfr.UNRECONCILED


def test_not_offered_ids_are_unreconciled(tmp_path):
    fx = build(tmp_path, not_offered=True)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["not_offered"]["count"] == 3
    assert doc["populations"]["not_offered"]["verdict"] == lfr.UNRECONCILED
    assert doc["populations"]["outbox"]["verdict"] == lfr.RECONCILED
    assert doc["verdict"] == lfr.UNRECONCILED


def test_accepted_outside_the_offers_is_unreconciled(tmp_path):
    fx = build(tmp_path, extra_accepted=True)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["accepted"]["verdict"] == lfr.UNRECONCILED
    assert doc["verdict"] == lfr.UNRECONCILED


def test_offered_event_without_ids_is_unreconciled_not_a_crash(tmp_path):
    fx = build(tmp_path, empty_offer=True)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["offered"]["malformed_events"] == 1
    assert doc["populations"]["offered"]["verdict"] == lfr.UNRECONCILED


def test_lock_taken_between_the_reads_is_producer_live(tmp_path, monkeypatch):
    fx = build(tmp_path)
    held = []

    def take(n):
        if n == 2:
            fd = os.open(fx.state / "qualification.lock", os.O_RDWR)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            held.append(fd)

    between_reads(monkeypatch, take)
    try:
        code, doc = run_plain(fx, tmp_path)
    finally:
        for fd in held:
            os.close(fd)
    assert doc["verdict"] == lfr.UNKNOWN_PRODUCER_LIVE


def test_archive_size_mismatch_is_unreconciled(tmp_path):
    fx = build(tmp_path)
    outbox = fx.state / fx.result["run_directory"] / "private-outbox"
    archive = sorted(outbox.iterdir())[0]
    with archive.open("ab") as out:
        out.write(b"x")
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["outbox"]["size_mismatches"] == 1
    assert doc["populations"]["outbox"]["verdict"] == lfr.UNRECONCILED


def test_inputs_owned_by_another_uid_are_refused(tmp_path, monkeypatch):
    fx = build(tmp_path)
    real = os.geteuid()
    monkeypatch.setattr(lfr.os, "geteuid", lambda: real + 1)
    code, doc = run_plain(fx, tmp_path)
    monkeypatch.undo()
    assert {"input": "state:root", "code": "not_owned_or_wrong_type"}.items() <= doc["errors"][
        0
    ].items()
    assert not doc["launch_eligible"]


def test_journal_line_with_an_unknown_state_is_unknown(tmp_path):
    fx = build(tmp_path)
    journal = next(iter(sorted((fx.ceremony / "operations").glob("load-*.jsonl"))))
    ops.append_line(journal, {"state": "resubmitted"})
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["open_operations"]["verdict"] == lfr.UNKNOWN
    assert any(e["code"] == "state" for e in doc["errors"])


def test_open_operation_in_another_address_case_is_found(tmp_path):
    fx = build(tmp_path, open_op_wallet=OWNER.upper().replace("0X", "0x"))
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["open_operations"]["open"] == 1
    assert doc["populations"]["open_operations"]["verdict"] == lfr.UNRECONCILED


def test_open_operation_with_an_unparsed_wallet_is_unknown(tmp_path):
    fx = build(tmp_path, open_op_wallet="EQ" + "A" * 46)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["open_operations"]["open_with_unparsed_wallet"] == 1
    assert doc["populations"]["open_operations"]["verdict"] == lfr.UNKNOWN


def test_run_refuses_malformed_address_arguments(tmp_path):
    fx = build(tmp_path)
    args = args_for(fx, tmp_path / "public" / "out.json")
    args.funding_owner_address = "0:" + "ab" * 31
    with pytest.raises(lfr.Refused) as caught:
        lfr.run(args, rpc=chain_for(fx)[0])
    assert caught.value.code == "bad_address"


def test_parent_directory_symlink_is_refused(tmp_path):
    fx = build(tmp_path)
    (tmp_path / "alias").symlink_to(tmp_path)
    args = args_for(fx, tmp_path / "public" / "out.json")
    args.state = str(tmp_path / "alias" / "state")
    code, doc = lfr.run(args, rpc=chain_for(fx)[0])
    assert {"input": "state:root", "code": "root_unavailable"}.items() <= doc["errors"][0].items()
    assert not doc["launch_eligible"]


def test_public_parent_symlink_is_refused(tmp_path):
    fx = build(tmp_path)
    (tmp_path / "alias").symlink_to(tmp_path / "public")
    args = args_for(fx, tmp_path / "public" / "out.json")
    args.reservations = str(tmp_path / "alias" / "reservations.json")
    code, doc = lfr.run(args, rpc=chain_for(fx)[0])
    assert any(
        e["input"] == "public:reservations-dir" and e["code"] == "root_unavailable"
        for e in doc["errors"]
    )


def test_system_prefix_rules():
    def info(mode, uid):
        return os.stat_result((mode, 1, 1, 1, uid, 0, 0, 0, 0, 0))

    lfr._check_system(info(0o040755, 0), "x")
    lfr._check_system(info(0o041777, 0), "x")
    for bad in (info(0o040777, 0), info(0o040775, 0), info(0o040755, 4242), info(0o100755, 0)):
        with pytest.raises(lfr.Refused):
            lfr._check_system(bad, "x")


def test_root_that_is_only_a_system_prefix_is_refused(tmp_path):
    reader = lfr.Reader()
    with pytest.raises(lfr.Refused):
        reader.root("/tmp", "state:root")
    reader.close()


def test_public_inputs_inside_the_state_or_ceremony_are_refused(tmp_path):
    fx = build(tmp_path)
    for target in (
        fx.state / "qualification-active.json",
        next(iter((fx.ceremony / "operations").glob("load-*.jsonl"))),
    ):
        args = args_for(fx, tmp_path / "public" / "out.json")
        args.reservations = str(target)
        with pytest.raises(lfr.Refused) as caught:
            lfr.run(args, rpc=chain_for(fx)[0])
        assert caught.value.input_id == "public:reservations"


def test_partial_read_and_probe_buffers_are_wiped(tmp_path, monkeypatch):
    fx = build(tmp_path)
    seen = []
    real = os.readv

    def failing(fd, buffers):
        target = buffers[0].obj if isinstance(buffers[0], memoryview) else buffers[0]
        seen.append(target)
        buffers[0][0:6] = b"CANARY"
        raise OSError("read failed")

    monkeypatch.setattr(lfr.os, "readv", failing)
    reader = lfr.Reader()
    fd = reader.root(str(fx.state), "state:root")
    with pytest.raises(lfr.Refused) as caught:
        reader.read(fd, "qualification-active.json", "state:qualification-active", 1 << 20)
    assert caught.value.code == "unreadable"
    assert seen and all(b"CANARY" not in bytes(b) for b in seen)

    def growing(fd, buffers):
        target = buffers[0].obj if isinstance(buffers[0], memoryview) else buffers[0]
        seen.append(target)
        if len(buffers[0]) == 1 and isinstance(buffers[0], bytearray):
            buffers[0][0:1] = b"C"
            return 1
        return real(fd, buffers)

    seen.clear()
    monkeypatch.setattr(lfr.os, "readv", growing)
    with pytest.raises(lfr.Refused) as caught:
        reader.read(fd, "qualification-active.json", "state:qualification-active", 1 << 20)
    reader.close()
    assert caught.value.code == "changed_while_read"
    assert len(seen) >= 2 and all(not any(b) for b in seen)


# ---------------------------------------------------------------- wallet set and attribution


def test_missing_relayer_file_with_an_open_operation_blocks(tmp_path):
    fx = build(tmp_path)
    fx.journal_op("fund-op-relayer-1", fx.relayers[1], OPERATOR, 3, {}, state="planned")
    (fx.state / "relayer-1.addr").unlink()
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["wallets"]["missing_relayers"] == 1
    assert doc["populations"]["wallets"]["verdict"] == lfr.UNRECONCILED
    assert doc["populations"]["open_operations"]["open"] == 1
    assert not doc["launch_eligible"]


def test_extra_or_mismatched_relayer_file_is_unreconciled(tmp_path):
    fx = build(tmp_path)
    (fx.state / "relayer-2.addr").write_bytes(address_bytes(0xA2))
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["wallets"]["extra_relayers"] == 1
    assert doc["populations"]["wallets"]["verdict"] == lfr.UNRECONCILED
    (fx.state / "relayer-2.addr").unlink()
    (fx.state / "relayer-1.addr").write_bytes(address_bytes(0xA3))
    code, doc = reconcile(fx, tmp_path, name="out2.json")
    assert doc["populations"]["wallets"]["mismatched_relayers"] == 1
    assert doc["populations"]["wallets"]["verdict"] == lfr.UNRECONCILED


def test_omitted_operator_is_unreconciled(tmp_path):
    fx = build(tmp_path)
    fx.public_files(
        fx.result,
        pre_run_tx=PRE_TX[0],
        expected_wallets={
            "highload": fx.highload,
            "funding_owner": OWNER,
            "relayers": fx.relayers,
            "operators": [OPERATOR],
        },
    )
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["wallets"]["operators"] == 1
    assert doc["populations"]["wallets"]["verdict"] == lfr.UNRECONCILED
    assert not doc["launch_eligible"]


def test_open_operation_outside_the_expected_wallets_is_unknown(tmp_path):
    fx = build(tmp_path)
    fx.journal_op("fund-op-operator-2", OPERATOR2, OWNER, 3, {}, state="planned")
    fx.public_files(
        fx.result,
        pre_run_tx=PRE_TX[0],
        expected_wallets={
            "highload": fx.highload,
            "funding_owner": OWNER,
            "relayers": fx.relayers,
            "operators": [OPERATOR],
        },
    )
    code, doc = reconcile(fx, tmp_path, expected_operator_count=1)
    assert doc["populations"]["wallets"]["verdict"] == lfr.RECONCILED
    assert doc["populations"]["open_operations"]["open_outside_expected_wallets"] == 1
    assert doc["populations"]["open_operations"]["verdict"] == lfr.UNKNOWN
    assert not doc["launch_eligible"]


def test_relayer_count_and_funding_labels_bind_to_public_evidence(tmp_path):
    fx = build(tmp_path)
    code, doc = reconcile(fx, tmp_path, expected_relayer_count=4)
    assert doc["populations"]["wallets"]["verdict"] == lfr.UNRECONCILED
    fx.public_files(
        fx.result,
        pre_run_tx=PRE_TX[0],
        addresses_by_label={"load-relayer-0": fx.relayers[0], "load-relayer-1": fx.relayers[0]},
    )
    code, doc = reconcile(fx, tmp_path, name="out2.json")
    assert doc["populations"]["wallets"]["unmatched_funding_labels"] == 1
    assert doc["populations"]["wallets"]["verdict"] == lfr.UNRECONCILED


def test_malformed_expected_wallets_file_is_unknown(tmp_path):
    fx = build(tmp_path)
    fx.public_files(
        fx.result,
        pre_run_tx=PRE_TX[0],
        expected_wallets={
            "highload": fx.highload,
            "funding_owner": OWNER,
            "relayers": [fx.relayers[0], fx.relayers[0]],
            "operators": [OPERATOR, OPERATOR2],
        },
    )
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["wallets"]["verdict"] == lfr.UNKNOWN
    assert doc["populations"]["funding_journal"]["verdict"] == lfr.UNRECONCILED
    assert not doc["launch_eligible"]


def test_funding_to_the_wrong_relayer_is_unreconciled(tmp_path):
    fx = build(tmp_path, wrong_destination=True)
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["funding_journal"]["unmatched"] == 1
    assert doc["populations"]["funding_journal"]["verdict"] == lfr.UNRECONCILED


def test_public_match_destination_must_equal_the_journal_destination(tmp_path):
    fx = build(tmp_path)
    fx.matches[0]["to"] = OPERATOR
    fx.public_files(
        fx.result,
        pre_run_tx=PRE_TX[0],
        addresses_by_label={"load-relayer-0": fx.relayers[0], "load-relayer-1": fx.relayers[1]},
    )
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["wallets"]["verdict"] == lfr.RECONCILED
    assert doc["populations"]["funding_journal"]["verdict"] == lfr.UNRECONCILED


def test_funding_of_another_operation_kind_is_unreconciled(tmp_path):
    fx = build(tmp_path, funding_kind="top-up")
    code, doc = reconcile(fx, tmp_path)
    assert doc["populations"]["funding_journal"]["verdict"] == lfr.UNRECONCILED


def test_same_size_prior_events_change_between_reads_is_unstable(tmp_path, monkeypatch):
    fx = build(tmp_path)
    prior = sorted(p for p in fx.state.glob("qualification-*") if p.is_dir())[0]
    events = prior / "events.jsonl"
    digest = hashlib.sha256(b"req990").hexdigest().encode()
    flipped = digest[:-1] + (b"0" if digest[-1:] != b"0" else b"1")
    between_reads(monkeypatch, lambda n: n == 1 and same_size_edit(events, digest, flipped))
    code, doc = run_plain(fx, tmp_path)
    assert doc["verdict"] == lfr.UNKNOWN_UNSTABLE


# ---------------------------------------------------------------- bounded journal lines


def test_journal_lines_are_decoded_with_only_their_own_bytes_live(tmp_path, monkeypatch):
    fx = build(tmp_path)
    live, decoded = [], []
    real_line, real_read = lfr.Reader._line_buffer, lfr.Reader.read
    real_loads = json.loads

    def line_buffer(self):
        buf = real_line(self)
        live.append(buf)
        return buf

    def read(self, *a, **k):
        buf = real_read(self, *a, **k)
        live.append(buf)
        return buf

    def loads(text, *a, **k):
        raw = bytes(text) if not isinstance(text, str) else text.encode()
        decoded.append(raw)
        assert CANARY.encode() not in raw
        # No live buffer holds a signed value at decode time: not this line's
        # (nulled), and no other line's (never read ahead or kept).
        assert all(CANARY.encode() not in bytes(b) for b in live)
        return real_loads(text, *a, **k)

    monkeypatch.setattr(lfr.Reader, "_line_buffer", line_buffer)
    monkeypatch.setattr(lfr.Reader, "read", read)
    monkeypatch.setattr(json, "loads", loads)
    code, doc = reconcile(fx, tmp_path)
    monkeypatch.undo()
    assert code == 0 and live and any(b'"state"' in d for d in decoded)
    assert all(not any(b) for b in live)


def test_overlong_journal_line_is_unknown_without_content(tmp_path, monkeypatch):
    fx = build(tmp_path)
    monkeypatch.setattr(lfr, "MAX_LINE_BYTES", 300)
    code, doc = reconcile(fx, tmp_path)
    assert any(e["code"] == "line_too_long" for e in doc["errors"])
    assert doc["populations"]["open_operations"]["verdict"] == lfr.UNKNOWN
    assert CANARY not in json.dumps(doc)


@pytest.mark.parametrize("escape", [b"\\q", b"\\uZZZZ", b"\\u12", b"\\x41", b"\\\x01", b"\x1f"])
def test_invalid_escape_inside_boc_is_refused_and_wiped(escape):
    raw = b'{"boc": "' + CANARY.encode() + escape + b'tail", "state": "signed"}'
    buf = bytearray(raw)
    with pytest.raises(lfr.Refused) as caught:
        lfr.project_line(buf, 0, len(buf), "ops:journal[0]")
    assert caught.value.code == "line_not_tokenizable"
    assert CANARY.encode() not in buf


def test_valid_escapes_inside_boc_are_nulled():
    raw = b'{"boc": "' + CANARY.encode() + b'\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9", "state": "signed"}'
    buf = bytearray(raw)
    assert lfr.project_line(buf, 0, len(buf), "ops:journal[0]") == {"state": "signed"}
    assert CANARY.encode() not in buf
