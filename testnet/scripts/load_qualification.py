"""Bounded, durable evidence for an explicitly qualified load run.

No keys or message bodies enter this journal. Funding reservations never roll back
on an unknown result. An unfinished run refuses a new run rather than replaying it.
"""

import base64
import fcntl
import json
import os
import stat
import threading
import time
from pathlib import Path

import testnet_lib as lib
from load_finality_window import AdmissionClosed

BUCKETS = (0.1, 0.25, 0.5, 1, 2, 3, 5, 10, 20, 30, 60, 120, 300)
QUERY_LIMIT = 1 << 23
MAX_CARRIER_BYTES = 1 << 20


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value):
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as out:
        os.chmod(tmp, 0o600)
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, path)
    sync_directory(path.parent)


def check_genesis(info, root_hex, file_hex):
    """RPC corroboration of the explicit ceremony identity, not a native proof."""
    try:
        initial = info["init"]
        valid = initial["workchain"] == -1 and initial["seqno"] == 0
        valid = valid and base64.b64decode(initial["root_hash"], validate=True).hex() == root_hex
        valid = valid and base64.b64decode(initial["file_hash"], validate=True).hex() == file_hex
    except (KeyError, TypeError, ValueError):
        valid = False
    if not valid:
        raise lib.TestnetError("qualified RPC genesis does not match the explicit ceremony")


def lock_state(directory):
    directory = lib.private_dir(Path(directory))
    fd = os.open(directory / "qualification.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise lib.TestnetError("unsafe qualification lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def ordinary_state_lock(directory):
    fd = lock_state(directory)
    try:
        if (Path(directory) / "qualification-active.json").exists() or (
            Path(directory) / "qualification-identity.json"
        ).exists():
            raise lib.TestnetError("qualified state requires qualification mode and reconciliation")
        return fd
    except BaseException:
        os.close(fd)
        raise


class Qualification:
    def __init__(self, directory, funding_cap, fee_stop, max_pending=8192, identity=None):
        if (
            type(funding_cap) is not int
            or type(fee_stop) is not int
            or funding_cap <= 0
            or fee_stop <= 0
            or not 1 <= max_pending <= 8192
        ):
            raise lib.TestnetError(
                "positive qualification budgets and bounded pending limit required"
            )
        self.directory = lib.private_dir(Path(directory))
        self.lock_fd = lock_state(self.directory)
        try:
            self.active = self.directory / "qualification-active.json"
            if (
                self.active.exists()
                and json.loads(self.active.read_text()).get("closed") is not True
            ):
                raise lib.TestnetError(
                    "previous qualified run unfinished: reconcile original messages"
                )
            identity_path = self.directory / "qualification-identity.json"
            if identity is not None:
                if identity_path.exists():
                    if json.loads(identity_path.read_text()) != identity:
                        raise lib.TestnetError("qualified state belongs to a different genesis")
                else:
                    if (
                        (self.directory / "highload.key").exists()
                        or (self.directory / "highload.addr").exists()
                        or list(self.directory.glob("relayer-*.pk"))
                    ):
                        raise lib.TestnetError(
                            "existing unbound load keys require a fresh qualified state"
                        )
                    atomic_json(identity_path, identity)
            self.run = self.directory / f"qualification-{time.time_ns()}"
            self.run.mkdir(mode=0o700)
            (self.run / "private-outbox").mkdir(mode=0o700)
            self.events = (self.run / "events.jsonl").open("x")
            os.chmod(self.run / "events.jsonl", 0o600)
            atomic_json(self.active, {"run": self.run.name, "closed": False})
        except BaseException:
            os.close(self.lock_fd)
            raise
        self.guard = threading.RLock()
        self.funding_cap, self.fee_stop = funding_cap, fee_stop
        self.max_pending = max_pending
        self.live = {}
        self.seen = bytearray(QUERY_LIMIT // 8)
        self.funded = self.funding_operations = self.offered = self.executed = 0
        self.accepted = self.failed = self.not_offered = 0
        self.not_offered_unknown = False
        self.funding_unknown = False
        self.funding_inflight = 0
        self.halted = False
        self.histograms = {name: [0] * (len(BUCKETS) + 1) for name in ("accepted", "executed")}
        self.started = time.monotonic()
        self.closed = False
        self.native = None

    def attach_native(self, observer):
        with self.guard:
            if self.native is not None or self.offered:
                raise lib.TestnetError("native observer must attach before the first offer")
            self.native = observer

    def native_healthy(self):
        if self.native is not None:
            self.native.assert_healthy()

    def event(self, kind, **fields):
        self.events.write(
            json.dumps(
                {
                    "event": kind,
                    "time_unix": time.time(),
                    "monotonic_seconds": time.monotonic(),
                    **fields,
                }
            )
            + "\n"
        )
        self.events.flush()
        os.fsync(self.events.fileno())

    def reserve_funding(self, amount, label):
        with self.guard:
            self.native_healthy()
            if self.halted:
                raise lib.TestnetError("qualified admission stopped")
            if (
                type(amount) is not int
                or amount <= 0
                or self.funded + amount > self.funding_cap
                or self.funding_operations >= 4096
            ):
                raise lib.TestnetError("qualified total funding ceiling reached")
            self.event("funding_reserved", amount_nanotos=amount, label=label)
            self.funded += amount
            self.funding_operations += 1
            self.funding_inflight += 1

    def funding_settled(self):
        with self.guard:
            if self.closed or self.funding_inflight <= 0:
                raise lib.TestnetError("funding settlement needs original-run reconciliation")
            self.event("funding_settled")
            self.funding_inflight -= 1

    def halt(self, reason):
        with self.guard:
            self.halted = True
            if not self.closed:
                self.event("admission_stopped", reason=reason)

    def uncertain_funding(self):
        with self.guard:
            self.funding_unknown = True
            self.halted = True
            if not self.closed:
                self.event("funding_unknown")

    def offer(self, ids, carrier, request_hashes=None):
        with self.guard:
            self.native_healthy()
            if self.halted:
                raise lib.TestnetError("qualified admission stopped")
            if not ids or len(set(ids)) != len(ids) or len(self.live) + len(ids) > self.max_pending:
                raise lib.TestnetError("duplicate query or qualified pending ceiling reached")
            for query in ids:
                if type(query) is not int or not 0 <= query < QUERY_LIMIT or query & 1023 == 1023:
                    raise lib.TestnetError("invalid qualified query id")
                if self.seen[query // 8] & (1 << (query % 8)):
                    raise lib.TestnetError("query reused within qualified run")
            # Archive and send exactly the same bounded immutable snapshot.
            with carrier.open("rb") as src:
                payload = src.read(MAX_CARRIER_BYTES + 1)
            if not payload or len(payload) > MAX_CARRIER_BYTES:
                raise lib.TestnetError("qualified carrier size limit")
            target = self.run / "private-outbox" / carrier.name
            with target.open("xb") as out:
                os.chmod(target, 0o600)
                if out.write(payload) != len(payload):
                    raise lib.TestnetError("short qualified carrier archive")
                out.flush()
                os.fsync(out.fileno())
            sync_directory(target.parent)
            stamp = time.monotonic()
            fields = {}
            if self.native is not None:
                if type(request_hashes) is not dict or set(request_hashes) != set(ids):
                    raise lib.TestnetError("native offer needs every signed request digest")
                try:
                    native_offer = self.native.offer(request_hashes)
                except AdmissionClosed as exc:
                    # The archived bytes are retained but never sent. Burn the
                    # allocated IDs and durably distinguish them from offers.
                    self.not_offered_unknown = True
                    self.event(
                        "not_offered",
                        query_ids=ids,
                        native_boot_id=exc.boot_id,
                        not_offered_monotonic_seconds=exc.now,
                        declared_deadline_monotonic_seconds=exc.deadline,
                        reason="fixed_stage_deadline",
                    )
                    for query in ids:
                        self.seen[query // 8] |= 1 << (query % 8)
                    self.not_offered += len(ids)
                    self.not_offered_unknown = False
                    raise

                fields["signed_request_hashes"] = request_hashes
                fields["native_boot_id"] = native_offer["boot_id"]
                fields["native_offered_monotonic_seconds"] = native_offer["monotonic_seconds"]
            self.event("offered", query_ids=ids, carrier_bytes=target.stat().st_size, **fields)
            for query in ids:
                self.seen[query // 8] |= 1 << (query % 8)
                self.live[query] = {"offered": stamp, "accepted": False}
            self.offered += len(ids)
            return payload

    def _histogram(self, kind, seconds):
        index = next((i for i, upper in enumerate(BUCKETS) if seconds <= upper), len(BUCKETS))
        self.histograms[kind][index] += 1

    def accept(self, ids):
        with self.guard:
            for query in ids:
                row = self.live[query]
                if not row["accepted"]:
                    elapsed = max(0, time.monotonic() - row["offered"])
                    self.event("accepted", query_id=query, offered_latency_seconds=elapsed)
                    row["accepted"] = True
                    self.accepted += 1
                    self._histogram("accepted", elapsed)

    def terminal(self, query, executed):
        with self.guard:
            row = self.live[query]
            elapsed = max(0, time.monotonic() - row["offered"])
            self.event(
                "executed" if executed else "unconfirmed",
                query_id=query,
                offered_latency_seconds=elapsed,
            )
            del self.live[query]
            if executed:
                self.executed += 1
                self._histogram("executed", elapsed)
            else:
                self.failed += 1

    def observe_fees(self, spent):
        with self.guard:
            self.event("fee_observation", spent_nanotos=spent)
            return spent >= self.fee_stop

    def finish(self):
        with self.guard:
            result = {
                "offered": self.offered,
                "not_offered": self.not_offered,
                "not_offered_unknown": self.not_offered_unknown,
                "accepted": self.accepted,
                "executed": self.executed,
                "unconfirmed": self.failed,
                "pending": len(self.live),
                "funded_nanotos": self.funded,
                "funding_cap_nanotos": self.funding_cap,
                "funding_unknown": self.funding_unknown,
                "funding_inflight": self.funding_inflight,
                "admission_stopped": self.halted,
                "run_directory": self.run.name,
                "observed_fee_stop_nanotos": self.fee_stop,
                "seconds_monotonic": time.monotonic() - self.started,
                "latency_bucket_upper_seconds": [*BUCKETS, "infinity"],
                "histograms": self.histograms,
                "verification_mode": "two_rpc_processed",
                "latency_scope": "offered to RPC seqno acceptance / two-RPC per-query processed? observation; not native finality proof",
            }
            result["all_queries_observed_executed"] = (
                self.offered > 0 and self.executed == self.offered
            )
            result["safe_to_start_new_run"] = (
                not self.live
                and not self.failed
                and not self.funding_unknown
                and self.funding_inflight == 0
                and not self.not_offered_unknown
            )
            if self.native is not None:
                result["native_finality"] = self.native.summary()
                result["verification_mode"] = "native_signed_request_completion"
                result["safe_to_start_new_run"] = (
                    result["safe_to_start_new_run"]
                    and result["native_finality"]["native_pending"] == 0
                )
                result["latency_scope"] = (
                    "RPC relayer acceptance / application reporting; native_finality contains "
                    "independently verified signed-request completion latency"
                )
            atomic_json(self.run / "result.json", result)
            atomic_json(
                self.active, {"run": self.run.name, "closed": result["safe_to_start_new_run"]}
            )
            self.events.close()
            os.close(self.lock_fd)
            self.closed = True
            return result

    def abort(self):
        """Release resources while leaving the unfinished-run fence in place."""
        with self.guard:
            if not self.closed:
                self.events.close()
                os.close(self.lock_fd)
                self.closed = True
