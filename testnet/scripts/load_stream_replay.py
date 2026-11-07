"""Read-only native replay alongside an append-only public load run.

Live coverage is provisional. Completion requires the producer's own safely
closed summary, the complete original journal and every capture. This tool
cannot close a spending fence and never reads private carriers or keys.
"""

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import stat
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from load_finality import HistoryError
from load_finality_collector import sync_directory
from load_finality_replay import RetainedPrefix
from load_finality_window import BUCKETS
from load_proof_archive import PublicProofArchive
from load_run_replay import (
    MAX_CAPTURE,
    MIB,
    EventIndex,
    NativeReplay,
    capture_count,
    digest,
    durable_json,
    install_interrupt_handlers,
    pinned,
    replay_capture,
    require,
    snapshot,
    validate_packet,
)
from pytosiq_core.tl import TlGenerator


class AppendJournal:
    """Copy only complete lines; final hashing also detects earlier rewrites."""

    def __init__(self, source, destination):
        self.path = Path(source)
        self.source = os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW), "rb")
        try:
            self.identity = self.check_identity()
            self.copy = Path(destination).open("xb")
        except BaseException:
            self.source.close()
            raise
        self.hasher = hashlib.sha256()
        self.total = self.lines = 0

    def check_identity(self):
        fd = os.fstat(self.source.fileno())
        path = self.path.stat(follow_symlinks=False)
        require(
            stat.S_ISREG(fd.st_mode) and stat.S_ISREG(path.st_mode),
            "regular public journal required",
        )
        identity = (fd.st_dev, fd.st_ino)
        require(identity == (path.st_dev, path.st_ino), "public journal replaced")
        require(fd.st_size >= self.source.tell(), "public journal truncated")
        if hasattr(self, "identity"):
            require(identity == self.identity, "public journal identity changed")
        return identity

    def pump(self, index, batch=256):
        self.check_identity()
        added = 0
        for _ in range(batch):
            position = self.source.tell()
            line = self.source.readline(MIB + 1)
            require(len(line) <= MIB, "event line budget")
            if not line or not line.endswith(b"\n"):
                self.source.seek(position)
                break
            require(
                self.total + len(line) <= 16 << 30 and self.lines < 12_000_000,
                "event stream budget",
            )
            index.add(json.loads(line))
            require(self.copy.write(line) == len(line), "short public event copy")
            self.hasher.update(line)
            self.total += len(line)
            self.lines += 1
            added += 1
        self.copy.flush()
        os.fsync(self.copy.fileno())
        return added

    def seal(self):
        self.check_identity()
        before = os.fstat(self.source.fileno())
        require(self.source.tell() == before.st_size, "unread or partial final event")
        expected = self.hasher.hexdigest()
        self.source.seek(0)
        hasher = hashlib.sha256()
        count = 0
        while raw := self.source.read(MIB):
            count += len(raw)
            require(count <= self.total, "event stream grew during final check")
            hasher.update(raw)
        after = os.fstat(self.source.fileno())
        self.check_identity()
        require(
            (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
            and count == self.total
            and hasher.hexdigest() == expected,
            "original event prefix changed",
        )
        self.sealed_state = (after.st_size, after.st_mtime_ns)
        return expected

    def check_sealed(self):
        self.check_identity()
        info = os.fstat(self.source.fileno())
        require(
            (info.st_size, info.st_mtime_ns) == self.sealed_state,
            "event journal changed after final hash",
        )

    def close(self):
        try:
            self.copy.close()
        finally:
            self.source.close()


def publish_result(path, value, before_link):
    """Persist the candidate before checking source context for publication."""
    require(not path.exists() and not path.is_symlink(), "public result already published")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        before_link()
        os.link(temporary, path)
        sync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def validate_complete_index(index):
    # The batch reader initializes this clock in finish_index. Streaming has
    # already verified observations, so that initializer must not rewind it.
    observed = index.last_observed_clock
    index.finish_index()
    if observed is not None:
        index.last_observed_clock = max(observed, index.last_observed_clock)


def find_summary(source):
    selected = []
    count = 0
    for path in source.parent.glob("summary-*.json"):
        count += 1
        require(count <= 8192, "summary discovery budget")
        if not re.fullmatch(r"summary-[0-9]{8}T[0-9]{6}Z\.json", path.name):
            continue
        info = path.stat(follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MIB, "public summary type/size")
        if not info.st_size:
            continue
        try:
            raw = snapshot(path, MIB)
        except HistoryError as error:
            if str(error) in ("public input changed", "public input changed or oversized"):
                continue
            raise
        try:
            summary = json.loads(raw)
        except json.JSONDecodeError:
            # The producer publishes this file after its final journal event.
            # A partial file is not a closed summary or successful evidence.
            continue
        if summary.get("qualification", {}).get("run_directory") == source.name:
            selected.append((path, raw, summary))
    require(len(selected) <= 1, "ambiguous original summary")
    return selected[0] if selected else None


def closure_ready(source):
    marker = source.parent / "qualification-active.json"
    if not marker.exists() and not marker.is_symlink():
        return True  # Archived public evidence still requires a safe summary.
    active = json.loads(snapshot(marker, MIB))
    require(
        type(active.get("closed")) is bool and type(active.get("run")) is str,
        "invalid public qualification marker",
    )
    return active["run"] != source.name or active["closed"] is True


def closed_context(summary, source, args, packet, anchor):
    q = summary["qualification"]
    native = q["native_finality"]
    require(
        q["run_directory"] == source.name
        and summary["wallet"] == args.wallet
        and summary["transfers_mode"] == "skip",
        "summary/run/profile mismatch",
    )
    require(
        q["safe_to_start_new_run"] is True
        and q["pending"] == 0
        and q["funding_unknown"] is False
        and native["native_pending"] == 0,
        "closed reconciled source required; reader cannot clear its fence",
    )
    require(
        native["latency_bucket_upper_seconds"] == [*BUCKETS, "infinity"], "histogram buckets differ"
    )
    validate_packet(
        packet,
        source,
        anchor,
        args,
        native.get("slo_population", "completion-prefix"),
        duration=native.get("stage_duration_seconds"),
        target_gas=summary.get("target_gas_per_block"),
        cutoff=native.get("cutoff_policy", "fail"),
    )
    return q


def run(args):
    require(
        type(args.max_seconds) in (int, float)
        and math.isfinite(args.max_seconds)
        and 0 < args.max_seconds <= 7 * 86400,
        "bounded streaming horizon required",
    )
    require(
        type(args.idle_seconds) in (int, float)
        and math.isfinite(args.idle_seconds)
        and 0 < args.idle_seconds <= 3600,
        "bounded idle horizon required",
    )
    source, output = Path(args.run), Path(args.output)
    require(
        source.is_absolute()
        and source.resolve() == source
        and re.fullmatch(r"qualification-[0-9]+", source.name),
        "canonical public run required",
    )
    require(
        output.is_absolute()
        and source not in output.parents
        and output not in source.parents
        and output != source,
        "separate absolute replay output required",
    )
    require(output.parent.resolve() == output.parent, "canonical output parent required")
    captures = source / "native-captures"
    require(captures.is_dir() and not captures.is_symlink(), "public captures directory required")
    anchor_raw = pinned(args.anchor, args.anchor_sha256)
    schema_raw = pinned(args.schema, args.schema_sha256, 16 * MIB)
    packet_raw = pinned(args.producer_packet, args.producer_packet_sha256)
    anchor, packet = json.loads(anchor_raw), json.loads(packet_raw)
    output.mkdir(mode=0o700)
    public = output / "public"
    public.mkdir(mode=0o700)
    for name, raw in (
        ("anchor.json", anchor_raw),
        ("schema.tl", schema_raw),
        ("producer-packet.json", packet_raw),
    ):
        with (public / name).open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    sync_directory(public)
    identity = {
        "run": str(source),
        "wallet": args.wallet,
        "wallet_code_hash": args.wallet_code_hash,
        "global_id": args.global_id,
        "global_version": args.global_version,
        "subwallet_id": args.subwallet_id,
        "anchor_sha256": args.anchor_sha256,
        "schema_sha256": args.schema_sha256,
        "verifier_sha256": args.verifier_sha256,
        "producer_packet_sha256": args.producer_packet_sha256,
        "max_captures": args.max_captures,
        "max_unique_bytes": args.max_unique_bytes,
    }
    durable_json(output / "context.json", identity)
    index = EventIndex(output / "index.sqlite", source, max_captures=args.max_captures)
    journal = archive = native = None
    try:
        journal = AppendJournal(source / "events.jsonl", output / "events.jsonl")
        archive = PublicProofArchive(
            output / "proofs.sqlite",
            identity=identity,
            max_unique_bytes=args.max_unique_bytes,
            max_captures=args.max_captures,
        )
        native = NativeReplay(args.verifier, args.verifier_sha256, public / "anchor.json", output)
        cache = RetainedPrefix(TlGenerator(str(public / "schema.tl")).generate(), anchor)
        previous, number = None, 0
        started = active = time.monotonic()
        while True:
            now = time.monotonic()
            require(
                now - started <= args.max_seconds and now - active <= args.idle_seconds,
                "streaming horizon or idle budget exhausted",
            )
            if journal.pump(index):
                active = time.monotonic()
            if index.baseline is not None and index.last_observed_clock is None:
                index.last_observed_clock = index.baseline["verified_observation_monotonic_seconds"]
            ready = index.baseline is not None and (
                number == 0
                or index.db.execute(
                    "SELECT 1 FROM checkpoints WHERE number=?", (number,)
                ).fetchone()
            )
            if ready:
                require(number < args.max_captures, "capture count budget")
                require(
                    shutil.disk_usage(output).free >= (20 << 30) + MAX_CAPTURE,
                    "replay free disk guard",
                )
                previous = replay_capture(
                    captures / f"capture-{number:06d}",
                    number,
                    previous,
                    cache,
                    native,
                    index,
                    archive,
                    identity,
                )
                number += 1
                active = time.monotonic()
                (output / "PROGRESS.json").write_text(
                    json.dumps(
                        {
                            "status": "LIVE_COVERAGE_NOT_ACCEPTED",
                            "captures_verified": number,
                            "offers_indexed": index.offers,
                            "closed_source_accepted": False,
                        }
                    )
                    + "\n"
                )
                continue
            selected = (
                find_summary(source)
                if index.baseline is not None and closure_ready(source)
                else None
            )
            if selected is not None:
                path, summary_raw, summary = selected
                q = closed_context(summary, source, args, packet, anchor)
                require(
                    capture_count(captures, args.max_captures) == number, "unverified final capture"
                )
                validate_complete_index(index)
                index.complete(q)
                events_sha = journal.seal()
                require(
                    snapshot(path, MIB) == summary_raw
                    and snapshot(args.anchor) == anchor_raw
                    and snapshot(args.schema, 16 * MIB) == schema_raw
                    and snapshot(args.producer_packet) == packet_raw,
                    "final context changed",
                )
                journal.check_sealed()
                result = {
                    "status": "FULL_STREAMED_CLOSED_RUN_PROOF_HISTORY_DIGEST_CLOCK_COVERAGE_VERIFIED",
                    "scope": "Coverage only; no load/72h acceptance or financial fence clearance",
                    "identity": identity,
                    "summary_sha256": digest(summary_raw),
                    "events_sha256": events_sha,
                    "captures": number,
                    "offered": index.offers,
                    "not_offered": index.not_offered,
                    "recomputed_histogram": index.histogram,
                    "archive": archive.stats(),
                    "source_native_latency_criteria_pass": q["native_finality"][
                        "latency_criteria_pass"
                    ],
                }

                def final_source_check():
                    require(
                        capture_count(captures, args.max_captures) == number,
                        "unverified final capture",
                    )
                    require(
                        snapshot(path, MIB) == summary_raw
                        and snapshot(args.anchor) == anchor_raw
                        and snapshot(args.schema, 16 * MIB) == schema_raw
                        and snapshot(args.producer_packet) == packet_raw,
                        "final context changed at publication",
                    )
                    require(closure_ready(source), "original run reopened before publication")
                    journal.check_sealed()

                publish_result(output / "RESULT.json", result, final_source_check)
                return result
            time.sleep(0.2)
    finally:
        # Attempt every close even if an event-copy flush or SQLite close fails.
        with ExitStack() as cleanup:
            cleanup.callback(index.close)
            if archive is not None:
                cleanup.callback(archive.close)
            if native is not None:
                cleanup.callback(native.close)
            if journal is not None:
                cleanup.callback(journal.close)


def main():
    install_interrupt_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "run",
        "output",
        "anchor",
        "anchor-sha256",
        "schema",
        "schema-sha256",
        "producer-packet",
        "producer-packet-sha256",
        "verifier",
        "verifier-sha256",
        "wallet",
        "wallet-code-hash",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--global-id", type=int, default=2)
    parser.add_argument("--global-version", type=int, default=16)
    parser.add_argument("--subwallet-id", type=int, default=4269)
    parser.add_argument("--max-unique-bytes", type=int, default=128 << 30)
    parser.add_argument("--max-captures", type=int, default=1_000_000)
    parser.add_argument("--max-seconds", type=float, default=4 * 86400)
    parser.add_argument("--idle-seconds", type=float, default=300)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args)))
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        parser.exit(1, f"stream replay refused: {type(error).__name__}: {error}\n")


if __name__ == "__main__":
    main()
