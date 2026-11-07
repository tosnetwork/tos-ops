"""Deduplicate public proof bytes; storage integrity is not native proof validation.

Only explicit public TL responses enter this API. Never pass wallet keys, signed
carriers, private journals or an unfiltered directory. Callers retain full native
verification and offered-query reconciliation as separate acceptance gates.
"""

import hashlib
import json
import sqlite3
from contextlib import contextmanager


class ArchiveError(ValueError):
    pass


class PublicProofArchive:
    """One writer, atomic contiguous captures, bounded unique bytes and RAM.

    SQLite FULL synchronous transactions retain either the entire capture or
    none after interruption. Repeated bytes are stored once, without hardlinks
    (and therefore without the filesystem's per-inode link-count limit).
    """

    def __init__(self, path, *, identity, max_unique_bytes, max_captures=1_000_000):
        if (
            type(max_unique_bytes) is not int
            or not 0 < max_unique_bytes <= 1 << 40
            or type(max_captures) is not int
            or not 0 < max_captures <= 1_000_000
        ):
            raise ArchiveError("invalid archive bounds")
        identity = self._json(identity)
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            with self._transaction():
                self.db.execute(
                    "CREATE TABLE IF NOT EXISTS settings "
                    "(singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                    "identity TEXT NOT NULL, byte_limit INTEGER NOT NULL, "
                    "capture_limit INTEGER NOT NULL, used_bytes INTEGER NOT NULL)"
                )
                self.db.execute(
                    "CREATE TABLE IF NOT EXISTS blobs (digest TEXT PRIMARY KEY, body BLOB NOT NULL)"
                )
                self.db.execute(
                    "CREATE TABLE IF NOT EXISTS captures "
                    "(number INTEGER PRIMARY KEY, metadata TEXT NOT NULL, parts INTEGER NOT NULL)"
                )
                self.db.execute(
                    "CREATE TABLE IF NOT EXISTS parts "
                    "(capture INTEGER REFERENCES captures(number), position INTEGER, "
                    "digest TEXT REFERENCES blobs(digest), PRIMARY KEY(capture,position))"
                )
                expected = (identity, max_unique_bytes, max_captures)
                row = self.db.execute(
                    "SELECT identity,byte_limit,capture_limit FROM settings WHERE singleton=1"
                ).fetchone()
                if row is None:
                    self.db.execute("INSERT INTO settings VALUES(1,?,?,?,0)", expected)
                elif row != expected:
                    raise ArchiveError("archive identity or bounds changed")
            self.max_unique_bytes = max_unique_bytes
            self.max_captures = max_captures
        except BaseException:
            self.db.close()
            raise

    @staticmethod
    def _json(value):
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(text.encode()) > 1 << 20:
            raise ArchiveError("metadata exceeds 1 MiB")
        return text

    @contextmanager
    def _transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def append(self, number, parts, *, metadata):
        """Consume a bounded iterable; rollback every insertion on any failure."""
        metadata = self._json(metadata)
        with self._transaction():
            count = self.db.execute("SELECT coalesce(max(number)+1,0) FROM captures").fetchone()[0]
            if type(number) is not int or number != count or count >= self.max_captures:
                raise ArchiveError("capture must be next contiguous index within limit")
            used = self.db.execute("SELECT used_bytes FROM settings").fetchone()[0]
            self.db.execute("INSERT INTO captures VALUES(?,?,0)", (number, metadata))
            total = 0
            count = 0
            for position, body in enumerate(parts):
                if position >= 1024 or type(body) is not bytes or not 0 < len(body) <= 8 << 20:
                    raise ArchiveError("invalid public proof part or count")
                total += len(body)
                if total > 64 << 20:
                    raise ArchiveError("capture exceeds 64 MiB")
                digest = hashlib.sha256(body).hexdigest()
                old = self.db.execute("SELECT body FROM blobs WHERE digest=?", (digest,)).fetchone()
                if old is None:
                    if used + len(body) > self.max_unique_bytes:
                        raise ArchiveError("unique public proof byte budget exhausted")
                    self.db.execute("INSERT INTO blobs VALUES(?,?)", (digest, body))
                    used += len(body)
                elif old[0] != body:
                    raise ArchiveError("public proof blob collision or corruption")
                self.db.execute("INSERT INTO parts VALUES(?,?,?)", (number, position, digest))
                count += 1
            if count == 0:
                raise ArchiveError("empty capture")
            self.db.execute("UPDATE captures SET parts=? WHERE number=?", (count, number))
            self.db.execute("UPDATE settings SET used_bytes=?", (used,))

    def read(self, number):
        """Return original bytes in exact order, checking every content digest."""
        row = self.db.execute(
            "SELECT metadata,parts FROM captures WHERE number=?", (number,)
        ).fetchone()
        if row is None:
            raise ArchiveError("missing capture")
        result = []
        total = 0
        for position, digest, body in self.db.execute(
            "SELECT p.position,p.digest,b.body FROM parts p JOIN blobs b "
            "ON p.digest=b.digest WHERE p.capture=? ORDER BY p.position",
            (number,),
        ):
            if (
                position != len(result)
                or len(result) >= 1024
                or not 0 < len(body) <= 8 << 20
                or hashlib.sha256(body).hexdigest() != digest
            ):
                raise ArchiveError("corrupt public proof part")
            total += len(body)
            if total > 64 << 20:
                raise ArchiveError("capture exceeds 64 MiB")
            result.append(body)
        if len(result) != row[1] or not result:
            raise ArchiveError("missing public proof part")
        return json.loads(row[0]), result

    def stats(self):
        return {
            "captures": self.db.execute("SELECT count(*) FROM captures").fetchone()[0],
            "unique_parts": self.db.execute("SELECT count(*) FROM blobs").fetchone()[0],
            "unique_bytes": self.db.execute("SELECT used_bytes FROM settings").fetchone()[0],
        }

    def close(self):
        self.db.close()
