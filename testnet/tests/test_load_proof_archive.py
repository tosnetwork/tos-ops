"""Storage/atomicity controls; these do not attest native cryptographic validity."""

import pytest
from load_proof_archive import ArchiveError, PublicProofArchive


def archive(tmp_path, **kw):
    return PublicProofArchive(
        tmp_path / "public.sqlite", identity={"anchor": "fixed"}, max_unique_bytes=10, **kw
    )


def test_dedup_order_resume(tmp_path):
    a = archive(tmp_path)
    a.append(0, [b"ab", b"cd", b"ab"], metadata={"target": 1})
    a.append(1, [b"cd", b"ab"], metadata={"target": 2})
    assert a.stats() == {"captures": 2, "unique_parts": 2, "unique_bytes": 4}
    a.close()
    a = archive(tmp_path)
    assert a.read(0) == ({"target": 1}, [b"ab", b"cd", b"ab"])
    assert a.read(1) == ({"target": 2}, [b"cd", b"ab"])
    a.close()


@pytest.mark.parametrize("parts", [[], [b""], [bytearray(b"a")], [b"a"] * 1025, [b"a" * 11]])
def test_reject_rollback(tmp_path, parts):
    a = archive(tmp_path)
    with pytest.raises(ArchiveError):
        a.append(0, parts, metadata={})
    assert a.stats() == {"captures": 0, "unique_parts": 0, "unique_bytes": 0}
    a.append(0, [b"ok"], metadata={})
    a.close()


def test_interrupted_iterable_rolls_back(tmp_path):
    a = archive(tmp_path)

    def broken():
        yield b"ab"
        raise RuntimeError("simulated interruption")

    with pytest.raises(RuntimeError, match="interruption"):
        a.append(0, broken(), metadata={})
    assert a.stats()["unique_bytes"] == 0
    a.close()


@pytest.mark.parametrize("number", [True, -1, 1])
def test_gap_or_invalid_index(tmp_path, number):
    a = archive(tmp_path)
    with pytest.raises(ArchiveError, match="contiguous"):
        a.append(number, [b"a"], metadata={})
    a.close()


def test_duplicate_and_limit(tmp_path):
    a = archive(tmp_path, max_captures=1)
    a.append(0, [b"a"], metadata={})
    for number in (0, 1):
        with pytest.raises(ArchiveError):
            a.append(number, [b"a"], metadata={})
    a.close()


def test_resume_identity_mismatch(tmp_path):
    a = archive(tmp_path)
    a.close()
    with pytest.raises(ArchiveError, match="identity"):
        PublicProofArchive(
            tmp_path / "public.sqlite", identity={"anchor": "other"}, max_unique_bytes=10
        )


@pytest.mark.parametrize("mutation", ["bytes", "missing"])
def test_corruption_rejected(tmp_path, mutation):
    a = archive(tmp_path)
    a.append(0, [b"ab", b"cd"], metadata={})
    if mutation == "bytes":
        a.db.execute("UPDATE blobs SET body=? WHERE body=?", (b"xx", b"ab"))
    else:
        a.db.execute("DELETE FROM parts WHERE position=1")
    with pytest.raises(ArchiveError):
        a.read(0)
    a.close()


def test_actual_process_kill_preserves_atomicity(tmp_path):
    import os
    import signal
    import subprocess
    import sys

    a = archive(tmp_path)
    a.close()
    child = """
import os,signal,sys
from load_proof_archive import PublicProofArchive
a=PublicProofArchive(sys.argv[1],identity={'anchor':'fixed'},max_unique_bytes=10)
def interrupted():
    yield b'ab'
    os.kill(os.getpid(),signal.SIGKILL)
a.append(0,interrupted(),metadata={})
"""
    done = subprocess.run(
        [sys.executable, "-c", child, str(tmp_path / "public.sqlite")],
        env=os.environ.copy(),
        timeout=10,
    )
    assert done.returncode == -signal.SIGKILL
    a = archive(tmp_path)
    assert a.stats() == {"captures": 0, "unique_parts": 0, "unique_bytes": 0}
    a.append(0, [b"ok"], metadata={})
    assert a.read(0)[1] == [b"ok"]
    a.close()
