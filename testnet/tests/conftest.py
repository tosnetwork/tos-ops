"""Test import roots and the real signature verifier fixture."""

import hashlib
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))


@pytest.fixture(scope="session", autouse=True)
def con01_signature_environment(request, tmp_path_factory):
    """Compile only when certificate tests need a backend and no pin was supplied."""
    modules = {"test_con01_history.py", "test_con01_observer_crypto.py"}
    if not any(item.path.name in modules for item in request.session.items):
        yield
        return
    names = ("CON01_SIGNATURE_VERIFIER", "CON01_SIGNATURE_VERIFIER_SHA256")
    supplied = [os.environ.get(name) for name in names]
    if any(supplied):
        if not all(supplied):
            pytest.fail("set both CON01_SIGNATURE_VERIFIER and CON01_SIGNATURE_VERIFIER_SHA256")
        yield
        return
    prefix = os.environ.get("OPENSSL_PREFIX")
    if prefix:
        prefix = Path(prefix)
    elif os.environ.get("TOS_ROOT"):
        prefix = Path(os.environ["TOS_ROOT"]) / "build" / "third-party" / "openssl"
    else:
        pytest.fail("certificate tests need OPENSSL_PREFIX or a built TOS_ROOT (OpenSSL >= 3.5)")
    header = prefix / "include" / "openssl" / "evp.h"
    library = prefix / "lib" / "libcrypto.a"
    if not header.is_file() or not library.is_file():
        pytest.fail(
            "certificate tests need built OpenSSL >= 3.5; set OPENSSL_PREFIX or supply the pinned verifier"
        )
    program = tmp_path_factory.mktemp("con01-verifier") / "mldsa-verify"
    source = SCRIPTS.parent / "acceptance" / "con01_history" / "mldsa_verify.c"
    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        str(prefix / "include"),
        str(source),
        str(library),
        "-ldl",
        "-pthread",
        "-o",
        str(program),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        pytest.fail(f"could not build the real certificate verifier: {error}")
    if result.returncode:
        pytest.fail(
            "certificate verifier build failed (OpenSSL >= 3.5 required): " + result.stderr[-4000:]
        )
    program.chmod(0o500)
    os.environ[names[0]] = str(program)
    os.environ[names[1]] = hashlib.sha256(program.read_bytes()).hexdigest()
    try:
        yield
    finally:
        for name in names:
            os.environ.pop(name, None)
