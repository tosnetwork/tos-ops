"""Test against the selected checkout's schemas, never stale generated artifacts."""

import os
import sys
import tempfile
from pathlib import Path

import pytest


def pytest_sessionstart(session):
    configured = os.environ.get("TOS_ROOT")
    if not configured:
        return
    root = Path(configured).resolve()
    source = root / "test" / "tostester" / "src"
    schemas = root / "tl" / "generate" / "scheme"
    if not (source / "tl").is_dir():
        raise pytest.UsageError("TOS_ROOT must name a checkout with the Python TL generator")
    if any(name == "tosapi" or name.startswith("tosapi.") for name in sys.modules):
        raise pytest.UsageError(
            "start pytest in a fresh process before importing generated tosapi bindings"
        )
    sys.path.insert(0, str(source))
    import tl

    temporary = tempfile.TemporaryDirectory(
        prefix="schemas-", dir=session.config.cache.mkdir("tos-bindings")
    )
    session.config.add_cleanup(temporary.cleanup)
    generated = Path(temporary.name)
    for name in ("lite_api.tl", "tos_api.tl", "toslib_api.tl"):
        schema = schemas / name
        if not schema.is_file():
            raise pytest.UsageError(f"TOS_ROOT is missing the selected schema: {name}")
        tl.generate(schema, generated / "tosapi")
    sys.path.insert(0, str(generated))
    inherited = os.environ.get("PYTHONPATH")
    paths = [str(generated), str(source)]
    if inherited:
        paths.append(inherited)
    os.environ["PYTHONPATH"] = os.pathsep.join(paths)
