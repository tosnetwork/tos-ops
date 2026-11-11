"""Bind every frozen segment, including open-segment complete-line prefixes."""

import hashlib
import json
from pathlib import Path

from .certificate import require


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for part in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def segments(root):
    inventory = json.loads((root / "SNAPSHOT.json").read_bytes())["segments"]
    require(0 < len(inventory) <= 4096, "bounded frozen segment inventory required")
    source_dirs = {path.name: path for path in root.glob("src-*")}
    require(
        set(source_dirs) == {"src-node1", "src-node3", "src-node5"}
        and all(
            path.is_dir() and not path.is_symlink() for path in source_dirs.values()
        ),
        "exact original source directories required",
    )
    actual = {
        str(path.relative_to(root))
        for folder in source_dirs.values()
        for path in folder.glob("seg-*.jsonl")
    }
    require(
        actual == {row["path"] for row in inventory},
        "snapshot must cover complete worker input inventory",
    )
    paths = {}
    for row in inventory:
        name = row["path"]
        path = root / name
        require(
            not Path(name).is_absolute()
            and path.resolve().is_relative_to(root.resolve())
            and not path.is_symlink()
            and path.is_file(),
            "frozen segment path outside replay",
        )
        require(name not in paths, "duplicate frozen segment inventory")
        paths[name] = path
    return paths


def pin_segments(root):
    return {name: sha(path) for name, path in segments(root).items()}


def validate_segments(root):
    paths = segments(root)
    pinned = json.loads((root / "SEGMENT-HASHES.json").read_bytes())
    require(
        set(pinned) == set(paths), "complete frozen segment digest inventory required"
    )
    require(
        all(sha(path) == pinned[name] for name, path in paths.items()),
        "frozen segment digest changed",
    )
