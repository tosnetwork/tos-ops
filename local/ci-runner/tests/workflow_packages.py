"""The apt packages tos's workflows install, so the CI image can provide every one.

    workflow_packages.py --write TOS_ROOT   regenerate image-packages.json from TOS_ROOT's workflows
    workflow_packages.py --check TOS_ROOT   exit 1 unless image-packages.json matches them

The result pins the tos commit and the SHA-256 of the workflow files it was
derived from. Each workflow is parsed as YAML first, so folded and literal
blocks reach the shell parser as YAML defines them. A package named through a
variable, an expression, a glob or quotes cannot be known statically, and an
install command the parser cannot attribute to a decoded string is refused:
both are errors naming the place, never silently left out.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
PINNED = HERE.parent / "image-packages.json"
# Options of apt and apt-get that take a separate argument.
OPTIONS_WITH_ARGUMENT = {"-o", "-c", "-t", "--option", "--config-file", "--target-release", "--default-release"}
# Options before "install" may take an argument (-o Dpkg::Use-Pty=0, --option Dpkg::Use-Pty=0).
_ARG_OPTIONS = "|".join(re.escape(o) for o in sorted(OPTIONS_WITH_ARGUMENT, key=len, reverse=True))
INSTALL = re.compile(rf"\bapt(?:-get)?\s+((?:(?:{_ARG_OPTIONS})\s+\S+\s+|-\S+\s+)*)install\b")
# A shell comment starts at a "#" that begins a word.
COMMENT = re.compile(r"(^|\s)#.*$")
TERMINATORS = ("&&", "||", ";", "|", ">", "2>", "&>", ")")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9.+-]*")


class DynamicPackage(ValueError):
    pass


def logical_lines(text: str) -> list[tuple[int, str]]:
    """(first line number, text) with backslash continuations joined and comment lines dropped."""
    out: list[tuple[int, str]] = []
    pending, start = "", 0
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not pending and line.startswith("#"):
            continue
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        out.append((start, pending + line))
        pending = ""
    if pending:
        out.append((start, pending))
    return out


def install_count(text: str) -> int:
    """Install commands in text, outside comment lines and inline comments."""
    return sum(len(INSTALL.findall(COMMENT.sub("", line))) for _, line in logical_lines(text))


def scalars(node: object, path: str = "") -> list[tuple[str, str]]:
    """(key path, value) of every string in a decoded YAML document."""
    if isinstance(node, str):
        return [(path, node)]
    if isinstance(node, dict):
        return [item for key, value in node.items() for item in scalars(value, f"{path}/{key}")]
    if isinstance(node, list):
        return [item for i, value in enumerate(node) for item in scalars(value, f"{path}[{i}]")]
    return []


def packages_in(text: str, where: str) -> set[str]:
    found: set[str] = set()
    for number, line in logical_lines(text):
        line = COMMENT.sub("", line)
        for match in INSTALL.finditer(line):
            tokens = line[match.end():].split()
            skip_next = False
            for token in tokens:
                if skip_next:
                    skip_next = False
                    continue
                if token in TERMINATORS or token.startswith(TERMINATORS) or token.startswith("#"):
                    break
                if token in OPTIONS_WITH_ARGUMENT:
                    skip_next = True
                    continue
                if token.startswith("-"):
                    continue
                # Anything but a plain package name (a variable, an expression,
                # a substitution, a glob, quotes) cannot be known statically.
                name = token.split("=", 1)[0]
                if not PACKAGE.fullmatch(name):
                    raise DynamicPackage(f"{where}:{number}: package {token!r} is not static")
                found.add(name)
    return found


def workflow_files(tos_root: Path) -> list[Path]:
    return sorted((tos_root / ".github" / "workflows").glob("*.y*ml"))


def workflows_digest(files: list[Path], root: Path) -> str:
    h = hashlib.sha256()
    for f in files:
        h.update(str(f.relative_to(root)).encode() + b"\0" + f.read_bytes() + b"\0")
    return h.hexdigest()


def derive(tos_root: Path) -> dict:
    files = workflow_files(tos_root)
    if not files:
        raise SystemExit(f"no workflows under {tos_root}/.github/workflows")
    packages: set[str] = set()
    for f in files:
        packages |= workflow_packages(f.read_text(), f.name)
    return {"workflows_sha256": workflows_digest(files, tos_root), "packages": sorted(packages)}


def workflow_packages(text: str, name: str) -> set[str]:
    """Packages installed by one workflow, from its decoded YAML strings."""
    found: set[str] = set()
    attributed = 0
    for path, value in scalars(yaml.safe_load(text)):
        found |= packages_in(value, f"{name}:{path}")
        attributed += install_count(value)
    raw = install_count(text)
    if raw > attributed:
        raise DynamicPackage(f"{name}: {raw} install commands in the file, {attributed} in its decoded strings")
    return found


def tos_commit(tos_root: Path) -> str:
    out = subprocess.run(["git", "-C", str(tos_root), "rev-parse", "HEAD"], capture_output=True, text=True)
    if out.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", out.stdout.strip()):
        raise SystemExit(f"cannot read the commit of {tos_root}")
    return out.stdout.strip()


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in ("--write", "--check"):
        print(__doc__, file=sys.stderr)
        return 2
    derived = derive(Path(argv[1]))
    if argv[0] == "--write":
        # The commit identifies the source; the digest is what the check compares.
        PINNED.write_text(json.dumps({"tos_commit": tos_commit(Path(argv[1])), **derived}, indent=2) + "\n")
        print(f"{PINNED.name}: {len(derived['packages'])} packages from workflows {derived['workflows_sha256'][:12]}")
        return 0
    pinned = json.loads(PINNED.read_text())
    if {k: pinned.get(k) for k in derived} != derived:
        print(f"{PINNED.name} does not match {argv[1]}'s workflows; regenerate with --write", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
