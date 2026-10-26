#!/usr/bin/env python3
"""Fetch a role's node binaries from a tos GitHub release, verified, as a release DIR.

    fetch-release.py --tag v<version> --rev <40-hex commit> --role validator|fullnode|rpc|dht
                     [--arch x86_64|arm64] --out DIR [--base-url URL]

Production takes its node binaries from the tos repository's GitHub releases
instead of building them on each host (the testnet keeps building with
build-node-binaries.sh). The release is downloaded over plain HTTPS, without a
GitHub login, from <base-url>/<tag>/<asset>; the base URL defaults to the
public tos repository's release downloads and can be overridden with
--base-url or TOS_RELEASE_BASE_URL (tests serve a fake release locally).

Downloaded: the role's binaries as <binary>-linux-<arch>, the node build's
record node-build-info-linux-<arch>.txt, SHA256SUMS, release-provenance.json
and the node build artifact zip tos-node-linux-<arch>.zip, which the
provenance record names as artifact tos-node-<arch>-linux of workflow
build-tos-linux-node-binaries.yml. The rpc role also needs the standalone
services tos-rpc-linux-<arch> and tos-wallet-index-linux-<arch>, members of the
same zip and lines of the same build record, so it works only with a release
that publishes them. Everything is verified in a private scratch
directory before --out is created, and the fetch is refused when

  - an asset is missing from the release;
  - release-provenance.json does not name the tos repository, the full
    release set, --tag and a tag_commit equal to --rev, or its record of the
    node artifact names another workflow or a head_sha other than --rev;
  - SHA256SUMS is malformed, lists a name twice, or does not list a
    downloaded file, or a downloaded file's sha256 differs from it;
  - the artifact zip's sha256 differs from the artifact digest GitHub
    recorded at upload, as the provenance record carries it;
  - a binary or the build record is not byte-identical to the member of that
    zip it was copied from, so every file is bound to the provenance record;
  - the build record names another tos_revision, its sha256 of a binary
    differs from the binary, or its `needed` line for a binary differs from
    the DT_NEEDED libraries readelf reads from it;
  - this host cannot run the binaries: the dynamic loader (ldd) does not find
    every library they need, glibc is older than 2.39, or a binary's -V does
    not report Commit: <rev>. The refusal names the Ubuntu package of each
    missing library it knows (libjemalloc2, libgsl27, libblas3,
    libreadline8t64, libatomic1 on arm64). Nothing is installed here:
    install the packages and fetch again;
  - --out already exists.

The result has exactly the layout build-node-binaries.sh writes and
check-release.sh accepts: the plain binary names (mode 0755), SHA256SUMS over
them and BUILD-INFO naming tos_revision <rev>, the source (tag, repository,
provenance digest, artifact run and digest) and the node build's recipe
lines. check-release.sh and the runtime check run on it before it is moved
into place, so `install-node.sh binaries|prepare --release DIR --rev COMMIT`
installs it unchanged.

SHA256SUMS, the provenance record and the binaries come from the same
release, so these checks detect damage, mix-ups and a release of another
commit, not a deliberately rewritten release. Compare the provenance digest
in BUILD-INFO across hosts and against the release published for the tag.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECK_RELEASE = HERE / "check-release.sh"
DEFAULT_REPOSITORY = "tosnetwork/tos"
DEFAULT_BASE_URL = f"https://github.com/{DEFAULT_REPOSITORY}/releases/download"
RELEASE_SET = "full"
NODE_WORKFLOW = "build-tos-linux-node-binaries.yml"
# The same binaries build-node-binaries.sh builds for each role.
ROLE_BINARIES = {
    "validator": [
        "validator-engine",
        "validator-engine-console",
        "lite-client",
        "generate-random-id",
        "tos-pq-consensus-key",
    ],
    "fullnode": [
        "validator-engine",
        "validator-engine-console",
        "lite-client",
        "generate-random-id",
        "tos-pq-consensus-key",
    ],
    # A full node host that also runs tos-wallet-index and tos-rpc: the index
    # reads the co-hosted node's database and must run the same version. The
    # services ship as tos-rpc-linux-<arch> and tos-wallet-index-linux-<arch>
    # in the node build artifact; a release without them is refused (missing
    # asset) like any other.
    "rpc": [
        "validator-engine",
        "validator-engine-console",
        "lite-client",
        "generate-random-id",
        "tos-pq-consensus-key",
        "tos-rpc",
        "tos-wallet-index",
    ],
    "dht": ["dht-server", "generate-random-id"],
}
# The binaries whose -V prints the commit they were built from. The consensus
# key tool and the two RPC services have no such option; the loader check
# alone covers them.
VERSIONED = frozenset(
    {
        "validator-engine",
        "validator-engine-console",
        "lite-client",
        "generate-random-id",
        "dht-server",
    }
)
MIN_GLIBC = (2, 39)
# The Ubuntu 24.04 package that provides each library the release's node
# binaries link, named in the refusal. The build record's `needed` lines are
# the authority for what a binary links; a soname missing here is still
# refused, without a package hint.
LIBRARY_PACKAGES = {
    "libjemalloc.so.2": "libjemalloc2",
    "libgsl.so.27": "libgsl27",
    "libblas.so.3": "libblas3",
    "libreadline.so.8": "libreadline8t64",
    "libatomic.so.1": "libatomic1",
}
NEEDED_RE = re.compile(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]")
# Lines of the node build's BUILD-INFO copied into the release's BUILD-INFO.
RECIPE_KEYS = (
    "source_date_epoch",
    "architecture",
    "compiler",
    "flags",
    "jemalloc",
    "jemalloc_package",
    "build_os",
)
ARCHES = ("x86_64", "arm64")
REV_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(r"^v[0-9A-Za-z][0-9A-Za-z._-]*$")
SUMS_LINE_RE = re.compile(r"^([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]*)$")
NODE_SHA_RE = re.compile(r"^sha256 ([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)$")
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
# Generous bounds: an asset larger than this is not a node binary.
MAX_ASSET_BYTES = 4 << 30
MAX_METADATA_BYTES = 1 << 20
TIMEOUT_SECONDS = 60
RUN_TIMEOUT_SECONDS = 30
CHUNK = 1 << 20


class Refused(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def check_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    loopback = parsed.hostname in ("127.0.0.1", "::1", "localhost")
    if parsed.scheme == "https" or (parsed.scheme == "http" and loopback):
        return base_url.rstrip("/")
    raise Refused(f"the base URL must be https:// (plain http only on loopback), got {base_url!r}")


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a release download's redirect only to another https URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(req.full_url).scheme == "https":
            if urllib.parse.urlsplit(newurl).scheme != "https":
                raise Refused(f"{req.full_url} redirects to non-https {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(HttpsOnlyRedirect)


def download(base_url: str, tag: str, name: str, destination: Path, limit: int) -> None:
    url = f"{base_url}/{urllib.parse.quote(tag)}/{urllib.parse.quote(name)}"
    request = urllib.request.Request(url, headers={"User-Agent": "tos-ops-fetch-release"})
    try:
        with OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
            size = 0
            with destination.open("wb") as handle:
                for block in iter(lambda: response.read(CHUNK), b""):
                    size += len(block)
                    if size > limit:
                        raise Refused(f"{name} is larger than {limit} bytes")
                    handle.write(block)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise Refused(
                f"release {tag} has no asset {name} ({url} returned 404); "
                "this release does not ship the binaries this role needs"
            ) from None
        raise Refused(f"downloading {url} failed: HTTP {error.code}") from None
    except (urllib.error.URLError, OSError) as error:
        raise Refused(f"downloading {url} failed: {error}") from None


def parse_sums(text: str) -> dict[str, str]:
    sums: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = SUMS_LINE_RE.fullmatch(line)
        if not match:
            raise Refused(f"SHA256SUMS line {number} is not '<sha256>  <name>': {line!r}")
        digest, name = match.groups()
        if name in sums:
            raise Refused(f"SHA256SUMS lists {name} twice")
        sums[name] = digest
    if not sums:
        raise Refused("SHA256SUMS is empty")
    return sums


def check_provenance(record: object, *, repository: str, tag: str, rev: str) -> None:
    if not isinstance(record, dict):
        raise Refused("release-provenance.json is not a JSON object")
    for key, expected in (
        ("repository", repository),
        ("release_set", RELEASE_SET),
        ("tag", tag),
        ("tag_commit", rev),
    ):
        if record.get(key) != expected:
            raise Refused(
                f"release-provenance.json records {key} {record.get(key)!r}, expected {expected!r}"
            )


def provenance_artifact(record: dict, *, artifact: str, rev: str) -> dict:
    """The provenance entry for the build artifact the binaries were copied from."""
    entries = record.get("artifacts")
    if not isinstance(entries, list):
        raise Refused("release-provenance.json lists no artifacts")
    matching = [e for e in entries if isinstance(e, dict) and e.get("artifact_name") == artifact]
    if len(matching) != 1:
        raise Refused(
            f"release-provenance.json has {len(matching)} records of artifact {artifact}, "
            "expected exactly one"
        )
    (entry,) = matching
    if entry.get("workflow") != NODE_WORKFLOW:
        raise Refused(
            f"release-provenance.json says artifact {artifact} came from workflow "
            f"{entry.get('workflow')!r}, not {NODE_WORKFLOW}"
        )
    if entry.get("head_sha") != rev:
        raise Refused(
            f"release-provenance.json says artifact {artifact} was built from "
            f"{entry.get('head_sha')!r}, not {rev}"
        )
    if not DIGEST_RE.fullmatch(str(entry.get("artifact_digest") or "")):
        raise Refused(f"release-provenance.json carries no sha256 digest for artifact {artifact}")
    return entry


def zip_member(archive: Path, name: str) -> zipfile.ZipInfo:
    with zipfile.ZipFile(archive) as bundle:
        matching = [m for m in bundle.infolist() if m.filename == name]
        if len(matching) != 1:
            raise Refused(f"{archive.name} has {len(matching)} members named {name}, expected one")
        (member,) = matching
        if member.is_dir() or (member.external_attr >> 16) & 0o170000 == 0o120000:
            raise Refused(f"{archive.name}: {name} is not a regular file")
        return member


def zip_member_sha256(archive: Path, name: str) -> str:
    member = zip_member(archive, name)
    digest = hashlib.sha256()
    with zipfile.ZipFile(archive) as bundle, bundle.open(member) as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def check_build_info(
    text: str, *, rev: str, digests: dict[str, str]
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Refuse unless the node build record names --rev and each binary's digest.

    Returns the record's recipe lines and its `needed` lines (binary -> sorted
    sonames), the libraries the build linked each binary against."""
    fields: dict[str, str] = {}
    listed: dict[str, str] = {}
    needed: dict[str, list[str]] = {}
    for line in text.splitlines():
        match = NODE_SHA_RE.fullmatch(line)
        if match:
            listed[match.group(2)] = match.group(1)
            continue
        key, _, value = line.partition(" ")
        if key == "needed":
            name, *libraries = value.split()
            if name in needed:
                raise Refused(f"the node build record has two needed lines for {name}")
            needed[name] = sorted(libraries)
            continue
        fields.setdefault(key, value)
    if fields.get("tos_revision") != rev:
        raise Refused(
            f"the node build record names tos_revision {fields.get('tos_revision')!r}, not {rev}"
        )
    for name, digest in digests.items():
        if listed.get(name) != digest:
            raise Refused(
                f"the node build record lists {name} as {listed.get(name)!r}, "
                f"but the binary has sha256 {digest}"
            )
    recipe = {key: fields[key] for key in RECIPE_KEYS if key in fields}
    return recipe, needed


def run_tool(command: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=RUN_TIMEOUT_SECONDS,
            check=False,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired:
        raise Refused(f"{command[0]} did not finish within {RUN_TIMEOUT_SECONDS} s") from None
    except OSError as error:
        raise Refused(f"cannot run {command[0]}: {error}") from None


def elf_needed(readelf: str, path: Path) -> list[str]:
    """The DT_NEEDED sonames of an ELF file, sorted, as `readelf -d` lists them."""
    result = run_tool([readelf, "-d", "-W", str(path)])
    if result.returncode != 0:
        raise Refused(f"readelf cannot read {path.name}: {result.stderr.strip()[-300:]}")
    return sorted(NEEDED_RE.findall(result.stdout))


def check_needed(stage: Path, binaries: list[str], needed: dict[str, list[str]]) -> None:
    """Refuse unless each binary links exactly the libraries the build record names.

    A record without `needed` lines has nothing to compare; a record that has
    them must have one for every binary."""
    if not needed:
        return
    readelf = shutil.which("readelf")
    if readelf is None:
        raise Refused(
            "readelf is not installed (package binutils); it reads the libraries "
            "each binary links to compare them with the build record"
        )
    for name in binaries:
        if name not in needed:
            raise Refused(f"the node build record has needed lines, but none for {name}")
        actual = elf_needed(readelf, stage / name)
        if actual != needed[name]:
            raise Refused(
                f"{name} links {' '.join(actual) or 'nothing'}, but the node build record "
                f"says {' '.join(needed[name]) or 'nothing'}"
            )


def check_runnable(stage: Path, binaries: list[str], rev: str) -> str:
    """Refuse unless this host's loader and glibc run every binary at --rev.

    Installs nothing. Returns the host's glibc version."""
    ldd = shutil.which("ldd")
    if ldd is None:
        raise Refused("ldd is not installed; it comes with glibc (package libc-bin)")
    version = run_tool([ldd, "--version"])
    first = (version.stdout.splitlines() or [""])[0]
    match = re.search(r"(\d+)\.(\d+)\s*$", first)
    if version.returncode != 0 or not match:
        raise Refused(f"cannot read this host's glibc version from ldd --version: {first!r}")
    glibc = (int(match.group(1)), int(match.group(2)))
    if glibc < MIN_GLIBC:
        raise Refused(
            f"this host's glibc is {glibc[0]}.{glibc[1]}; the release binaries need "
            f"glibc {MIN_GLIBC[0]}.{MIN_GLIBC[1]} or newer"
        )
    missing: dict[str, list[str]] = {}
    for name in binaries:
        loader = run_tool([ldd, str(stage / name)])
        output = loader.stdout + loader.stderr
        absent = sorted(
            line.split("=>")[0].strip() for line in output.splitlines() if "=> not found" in line
        )
        if absent:
            missing[name] = absent
        elif loader.returncode != 0 or "not a dynamic executable" in output:
            raise Refused(f"this host's loader cannot load {name}: {output.strip()[-300:]}")
    if missing:
        libraries = sorted({lib for absent in missing.values() for lib in absent})
        packages = sorted({LIBRARY_PACKAGES[lib] for lib in libraries if lib in LIBRARY_PACKAGES})
        unknown = [lib for lib in libraries if lib not in LIBRARY_PACKAGES]
        detail = "; ".join(f"{name} needs {', '.join(libs)}" for name, libs in missing.items())
        hint = f"; install the packages {' '.join(packages)}" if packages else ""
        if unknown:
            hint += f"; no known package provides {', '.join(unknown)}"
        raise Refused(f"this host lacks libraries the binaries need: {detail}{hint}")
    for name in binaries:
        if name in VERSIONED:
            ran = run_tool([str(stage / name), "-V"])
            if f"Commit: {rev}" not in ran.stdout:
                tail = (ran.stdout + ran.stderr).strip()[-300:]
                raise Refused(
                    f"{name} -V does not report Commit: {rev} (exit {ran.returncode}: {tail})"
                )
    return f"{glibc[0]}.{glibc[1]}"


def fetch(
    *,
    tag: str,
    rev: str,
    role: str,
    arch: str,
    out: Path,
    base_url: str,
    repository: str = DEFAULT_REPOSITORY,
) -> list[str]:
    if not TAG_RE.fullmatch(tag):
        raise Refused(f"--tag must be a release tag v<version>, got {tag!r}")
    if not REV_RE.fullmatch(rev):
        raise Refused("--rev must be a full 40-character lowercase commit id")
    if role not in ROLE_BINARIES:
        raise Refused(f"--role must be one of {sorted(ROLE_BINARIES)}, got {role!r}")
    if arch not in ARCHES:
        raise Refused(f"--arch must be one of {list(ARCHES)}, got {arch!r}")
    if out.exists() or out.is_symlink():
        raise Refused(f"{out} already exists; fetch into a new directory")
    if not out.parent.is_dir():
        raise Refused(f"{out.parent} is not a directory")
    base_url = check_base_url(base_url)
    binaries = ROLE_BINARIES[role]
    assets = {name: f"{name}-linux-{arch}" for name in binaries}
    archive_name = f"tos-node-linux-{arch}.zip"
    artifact = f"tos-node-{arch}-linux"
    build_info = f"node-build-info-linux-{arch}.txt"

    with tempfile.TemporaryDirectory(prefix="fetch-release-") as scratch_dir:
        scratch = Path(scratch_dir)
        downloads = scratch / "download"
        downloads.mkdir()
        for name in ("SHA256SUMS", "release-provenance.json", build_info):
            download(base_url, tag, name, downloads / name, MAX_METADATA_BYTES)
        sums = parse_sums((downloads / "SHA256SUMS").read_text(errors="replace"))
        try:
            record = json.loads((downloads / "release-provenance.json").read_text())
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise Refused(f"release-provenance.json is not valid JSON: {error}") from None
        check_provenance(record, repository=repository, tag=tag, rev=rev)
        entry = provenance_artifact(record, artifact=artifact, rev=rev)
        for asset in [archive_name, *assets.values()]:
            download(base_url, tag, asset, downloads / asset, MAX_ASSET_BYTES)

        checked = ["release-provenance.json", build_info, archive_name, *assets.values()]
        actual = {name: sha256_file(downloads / name) for name in ["SHA256SUMS", *checked]}
        for name in checked:
            if name not in sums:
                raise Refused(f"{name} is not listed in the release's SHA256SUMS")
            if sums[name] != actual[name]:
                raise Refused(
                    f"{name} has sha256 {actual[name]}, but the release's SHA256SUMS "
                    f"lists {sums[name]}"
                )
        recorded = DIGEST_RE.fullmatch(entry["artifact_digest"]).group(1)  # type: ignore[union-attr]
        if actual[archive_name] != recorded:
            raise Refused(
                f"{archive_name} has sha256 {actual[archive_name]}, but release-provenance.json "
                f"records artifact {artifact} as {entry['artifact_digest']}"
            )
        # Each file is a copy of a member of the zip the provenance anchors.
        members = {asset: name for name, asset in assets.items()}
        members[build_info] = "BUILD-INFO"
        for asset, member_name in members.items():
            member = zip_member_sha256(downloads / archive_name, member_name)
            if member != actual[asset]:
                raise Refused(
                    f"{asset} is not the {member_name} in {archive_name} that "
                    f"release-provenance.json records ({actual[asset]} != {member})"
                )
        recipe, needed = check_build_info(
            (downloads / build_info).read_text(errors="replace"),
            rev=rev,
            digests={name: actual[asset] for name, asset in assets.items()},
        )

        stage = scratch / "release"
        stage.mkdir()
        for name, asset in sorted(assets.items()):
            shutil.copyfile(downloads / asset, stage / name)
            os.chmod(stage / name, 0o755)
        (stage / "SHA256SUMS").write_text(
            "".join(f"{actual[assets[name]]}  {name}\n" for name in sorted(assets))
        )
        os.chmod(stage, 0o755)
        check_needed(stage, binaries, needed)
        glibc = check_runnable(stage, binaries, rev)
        fetched = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        (stage / "BUILD-INFO").write_text(
            f"tos_revision {rev}\n"
            f"source github-release {tag}\n"
            f"repository {repository}\n"
            f"arch {arch}\n"
            f"provenance_sha256 {actual['release-provenance.json']}\n"
            f"release_sha256sums_sha256 {actual['SHA256SUMS']}\n"
            f"artifact {artifact} run {entry.get('run_id')} {entry['artifact_digest']}\n"
            f"node_build_info_sha256 {actual[build_info]}\n"
            + "".join(f"node_build {key} {value}\n" for key, value in recipe.items())
            + f"host_glibc {glibc}\n"
            f"fetched {fetched}\n"
        )
        result = subprocess.run(
            ["bash", str(CHECK_RELEASE), str(stage), rev, *binaries],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise Refused(f"check-release.sh refused the result: {result.stderr.strip()}")
        if out.exists() or out.is_symlink():
            raise Refused(f"{out} appeared while fetching; fetch into a new directory")
        shutil.move(str(stage), str(out))
    return sorted(binaries)


def default_arch() -> str:
    machine = platform.machine()
    return {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "arm64", "arm64": "arm64"}.get(
        machine.lower(), machine
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--tag", required=True, help="release tag, v<version>")
    parser.add_argument("--rev", required=True, help="the pinned tos commit the tag must name")
    parser.add_argument("--role", required=True, choices=sorted(ROLE_BINARIES))
    parser.add_argument("--arch", choices=ARCHES, help="default: this host's architecture")
    parser.add_argument("--out", required=True, type=Path, help="new release directory")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("TOS_RELEASE_BASE_URL", DEFAULT_BASE_URL),
        help="release download base (default: TOS_RELEASE_BASE_URL or the public tos releases)",
    )
    args = parser.parse_args(argv)
    try:
        binaries = fetch(
            tag=args.tag,
            rev=args.rev,
            role=args.role,
            arch=args.arch or default_arch(),
            out=args.out,
            base_url=args.base_url,
        )
    except Refused as error:
        print(f"fetch-release: refused: {error}", file=sys.stderr)
        return 1
    print(f"release {args.out} ({' '.join(binaries)}) from {args.tag} at {args.rev}")
    print(
        f"install: install-node.sh binaries --role {args.role} --release {args.out} --rev {args.rev}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
