#!/usr/bin/env python3
"""Fetch a role's node binaries from a tos GitHub release, verified, as a release DIR.

    fetch-release.py --tag v<version> --rev <40-hex commit> --role validator|fullnode|dht
                     [--arch x86_64|arm64] --out DIR [--base-url URL]

Production takes its node binaries from the tos repository's GitHub releases
instead of building them on each host (the testnet keeps building with
build-node-binaries.sh). The release is downloaded over plain HTTPS, without a
GitHub login, from <base-url>/<tag>/<asset>; the base URL defaults to the
public tos repository's release downloads and can be overridden with
--base-url or TOS_RELEASE_BASE_URL (tests serve a fake release locally).

Downloaded: the role's binaries as <binary>-linux-<arch>, SHA256SUMS,
release-provenance.json and the build artifact zip tos-linux-<arch>.zip that
the provenance record names. Everything is verified in a private scratch
directory before --out is created, and the fetch is refused when

  - an asset is missing from the release;
  - release-provenance.json does not name the tos repository, the full
    release set, --tag and a tag_commit equal to --rev;
  - SHA256SUMS is malformed, lists a name twice, or does not list a
    downloaded file, or a downloaded file's sha256 differs from it;
  - the artifact zip's sha256 differs from the artifact digest GitHub
    recorded at upload, as the provenance record carries it;
  - a binary is not byte-identical to the member of that zip it was copied
    from, so every binary is bound to the provenance record;
  - --out already exists.

The result has exactly the layout build-node-binaries.sh writes and
check-release.sh accepts: the plain binary names (mode 0755), SHA256SUMS over
them and BUILD-INFO naming tos_revision <rev> and the source (tag, repository,
provenance digest, artifact run and digest). check-release.sh runs on it before
it is moved into place, so `install-node.sh binaries|prepare --release DIR
--rev COMMIT` installs it unchanged.

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
    "dht": ["dht-server", "generate-random-id"],
}
ARCHES = ("x86_64", "arm64")
REV_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(r"^v[0-9A-Za-z][0-9A-Za-z._-]*$")
SUMS_LINE_RE = re.compile(r"^([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]*)$")
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
# Generous bounds: an asset larger than this is not a node binary.
MAX_ASSET_BYTES = 4 << 30
MAX_METADATA_BYTES = 1 << 20
TIMEOUT_SECONDS = 60
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
    archive_name = f"tos-linux-{arch}.zip"
    artifact = f"tos-{arch}-linux"

    with tempfile.TemporaryDirectory(prefix="fetch-release-") as scratch_dir:
        scratch = Path(scratch_dir)
        downloads = scratch / "download"
        downloads.mkdir()
        for name in ("SHA256SUMS", "release-provenance.json"):
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

        actual = {}
        for name in ["SHA256SUMS", "release-provenance.json", archive_name, *assets.values()]:
            actual[name] = sha256_file(downloads / name)
        for name, digest in actual.items():
            if name == "SHA256SUMS":
                continue
            if name not in sums:
                raise Refused(f"{name} is not listed in the release's SHA256SUMS")
            if sums[name] != digest:
                raise Refused(
                    f"{name} has sha256 {digest}, but the release's SHA256SUMS lists {sums[name]}"
                )
        recorded = DIGEST_RE.fullmatch(entry["artifact_digest"]).group(1)  # type: ignore[union-attr]
        if actual[archive_name] != recorded:
            raise Refused(
                f"{archive_name} has sha256 {actual[archive_name]}, but release-provenance.json "
                f"records artifact {artifact} as {entry['artifact_digest']}"
            )
        for name, asset in assets.items():
            member = zip_member_sha256(downloads / archive_name, name)
            if member != actual[asset]:
                raise Refused(
                    f"{asset} is not the {name} in {archive_name} that release-provenance.json "
                    f"records ({actual[asset]} != {member})"
                )

        stage = scratch / "release"
        stage.mkdir()
        for name, asset in sorted(assets.items()):
            shutil.copyfile(downloads / asset, stage / name)
            os.chmod(stage / name, 0o755)
        (stage / "SHA256SUMS").write_text(
            "".join(f"{actual[assets[name]]}  {name}\n" for name in sorted(assets))
        )
        fetched = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        (stage / "BUILD-INFO").write_text(
            f"tos_revision {rev}\n"
            f"source github-release {tag}\n"
            f"repository {repository}\n"
            f"arch {arch}\n"
            f"provenance_sha256 {actual['release-provenance.json']}\n"
            f"release_sha256sums_sha256 {actual['SHA256SUMS']}\n"
            f"artifact {artifact} run {entry.get('run_id')} {entry['artifact_digest']}\n"
            f"fetched {fetched}\n"
        )
        os.chmod(stage, 0o755)
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
