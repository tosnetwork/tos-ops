"""fetch-release.py: a verified release DIR from a tos GitHub release, served locally."""

import functools
import hashlib
import http.server
import importlib.util
import json
import subprocess
import sys
import threading
import zipfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
FETCH = SCRIPTS / "fetch-release.py"
CHECK = SCRIPTS / "check-release.sh"
TAG = "v0.9.1"
PIN = "4b4892b8d94e33fcb9699a9fd9b8032c12efdfd0"
OTHER = "85c679c3454f306eb867e25b1960ae3d757bd3dd"
NODE = [
    "validator-engine",
    "validator-engine-console",
    "lite-client",
    "generate-random-id",
    "tos-pq-consensus-key",
]
DHT = ["dht-server", "generate-random-id"]
ALL = sorted(set(NODE + DHT))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeRelease:
    """A release laid out as release-artifacts.py stages it, under <root>/<tag>/."""

    def __init__(self, root: Path, tag: str = TAG, commit: str = PIN, arches=("x86_64", "arm64")):
        self.dir = root / tag
        self.dir.mkdir(parents=True)
        self.tag, self.commit = tag, commit
        self.records = []
        for arch in arches:
            archive = self.dir / f"tos-linux-{arch}.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                for name in ALL:
                    bundle.writestr(name, self.binary(name, arch))
                bundle.writestr("smartcont/elector-code.fc", ";; contract\n")
            for name in ALL:
                (self.dir / f"{name}-linux-{arch}").write_bytes(self.binary(name, arch))
            self.records.append(
                {
                    "workflow": f"build-tos-linux-{arch}-appimage.yml",
                    "run_id": 1000 + len(self.records),
                    "run_attempt": 1,
                    "run_url": "https://example.invalid/run",
                    "event": "push",
                    "head_sha": commit,
                    "artifact_id": 2000 + len(self.records),
                    "artifact_name": f"tos-{arch}-linux",
                    "artifact_digest": f"sha256:{sha256(archive.read_bytes())}",
                }
            )
        self.write_provenance()
        self.write_sums()

    @staticmethod
    def binary(name: str, arch: str) -> bytes:
        return f"#!/bin/sh\necho {name} {arch}\n".encode()

    def provenance(self) -> dict:
        return json.loads((self.dir / "release-provenance.json").read_text())

    def write_provenance(self, record: dict | None = None) -> None:
        record = record or {
            "repository": "tosnetwork/tos",
            "release_set": "full",
            "tag": self.tag,
            "tag_commit": self.commit,
            "artifacts": self.records,
        }
        (self.dir / "release-provenance.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n"
        )

    def write_sums(self) -> None:
        names = sorted(p.name for p in self.dir.iterdir() if p.name != "SHA256SUMS")
        (self.dir / "SHA256SUMS").write_text(
            "".join(f"{sha256((self.dir / n).read_bytes())}  {n}\n" for n in names)
        )


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture
def served(tmp_path):
    root = tmp_path / "served"
    release = FakeRelease(root)
    handler = functools.partial(Quiet, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield release, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def fetch(base_url, out, *, tag=TAG, rev=PIN, role="validator", arch="x86_64", extra=()):
    command = [sys.executable, "-I", str(FETCH), "--tag", tag, "--rev", rev, "--role", role]
    if arch is not None:
        command += ["--arch", arch]
    command += ["--out", str(out), "--base-url", base_url, *extra]
    return subprocess.run(command, capture_output=True, text=True)


def refused(result, text):
    assert result.returncode != 0, result.stdout
    assert text in result.stderr, result.stderr


@pytest.mark.parametrize(("role", "binaries"), [("validator", NODE), ("dht", DHT)])
def test_a_verified_release_is_written_in_the_layout_check_release_accepts(
    served, tmp_path, role, binaries
):
    release, url = served
    out = tmp_path / f"release-{PIN}"
    result = fetch(url, out, role=role, arch="arm64")
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in out.iterdir()) == sorted([*binaries, "SHA256SUMS", "BUILD-INFO"])
    for name in binaries:
        assert (out / name).read_bytes() == FakeRelease.binary(name, "arm64")
        assert (out / name).stat().st_mode & 0o777 == 0o755
    info = (out / "BUILD-INFO").read_text().splitlines()
    assert f"tos_revision {PIN}" in info
    assert f"source github-release {TAG}" in info
    digest = sha256((release.dir / "release-provenance.json").read_bytes())
    assert f"provenance_sha256 {digest}" in info
    check = subprocess.run(
        ["bash", str(CHECK), str(out), PIN, *binaries], capture_output=True, text=True
    )
    assert check.returncode == 0, check.stderr


def test_a_release_of_another_commit_is_refused(served, tmp_path):
    _, url = served
    out = tmp_path / "out"
    refused(fetch(url, out, rev=OTHER), f"tag_commit '{PIN}', expected '{OTHER}'")
    assert not out.exists()


def test_a_provenance_record_of_another_tag_is_refused(served, tmp_path):
    release, url = served
    record = release.provenance()
    record["tag"] = "v0.9.0"
    release.write_provenance(record)
    release.write_sums()
    refused(fetch(url, tmp_path / "out"), "records tag 'v0.9.0', expected 'v0.9.1'")


def test_a_provenance_record_of_another_repository_is_refused(served, tmp_path):
    release, url = served
    record = release.provenance()
    record["repository"] = "someone/tos"
    release.write_provenance(record)
    release.write_sums()
    refused(fetch(url, tmp_path / "out"), "records repository 'someone/tos'")


def test_an_artifact_built_from_another_commit_is_refused(served, tmp_path):
    release, url = served
    record = release.provenance()
    record["artifacts"][0]["head_sha"] = OTHER
    release.write_provenance(record)
    release.write_sums()
    refused(fetch(url, tmp_path / "out"), f"was built from '{OTHER}', not {PIN}")


def test_a_tampered_binary_is_refused(served, tmp_path):
    release, url = served
    with open(release.dir / "validator-engine-linux-x86_64", "ab") as handle:
        handle.write(b"x")
    out = tmp_path / "out"
    refused(fetch(url, out), "validator-engine-linux-x86_64 has sha256")
    assert not out.exists()


def test_a_binary_that_is_not_the_provenance_artifacts_copy_is_refused(served, tmp_path):
    release, url = served
    # Consistent with SHA256SUMS, but not the bytes of the recorded build artifact.
    (release.dir / "lite-client-linux-x86_64").write_bytes(b"another build\n")
    release.write_sums()
    refused(fetch(url, tmp_path / "out"), "lite-client-linux-x86_64 is not the lite-client in")


def test_a_missing_asset_is_refused(served, tmp_path):
    release, url = served
    (release.dir / "validator-engine-linux-x86_64").unlink()
    release.write_sums()
    out = tmp_path / "out"
    refused(fetch(url, out), "has no asset validator-engine-linux-x86_64")
    assert not out.exists()


def test_a_release_without_provenance_is_refused(served, tmp_path):
    release, url = served
    (release.dir / "release-provenance.json").unlink()
    refused(fetch(url, tmp_path / "out"), "has no asset release-provenance.json")


def test_a_file_not_in_sha256sums_is_refused(served, tmp_path):
    release, url = served
    sums = release.dir / "SHA256SUMS"
    lines = sums.read_text().splitlines(keepends=True)
    sums.write_text("".join(x for x in lines if not x.endswith("  dht-server-linux-x86_64\n")))
    refused(
        fetch(url, tmp_path / "out", role="dht"),
        "dht-server-linux-x86_64 is not listed in the release's SHA256SUMS",
    )


def test_provenance_not_matching_sha256sums_is_refused(served, tmp_path):
    release, url = served
    record = release.provenance()
    record["note"] = "edited after SHA256SUMS"
    release.write_provenance(record)
    refused(fetch(url, tmp_path / "out"), "release-provenance.json has sha256")


def test_an_artifact_digest_mismatch_is_refused(served, tmp_path):
    release, url = served
    record = release.provenance()
    record["artifacts"][0]["artifact_digest"] = "sha256:" + "0" * 64
    release.write_provenance(record)
    release.write_sums()
    refused(
        fetch(url, tmp_path / "out"), "release-provenance.json records artifact tos-x86_64-linux"
    )


def test_a_malformed_sha256sums_is_refused(served, tmp_path):
    release, url = served
    with open(release.dir / "SHA256SUMS", "a") as handle:
        handle.write("not a digest line\n")
    refused(fetch(url, tmp_path / "out"), "SHA256SUMS line")


def test_an_existing_out_is_refused_and_left_alone(served, tmp_path):
    _, url = served
    out = tmp_path / "out"
    out.mkdir()
    (out / "keep").write_text("operator data\n")
    refused(fetch(url, out), "already exists")
    assert [p.name for p in out.iterdir()] == ["keep"]


def test_a_role_this_tool_does_not_know_is_refused(served, tmp_path):
    _, url = served
    refused(fetch(url, tmp_path / "out", role="observer"), "invalid choice: 'observer'")


def test_an_arch_this_tool_does_not_know_is_refused(served, tmp_path):
    _, url = served
    refused(fetch(url, tmp_path / "out", arch="riscv64"), "invalid choice: 'riscv64'")


@pytest.mark.parametrize(
    ("tag", "rev", "text"),
    [
        ("0.9.1", PIN, "--tag must be a release tag"),
        ("v0.9.1/../x", PIN, "--tag must be a release tag"),
        (TAG, PIN[:12], "--rev must be a full"),
        (TAG, PIN.upper(), "--rev must be a full"),
    ],
)
def test_malformed_tags_and_revisions_are_refused(served, tmp_path, tag, rev, text):
    _, url = served
    refused(fetch(url, tmp_path / "out", tag=tag, rev=rev), text)


def test_plain_http_is_refused_off_loopback(tmp_path):
    result = fetch("http://releases.example.invalid", tmp_path / "out")
    refused(result, "must be https://")


def test_the_base_url_comes_from_the_environment(served, tmp_path):
    _, url = served
    command = [sys.executable, "-I", str(FETCH), "--tag", TAG, "--rev", PIN, "--role", "dht"]
    command += ["--arch", "x86_64", "--out", str(tmp_path / "out")]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env={"TOS_RELEASE_BASE_URL": url, "PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr


def load_module():
    spec = importlib.util.spec_from_file_location("fetch_release", FETCH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_result_check_release_refuses_is_not_moved_into_place(served, tmp_path):
    _, url = served
    module = load_module()
    refuse = tmp_path / "refuse.sh"
    refuse.write_text("echo 'check-release: refused for the test' >&2; exit 1\n")
    module.CHECK_RELEASE = refuse
    out = tmp_path / "out"
    with pytest.raises(module.Refused, match="check-release.sh refused the result"):
        module.fetch(tag=TAG, rev=PIN, role="dht", arch="x86_64", out=out, base_url=url)
    assert not out.exists()


def test_the_role_binaries_are_the_ones_the_host_build_builds():
    module = load_module()
    build = (SCRIPTS / "build-node-binaries.sh").read_text()
    assert f"validator|fullnode) TARGETS=({' '.join(module.ROLE_BINARIES['validator'])})" in build
    assert f"dht) TARGETS=({' '.join(module.ROLE_BINARIES['dht'])})" in build
    assert module.ROLE_BINARIES["fullnode"] == module.ROLE_BINARIES["validator"]
