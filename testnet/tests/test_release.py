"""check-release.sh: what install-node.sh accepts as a release to install."""

import hashlib
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
CHECK = SCRIPTS / "check-release.sh"
PIN = "4b4892b8d94e33fcb9699a9fd9b8032c12efdfd0"
OTHER = "85c679c3454f306eb867e25b1960ae3d757bd3dd"
VALIDATOR = [
    "validator-engine",
    "validator-engine-console",
    "lite-client",
    "generate-random-id",
    "tos-pq-consensus-key",
]


def write_sums(release: Path) -> None:
    lines = [
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
        for p in sorted(release.iterdir())
        if p.name not in ("SHA256SUMS", "BUILD-INFO")
    ]
    (release / "SHA256SUMS").write_text("".join(lines))


def make_release(tmp_path: Path, rev: str = PIN) -> Path:
    """A release laid out as build-node-binaries.sh writes it."""
    release = tmp_path / f"release-{rev}"
    release.mkdir()
    for name in VALIDATOR:
        (release / name).write_bytes(f"{name} {rev}\n".encode())
    write_sums(release)
    (release / "BUILD-INFO").write_text(f"tos_revision {rev}\nhost h\nbuilt 2026-10-24T08:13:29Z\n")
    return release


def check(release: Path, rev: str = PIN, binaries=VALIDATOR):
    return subprocess.run(
        ["bash", str(CHECK), str(release), rev, *binaries], capture_output=True, text=True
    )


def test_a_release_of_the_pinned_commit_is_accepted(tmp_path):
    result = check(make_release(tmp_path))
    assert result.returncode == 0, result.stderr


def test_a_self_consistent_release_of_another_commit_is_refused(tmp_path):
    result = check(make_release(tmp_path, OTHER))
    assert result.returncode != 0
    assert f"built from {OTHER}, not the pinned {PIN}" in result.stderr


def test_a_release_without_build_info_is_refused(tmp_path):
    release = make_release(tmp_path)
    (release / "BUILD-INFO").unlink()
    result = check(release)
    assert result.returncode != 0
    assert "BUILD-INFO is missing" in result.stderr


def test_build_info_without_a_revision_is_refused(tmp_path):
    release = make_release(tmp_path)
    (release / "BUILD-INFO").write_text("host h\n")
    result = check(release)
    assert result.returncode != 0
    assert "names no tos_revision" in result.stderr


def test_a_changed_binary_is_refused(tmp_path):
    release = make_release(tmp_path)
    with open(release / "validator-engine", "ab") as f:
        f.write(b"x")
    result = check(release)
    assert result.returncode != 0
    assert "digest check failed" in result.stderr


def test_a_release_without_sha256sums_is_refused(tmp_path):
    release = make_release(tmp_path)
    (release / "SHA256SUMS").unlink()
    result = check(release)
    assert result.returncode != 0
    assert "SHA256SUMS is missing" in result.stderr


def test_a_file_sha256sums_does_not_cover_is_refused(tmp_path):
    release = make_release(tmp_path)
    (release / "dht-server").write_bytes(b"added later\n")
    result = check(release)
    assert result.returncode != 0
    assert "dht-server is not covered by SHA256SUMS" in result.stderr


def test_a_release_lacking_a_role_binary_is_refused(tmp_path):
    release = make_release(tmp_path)
    (release / "lite-client").unlink()
    write_sums(release)
    result = check(release)
    assert result.returncode != 0
    assert "lacks lite-client" in result.stderr


@pytest.mark.parametrize("rev", ["", "4b4892b8d", PIN.upper()])
def test_the_pinned_revision_must_be_a_full_commit_id(tmp_path, rev):
    result = check(make_release(tmp_path), rev)
    assert result.returncode != 0
    assert "full 40-character commit id" in result.stderr


def test_install_node_passes_the_pinned_revision_to_the_check():
    text = (SCRIPTS / "install-node.sh").read_text()
    body = text[text.index("verify_release() {") :]
    body = body[: body.index("\n}\n")]
    assert '[ -n "$REV" ] || die "--rev COMMIT is required with --release"' in body
    assert 'bash "$HERE/check-release.sh" "$dir" "$REV" $(role_binaries)' in body
    # The check runs in the preflight, before any step installs a file.
    preflight = text[text.index("preflight() {") :]
    preflight = preflight[: preflight.index("\n}\n")]
    assert 'verify_release "$RELEASE"' in preflight
    assert "  prepare) preflight; prepare ;;" in text
    assert "  binaries) preflight; binaries ;;" in text


def test_the_build_takes_the_commit_time_before_cmake_configures():
    text = (SCRIPTS / "build-node-binaries.sh").read_text()
    epoch = text.index('SOURCE_DATE_EPOCH=$(git -C "$SRC" log -1 --format=%ct "$REV")')
    assert text.index("export SOURCE_DATE_EPOCH") > epoch
    assert epoch > text.index('checkout -q "$REV"')
    assert epoch < text.index('cmake -S "$SRC"')
