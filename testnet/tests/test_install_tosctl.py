"""install-tosctl.sh: tosctl from a fetched release directory, on an unprivileged fake host.

No root and no live host: TOS_INSTALL_PREFIX roots /usr/local/bin and /etc/tos
under a temporary directory, `id` answers 0 and `install` drops the owner
change, as in test_rpc_role.py.
"""

import hashlib
import subprocess
from pathlib import Path

import pytest
from test_fetch_release import PIN as FETCH_PIN
from test_fetch_release import TAG as FETCH_TAG
from test_fetch_release import fakebin, served  # noqa: F401  (pytest fixtures)
from test_fetch_release import run as fetch_release
from test_rpc_role import FAKE_ID, root_namespace_available

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
INSTALL = SCRIPTS / "install-tosctl.sh"
TAG = "v0.9.1"
PIN = "4b4892b8d94e33fcb9699a9fd9b8032c12efdfd0"
OTHER = "85c679c3454f306eb867e25b1960ae3d757bd3dd"
PROVENANCE = "ab" * 32
OLD_BINARY = b"#!/bin/sh\necho the previous tosctl\n"
OLD_RECORD = "tos_revision " + OTHER + "\nsha256 " + "0" * 64 + "\nbuilt 2026-10-24T08:13:29Z\n"
# install without the owner change an unprivileged test cannot make. With
# FAKE_CORRUPT it damages the staged binary, as a failing disk would.
FAKE_INSTALL = """#!/usr/bin/env python3
import os, subprocess, sys
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write("install " + " ".join(sys.argv[1:]) + "\\n")
args, rest = [], sys.argv[1:]
while rest:
    if rest[0] in ("-o", "-g"):
        rest = rest[2:]
    else:
        args.append(rest.pop(0))
status = subprocess.run(["/usr/bin/install", *args]).returncode
if status == 0 and os.environ.get("FAKE_CORRUPT") and "/.tosctl." in args[-1]:
    with open(args[-1], "ab") as handle:
        handle.write(b"# damaged\\n")
sys.exit(status)
"""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tosctl_binary(line: str = f"COMMIT_ID: {PIN}", status: int = 0) -> bytes:
    """A tosctl that answers --version as the real one does."""
    return (
        "#!/bin/sh\n"
        'echo "tosctl 0.3.0"\n'
        '[ "$1" = --version ] || exit 0\n'
        f'echo "{line}"\n'
        'echo "BUILD_DATE: 2026-11-18 04:29:43 +0000"\n'
        f"exit {status}\n"
    ).encode()


def build_info(rev: str = PIN) -> str:
    """BUILD-INFO as fetch-release.py --role tosctl writes it."""
    return (
        f"tos_revision {rev}\n"
        f"source github-release {TAG}\n"
        "repository tosnetwork/tos\n"
        "arch x86_64\n"
        f"provenance_sha256 {PROVENANCE}\n"
        f"release_sha256sums_sha256 {'cd' * 32}\n"
        f"artifact tos-node-x86_64-linux run 1001 sha256:{'ef' * 32}\n"
        f"node_build_info_sha256 {'12' * 32}\n"
        "node_build rustc 1.100.0 (0ef1bc386 2026-11-09)\n"
        "node_build cargo 1.100.0 (3acc79c0c 2026-11-05)\n"
        "node_build rust_flags RUSTFLAGS=-C target-cpu=x86-64-v2 CC=clang-21 "
        "cargo build --release --locked -p tosctl\n"
        "host_glibc 2.39\n"
        "fetched 2026-11-18T05:00:00Z\n"
    )


def make_release(tmp_path: Path, binary: bytes | None = None, rev: str = PIN) -> Path:
    release = tmp_path / f"tosctl-{rev}"
    release.mkdir()
    data = tosctl_binary() if binary is None else binary
    (release / "tosctl").write_bytes(data)
    (release / "tosctl").chmod(0o755)
    (release / "SHA256SUMS").write_text(f"{sha256(data)}  tosctl\n")
    (release / "BUILD-INFO").write_text(build_info(rev))
    return release


class Host:
    def __init__(self, tmp_path: Path, uid: int = 0):
        self.bin = tmp_path / "hostbin"
        self.bin.mkdir()
        for name, text in (
            ("id", FAKE_ID.replace("echo 0", f"echo {uid}")),
            ("install", FAKE_INSTALL),
        ):
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        self.prefix = tmp_path / "root"
        self.prefix.mkdir()
        self.log = tmp_path / "host.log"
        self.log.write_text("")
        self.tosctl = self.prefix / "usr/local/bin/tosctl"
        self.record = self.prefix / "etc/tos/TOSCTL-BUILD-INFO"

    def env(self, **extra: str) -> dict[str, str]:
        return {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "FAKE_LOG": str(self.log),
            "TOS_INSTALL_PREFIX": str(self.prefix),
            **extra,
        }

    def __call__(self, *args: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(INSTALL), *args], capture_output=True, text=True, env=self.env(**extra)
        )

    def install(self, release: Path, rev: str = PIN, **extra: str) -> subprocess.CompletedProcess:
        return self("--release", str(release), "--rev", rev, **extra)

    def with_previous_install(self) -> "Host":
        self.tosctl.parent.mkdir(parents=True)
        self.tosctl.write_bytes(OLD_BINARY)
        self.record.parent.mkdir(parents=True)
        self.record.write_text(OLD_RECORD)
        return self

    def files(self) -> list[str]:
        return sorted(
            str(p.relative_to(self.prefix)) for p in self.prefix.rglob("*") if p.is_file()
        )

    def installs(self) -> list[str]:
        return [x for x in self.log.read_text().splitlines() if x.startswith("install ")]


@pytest.fixture
def host(tmp_path):
    return Host(tmp_path)


def refused(result: subprocess.CompletedProcess, text: str) -> None:
    assert result.returncode != 0, result.stdout
    assert text in result.stderr, result.stderr


# ---------------------------------------------------------------- the install


def test_a_fetched_release_is_installed_with_its_record(host, tmp_path):
    release = make_release(tmp_path)
    result = host.install(release)
    assert result.returncode == 0, result.stderr
    assert host.tosctl.read_bytes() == tosctl_binary()
    assert host.tosctl.stat().st_mode & 0o777 == 0o755
    assert host.record.stat().st_mode & 0o777 == 0o644
    # Nothing staged is left behind.
    assert host.files() == ["etc/tos/TOSCTL-BUILD-INFO", "usr/local/bin/tosctl"]
    record = host.record.read_text().splitlines()
    # The two fields build-tosctl.sh writes first, then the release's source.
    assert record[:2] == [f"tos_revision {PIN}", f"sha256 {sha256(tosctl_binary())}"]
    assert f"source github-release {TAG}" in record
    assert f"provenance_sha256 {PROVENANCE}" in record
    assert "node_build rustc 1.100.0 (0ef1bc386 2026-11-09)" in record
    assert any(x.startswith("node_build rust_flags RUSTFLAGS=-C target-cpu=") for x in record)
    assert record[-1].startswith("installed 20") and record[-1].endswith("Z")
    assert [x.split()[0] for x in record].count("tos_revision") == 1
    assert [x.split()[0] for x in record].count("sha256") == 1
    assert f"installed {host.tosctl} (sha256 {sha256(tosctl_binary())})" in result.stdout
    assert f"from release {TAG} at {PIN}" in result.stdout


def test_the_binary_and_the_record_are_owned_by_root(host, tmp_path):
    assert host.install(make_release(tmp_path)).returncode == 0
    binary, record = (x for x in host.installs() if " -d " not in f" {x} ")
    assert binary.startswith("install -m 0755 -o root -g root ")
    assert record.startswith("install -m 0644 -o root -g root ")


def test_the_binary_is_staged_beside_its_destination_and_renamed(host, tmp_path):
    release = make_release(tmp_path)
    assert host.install(release).returncode == 0
    # Nothing is ever copied onto the destination itself.
    destinations = [x.split()[-1] for x in host.installs()]
    assert str(host.tosctl) not in destinations
    assert str(host.record) not in destinations
    staged = [x for x in destinations if Path(x).name.startswith(".tosctl.")]
    assert len(staged) == 1 and Path(staged[0]).parent == host.tosctl.parent
    staged = [x for x in destinations if Path(x).name.startswith(".TOSCTL-BUILD-INFO.")]
    assert len(staged) == 1 and Path(staged[0]).parent == host.record.parent
    text = INSTALL.read_text()
    assert 'mv -fT -- "$STAGED_BIN" "$BIN/tosctl"' in text
    assert 'mv -fT -- "$STAGED_INFO" "$ETC/TOSCTL-BUILD-INFO"' in text


def test_a_previous_install_is_replaced(host, tmp_path):
    host.with_previous_install()
    assert host.install(make_release(tmp_path)).returncode == 0
    assert host.tosctl.read_bytes() == tosctl_binary()
    assert host.record.read_text().startswith(f"tos_revision {PIN}\n")
    assert "built " not in host.record.read_text()
    assert host.files() == ["etc/tos/TOSCTL-BUILD-INFO", "usr/local/bin/tosctl"]


def test_a_release_fetch_release_wrote_is_installed(served, host, tmp_path):  # noqa: F811
    release, url = served
    out = tmp_path / "fetched"
    fetched = fetch_release(release, url, out, role="tosctl")
    assert fetched.returncode == 0, fetched.stderr
    command = f"install-tosctl.sh --release {out} --rev {FETCH_PIN}"
    assert f"install: {command}" in fetched.stdout
    result = host.install(out, FETCH_PIN)
    assert result.returncode == 0, result.stderr
    assert host.tosctl.read_bytes() == release.binary("tosctl", "x86_64")
    record = host.record.read_text().splitlines()
    assert record[0] == f"tos_revision {FETCH_PIN}"
    assert f"source github-release {FETCH_TAG}" in record
    provenance = sha256((release.dir / "release-provenance.json").read_bytes())
    assert f"provenance_sha256 {provenance}" in record


def test_the_record_keeps_the_fields_the_host_build_writes():
    build = (SCRIPTS / "build-tosctl.sh").read_text()
    install = INSTALL.read_text()
    assert 'echo "tos_revision $REV"' in build and 'echo "tos_revision $REV"' in install
    assert 'echo "sha256 $(sha256sum /usr/local/bin/tosctl' in build
    assert 'echo "sha256 $EXPECTED"' in install
    assert "/etc/tos/TOSCTL-BUILD-INFO" in build and '"$ETC/TOSCTL-BUILD-INFO"' in install


# ---------------------------------------------------------------- refusals


def other_commit(tmp_path):
    return make_release(tmp_path, rev=OTHER), f"was built from {OTHER}, not the pinned {PIN}"


def tampered(tmp_path):
    release = make_release(tmp_path)
    with open(release / "tosctl", "ab") as handle:
        handle.write(b"x")
    return release, "release digest check failed"


def without_tosctl(tmp_path):
    release = make_release(tmp_path)
    (release / "tosctl").unlink()
    (release / "SHA256SUMS").write_text(f"{sha256(b'node')}  lite-client\n")
    (release / "lite-client").write_bytes(b"node")
    return release, "the release lacks tosctl"


def without_sums(tmp_path):
    release = make_release(tmp_path)
    (release / "SHA256SUMS").unlink()
    return release, "SHA256SUMS is missing"


def reporting_another_commit(tmp_path):
    release = make_release(tmp_path, tosctl_binary(f"COMMIT_ID: {OTHER}"))
    return release, f"tosctl --version does not report COMMIT_ID: {PIN}"


def reporting_a_longer_line(tmp_path):
    release = make_release(tmp_path, tosctl_binary(f"COMMIT_ID: {PIN}-dirty"))
    return release, f"tosctl --version does not report COMMIT_ID: {PIN}"


def reporting_the_commit_inside_a_line(tmp_path):
    release = make_release(tmp_path, tosctl_binary(f"PARENT_COMMIT_ID: {PIN}"))
    return release, f"tosctl --version does not report COMMIT_ID: {PIN}"


def failing_to_run(tmp_path):
    binary = b'#!/bin/sh\necho "error while loading shared libraries: libssl.so.3" >&2\nexit 127\n'
    release = make_release(tmp_path, binary)
    return release, "tosctl --version failed on this host (exit 127): error while loading"


def exiting_nonzero_with_the_commit(tmp_path):
    release = make_release(tmp_path, tosctl_binary(status=3))
    return release, "tosctl --version failed on this host (exit 3)"


def without_a_source(tmp_path):
    release = make_release(tmp_path)
    info = release / "BUILD-INFO"
    lines = [x for x in info.read_text().splitlines() if not x.startswith("source ")]
    info.write_text("\n".join(lines) + "\n")
    return release, "names no 'source github-release <tag>'"


def a_host_build(tmp_path):
    release = make_release(tmp_path)
    (release / "BUILD-INFO").write_text(f"tos_revision {PIN}\nhost h\nbuilt 2026-10-24T08:13:29Z\n")
    return release, "install only what fetch-release.py --role tosctl wrote"


def with_two_sources(tmp_path):
    release = make_release(tmp_path)
    with open(release / "BUILD-INFO", "a") as handle:
        handle.write("source github-release v0.9.2\n")
    return release, "names more than one source release"


def without_a_provenance_digest(tmp_path):
    release = make_release(tmp_path)
    info = release / "BUILD-INFO"
    info.write_text(
        info.read_text().replace(f"provenance_sha256 {PROVENANCE}", "provenance_sha256 -")
    )
    return release, "carries no provenance_sha256 digest"


def a_symbolic_link(tmp_path):
    release = make_release(tmp_path)
    target = tmp_path / "elsewhere"
    target.write_bytes(tosctl_binary())
    target.chmod(0o755)
    (release / "tosctl").unlink()
    (release / "tosctl").symlink_to(target)
    return release, "tosctl is a symbolic link"


def listed_twice(tmp_path):
    release = make_release(tmp_path)
    sums = release / "SHA256SUMS"
    sums.write_text(sums.read_text() * 2)
    return release, "SHA256SUMS does not list tosctl exactly once"


REFUSALS = [
    listed_twice,
    other_commit,
    tampered,
    without_tosctl,
    without_sums,
    reporting_another_commit,
    reporting_a_longer_line,
    reporting_the_commit_inside_a_line,
    failing_to_run,
    exiting_nonzero_with_the_commit,
    without_a_source,
    a_host_build,
    with_two_sources,
    without_a_provenance_digest,
    a_symbolic_link,
]


@pytest.mark.parametrize("defect", REFUSALS, ids=lambda f: f.__name__)
def test_a_refused_release_leaves_the_installed_tosctl_alone(host, tmp_path, defect):
    host.with_previous_install()
    release, text = defect(tmp_path)
    refused(host.install(release), text)
    assert host.tosctl.read_bytes() == OLD_BINARY
    assert host.record.read_text() == OLD_RECORD
    assert host.files() == ["etc/tos/TOSCTL-BUILD-INFO", "usr/local/bin/tosctl"]


@pytest.mark.parametrize("defect", REFUSALS, ids=lambda f: f.__name__)
def test_a_refused_release_installs_nothing_on_a_new_host(host, tmp_path, defect):
    release, text = defect(tmp_path)
    refused(host.install(release), text)
    assert host.files() == []


def test_a_staged_copy_that_differs_from_sha256sums_is_refused(host, tmp_path):
    host.with_previous_install()
    release = make_release(tmp_path)
    result = host.install(release, FAKE_CORRUPT="1")
    refused(result, "the staged tosctl has sha256")
    assert f"SHA256SUMS lists {sha256(tosctl_binary())}" in result.stderr
    assert host.tosctl.read_bytes() == OLD_BINARY
    assert host.record.read_text() == OLD_RECORD
    assert host.files() == ["etc/tos/TOSCTL-BUILD-INFO", "usr/local/bin/tosctl"]


def test_the_release_is_checked_by_check_release_for_tosctl():
    text = INSTALL.read_text()
    check = 'bash "$HERE/check-release.sh" "$RELEASE" "$REV" tosctl || die'
    assert check in text
    # Before anything is created on the host.
    assert text.index(check) < text.index("install -d ")
    assert text.index(check) < text.index("mktemp")


# ---------------------------------------------------------------- arguments and the root check


@pytest.mark.parametrize(
    ("args", "text"),
    [
        ((), "--release DIR is required"),
        (("--rev", PIN), "--release DIR is required"),
        (("--release",), "--release needs a directory"),
        (("--release", "DIR", "--rev"), "--rev needs a commit id"),
        (("--release", "DIR"), "--rev must be a full 40-character commit id"),
        (("--release", "DIR", "--rev", PIN[:12]), "--rev must be a full 40-character commit id"),
        (("--release", "DIR", "--rev", PIN.upper()), "--rev must be a full 40-character commit id"),
        (("--release", "DIR", "--rev", PIN, "--role", "tosctl"), "unknown option --role"),
        (("--release", "/nonexistent/release", "--rev", PIN), "is not a directory"),
    ],
)
def test_malformed_arguments_are_refused_before_any_change(host, tmp_path, args, text):
    release = make_release(tmp_path)
    args = tuple(str(release) if x == "DIR" else x for x in args)
    refused(host(*args), text)
    assert host.files() == []
    assert host.installs() == []


def test_an_unprivileged_run_is_refused(tmp_path):
    host = Host(tmp_path, uid=1000)
    refused(host.install(make_release(tmp_path)), "install-tosctl: run as root")
    assert host.files() == []


PREFIX_REFUSAL = "TOS_INSTALL_PREFIX is for unprivileged tests only"


def run_with_injected_euid(tmp_path, *, as_root: bool):
    """install-tosctl.sh with TOS_INSTALL_PREFIX, EUID=1000 in the environment and
    an `id` on PATH that answers 1000; as_root runs it with effective uid 0."""
    host = Host(tmp_path, uid=1000)
    release = make_release(tmp_path)
    command = ["bash", str(INSTALL), "--release", str(release), "--rev", PIN]
    if as_root:
        command = ["unshare", "--user", "--map-root-user", *command]
    result = subprocess.run(command, capture_output=True, text=True, env=host.env(EUID="1000"))
    return result, host


def test_a_root_run_refuses_the_test_prefix_even_with_an_injected_euid(tmp_path):
    if not root_namespace_available():
        pytest.skip("unshare --user --map-root-user is not available to this user")
    result, host = run_with_injected_euid(tmp_path, as_root=True)
    assert result.returncode != 0
    assert PREFIX_REFUSAL in result.stderr, result.stderr
    assert host.files() == []


def test_an_unprivileged_run_accepts_the_test_prefix(tmp_path):
    # The control: the same command with the real, non-zero effective uid gets
    # past the prefix guard (and stops at the root check of the fake id).
    result, _ = run_with_injected_euid(tmp_path, as_root=False)
    assert result.returncode != 0
    assert PREFIX_REFUSAL not in result.stderr
    assert "run as root" in result.stderr


def test_every_host_path_is_under_the_test_prefix():
    seen = 0
    for line in INSTALL.read_text().splitlines():
        if line.lstrip().startswith("#"):
            continue
        for path in ("/usr/local/bin", "/etc/tos", "/var/lib", "/opt/"):
            if path in line:
                assert "$PREFIX" in line, line
                seen += 1
    assert seen == 2
