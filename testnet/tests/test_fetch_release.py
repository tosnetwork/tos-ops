"""fetch-release.py: a verified release DIR from a tos GitHub release, served locally."""

import functools
import hashlib
import http.server
import importlib.util
import json
import os
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
NODE_WORKFLOW = "build-tos-linux-node-binaries.yml"
NODE = [
    "validator-engine",
    "validator-engine-console",
    "lite-client",
    "generate-random-id",
    "tos-pq-consensus-key",
]
DHT = ["dht-server", "generate-random-id"]
# The standalone public-RPC services, published as tos-rpc-linux-<arch> and
# tos-wallet-index-linux-<arch> from the same node build artifact.
SERVICES = ["tos-rpc", "tos-wallet-index"]
RPC = NODE + SERVICES
ALL = sorted(set(NODE + DHT + SERVICES))
# The operator tool, published as tosctl-linux-<arch> from the same artifact
# by a release that builds it. Its own role fetches it; no node role does.
TOSCTL = "tosctl"
NODE_ROLES = {"validator": NODE, "fullnode": NODE, "rpc": RPC, "dht": DHT}
# What the release build links into tosctl (no C++ runtime), as its build
# record lists it on each architecture.
TOSCTL_LINKED = ["libc.so.6", "libcrypto.so.3", "libgcc_s.so.1", "libm.so.6", "libssl.so.3"]
LOADER = {"x86_64": "ld-linux-x86-64.so.2", "arm64": "ld-linux-aarch64.so.1"}
RUST_LINES = [
    "rustc 1.100.0 (0ef1bc386 2026-11-09)",
    "cargo 1.100.0 (3acc79c0c 2026-11-05)",
    "rust_flags RUSTFLAGS=-C target-cpu=x86-64-v2 CC=clang-21 "
    "cargo build --release --locked -p tosctl",
]
# The libraries the release's node build links into each binary (tos release
# policy: the build record's `needed` lines are the authority).
STDLIBS = ["libc.so.6", "libgcc_s.so.1", "libm.so.6", "libstdc++.so.6"]
LINKED = {
    "validator-engine": ["libjemalloc.so.2", "libgsl.so.27", "libblas.so.3"],
    "dht-server": ["libjemalloc.so.2"],
    "validator-engine-console": ["libreadline.so.8"],
    "lite-client": ["libreadline.so.8"],
    "generate-random-id": [],
    "tos-pq-consensus-key": [],
    "tos-rpc": ["libjemalloc.so.2"],
    "tos-wallet-index": ["libjemalloc.so.2"],
}
# Binaries without a -V option (no "Commit:" line).
UNVERSIONED = ("tos-pq-consensus-key", "tos-rpc", "tos-wallet-index")
JEMALLOC = ("validator-engine", "dht-server")
ARCHES = ("x86_64", "arm64")


def linked(name: str, arch: str) -> list[str]:
    if name == TOSCTL:
        return sorted([*TOSCTL_LINKED, LOADER[arch]])
    extra = ["libatomic.so.1"] if arch == "arm64" else []
    return sorted(LINKED[name] + STDLIBS + extra)


# A fake binary lists its DT_NEEDED sonames as "# NEEDED <soname>" lines. The
# fake readelf and ldd read them back the way the real tools report them.
FAKE_READELF = r"""#!/bin/sh
[ "$1" = -d ] && [ "$2" = -W ] || exit 2
echo "Dynamic section at offset 0x1000 contains 30 entries:"
sed -n 's/^# NEEDED \(.*\)$/ 0x0000000000000001 (NEEDED)             Shared library: [\1]/p' "$3"
"""
# ldd, steered by the environment: FAKE_GLIBC, FAKE_NOT_DYNAMIC, and
# FAKE_MISSING (space-separated sonames this host lacks).
FAKE_LDD = r"""#!/bin/sh
if [ "$1" = --version ]; then
  echo "ldd (Fake GLIBC ${FAKE_GLIBC:-2.39}-0) ${FAKE_GLIBC:-2.39}"
  exit 0
fi
if [ -n "$FAKE_NOT_DYNAMIC" ]; then
  echo "	not a dynamic executable"
  exit 1
fi
echo "	linux-vdso.so.1 (0x00007ffd)"
for lib in $(sed -n 's/^# NEEDED //p' "$1"); do
  case " $FAKE_MISSING " in
    *" $lib "*) echo "	$lib => not found" ;;
    *) echo "	$lib => /lib/$lib (0x00007f01)" ;;
  esac
done
"""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeRelease:
    """A release laid out as release-artifacts.py stages it, under <root>/<tag>/.

    Change an attribute, then publish() writes a release consistent in every
    other respect, so a test isolates exactly one defect."""

    def __init__(self, root: Path, tag: str = TAG, commit: str = PIN):
        self.dir = root / tag
        self.dir.mkdir(parents=True)
        self.tag, self.commit = tag, commit
        self.build_commit = commit
        self.binary_commit = commit
        self.workflow = NODE_WORKFLOW
        self.build_info_member = True
        # False: a release published before the node artifact carried the services.
        self.services = True
        # False: a release published before the node artifact carried tosctl.
        self.tosctl = True
        # What tosctl --version prints as its commit line, and the build
        # record's lines of tosctl's recipe.
        self.tosctl_commit_line = f"COMMIT_ID: {commit}"
        self.rust_lines = list(RUST_LINES)
        # The build record's slhdsa_sha256 line per architecture; None: a
        # release built before the record carried it.
        self.slhdsa: dict[str, str | None] = dict(SLHDSA)
        # Overrides of what a binary links, and of what the build record says.
        self.linked_override: dict[str, list[str]] = {}
        self.needed_override: dict[str, list[str] | None] = {}
        self.publish()

    def links(self, name: str, arch: str) -> list[str]:
        return self.linked_override.get(name, linked(name, arch))

    def binary(self, name: str, arch: str) -> bytes:
        body = f"#!/bin/sh\n# {name} {arch}\n"
        body += "".join(f"# NEEDED {lib}\n" for lib in self.links(name, arch))
        if name == TOSCTL:
            # As the real tool: the commit only under --version, on a line of
            # its own; -V prints the package version alone.
            body += (
                'echo "tosctl 0.3.0"\n'
                '[ "$1" = --version ] || exit 0\n'
                f'echo "{self.tosctl_commit_line}"\n'
                'echo "BUILD_DATE: 2026-11-18 04:29:43 +0000"\n'
            )
        elif name not in UNVERSIONED:
            body += f'echo "{name} build"\necho "Commit: {self.binary_commit}"\n'
        return body.encode()

    def build_info(self, arch: str) -> bytes:
        lines = [
            f"tos_revision {self.build_commit}",
            "source_date_epoch 1761400000",
            f"architecture {'aarch64' if arch == 'arm64' else arch}",
            "compiler Ubuntu clang version 21.1.0",
            "flags CMAKE_BUILD_TYPE=Release TOS_ARCH=x86-64-v2 PORTABLE=x86-64-v2 TOS_USE_JEMALLOC=ON",
            *([f"slhdsa_sha256 {self.slhdsa[arch]}"] if self.slhdsa[arch] is not None else []),
            *(self.rust_lines if self.tosctl else []),
            "jemalloc /usr/lib/libjemalloc.so",
            "jemalloc_package libjemalloc-dev 5.3.0-2build1",
            "build_os Ubuntu 24.04.3 LTS",
        ]
        for n in self.shipped():
            libs = self.needed_override.get(n, self.links(n, arch))
            if libs is not None:
                lines.append(" ".join(["needed", n, *sorted(libs)]))
        lines += [f"sha256 {sha256(self.binary(n, arch))}  {n}" for n in self.shipped()]
        return ("\n".join(lines) + "\n").encode()

    def shipped(self) -> list[str]:
        names = [n for n in ALL if self.services or n not in SERVICES]
        return [*names, TOSCTL] if self.tosctl else names

    def publish(self) -> None:
        for path in self.dir.iterdir():
            path.unlink()
        records = []
        for arch in ARCHES:
            # The AppImage build's artifact, which carries no node binaries.
            appimage = self.dir / f"tos-linux-{arch}.zip"
            with zipfile.ZipFile(appimage, "w") as bundle:
                bundle.writestr("lite-client", b"an AppImage\n")
            archive = self.dir / f"tos-node-linux-{arch}.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                for name in self.shipped():
                    bundle.writestr(name, self.binary(name, arch))
                if self.build_info_member:
                    bundle.writestr("BUILD-INFO", self.build_info(arch))
            for name in self.shipped():
                (self.dir / f"{name}-linux-{arch}").write_bytes(self.binary(name, arch))
            (self.dir / f"node-build-info-linux-{arch}.txt").write_bytes(self.build_info(arch))
            for artifact, workflow, path in (
                (f"tos-{arch}-linux", f"build-tos-linux-{arch}-appimage.yml", appimage),
                (f"tos-node-{arch}-linux", self.workflow, archive),
            ):
                records.append(
                    {
                        "workflow": workflow,
                        "run_id": 1000 + len(records),
                        "run_attempt": 1,
                        "run_url": "https://example.invalid/run",
                        "event": "push",
                        "head_sha": self.commit,
                        "artifact_id": 2000 + len(records),
                        "artifact_name": artifact,
                        "artifact_digest": f"sha256:{sha256(path.read_bytes())}",
                    }
                )
        self.write_provenance(
            {
                "repository": "tosnetwork/tos",
                "release_set": "full",
                "tag": self.tag,
                "tag_commit": self.commit,
                "artifacts": records,
            }
        )
        self.write_sums()

    def provenance(self) -> dict:
        return json.loads((self.dir / "release-provenance.json").read_text())

    def write_provenance(self, record: dict) -> None:
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
def fakebin(tmp_path):
    directory = tmp_path / "fakebin"
    directory.mkdir()
    for name, text in (("ldd", FAKE_LDD), ("readelf", FAKE_READELF)):
        (directory / name).write_text(text)
        (directory / name).chmod(0o755)
    return directory


VALIDATOR_FLAGS = "fpu sse2 ssse3 sse4_1 sse4_2 sha_ni avx2"
# An arm64 CPU a validator may run on, as its /proc/cpuinfo Features line.
ARM64_FEATURES = "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics"
# The build record's line for the hardware SHA-256 backends of each release build.
SLHDSA = {
    "x86_64": "TOS_SLHDSA_SHA_NI=ON TOS_SLHDSA_ARMV8_SHA2=OFF",
    "arm64": "TOS_SLHDSA_SHA_NI=OFF TOS_SLHDSA_ARMV8_SHA2=ON",
}
# What a validator needs of each architecture's /proc/cpuinfo.
VALIDATOR_CPU = {
    "x86_64": ("flags", VALIDATOR_FLAGS, ["sha_ni", "ssse3", "sse4_1", "sse4_2"]),
    "arm64": ("Features", ARM64_FEATURES, ["aes", "pmull", "sha1", "sha2"]),
}
BACKEND = {"x86_64": "TOS_SLHDSA_SHA_NI", "arm64": "TOS_SLHDSA_ARMV8_SHA2"}


def cpuinfo_text(flags, key="flags"):
    # x86-64 lists them as "flags", aarch64 as "Features".
    return f"processor\t: 0\nmodel name\t: test cpu\n{key}\t\t: {flags}\n\nprocessor\t: 1\n"


def validator_cpuinfo(tmp_path, arch, flags=None):
    """Point the fetch at a CPU of this architecture, by default one a validator may use."""
    key, good, _ = VALIDATOR_CPU[arch]
    (tmp_path / "cpuinfo").write_text(cpuinfo_text(good if flags is None else flags, key))


@pytest.fixture
def served(tmp_path, fakebin):
    root = tmp_path / "served"
    release = FakeRelease(root)
    handler = functools.partial(Quiet, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cpuinfo = tmp_path / "cpuinfo"
    cpuinfo.write_text(cpuinfo_text(VALIDATOR_FLAGS))
    release.env = {"PATH": f"{fakebin}:/usr/bin:/bin", "TOS_CPUINFO": str(cpuinfo)}
    try:
        yield release, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def fetch(base_url, out, *, tag=TAG, rev=PIN, role="validator", arch="x86_64", env=None):
    command = [sys.executable, "-I", str(FETCH), "--tag", tag, "--rev", rev, "--role", role]
    if arch is not None:
        command += ["--arch", arch]
    command += ["--out", str(out)]
    if base_url is not None:
        command += ["--base-url", base_url]
    return subprocess.run(command, capture_output=True, text=True, env=env)


def run(release, url, out, **kwargs):
    extra = kwargs.pop("env", {})
    return fetch(url, out, env={**release.env, **extra}, **kwargs)


def refused(result, text):
    assert result.returncode != 0, result.stdout
    assert "Traceback" not in result.stderr, result.stderr
    assert text in result.stderr, result.stderr


def edit_provenance(release, change):
    record = release.provenance()
    change(record)
    release.write_provenance(record)
    release.write_sums()


def node_record(record, arch="x86_64"):
    (entry,) = [e for e in record["artifacts"] if e["artifact_name"] == f"tos-node-{arch}-linux"]
    return entry


# ---------------------------------------------------------------- happy path


# Without a validator's CPU: these roles are not asked for one.
@pytest.mark.parametrize(("role", "binaries"), [("fullnode", NODE), ("dht", DHT), ("rpc", RPC)])
def test_a_verified_release_is_written_in_the_layout_check_release_accepts(
    served, tmp_path, role, binaries
):
    release, url = served
    out = tmp_path / f"release-{PIN}"
    result = run(release, url, out, role=role, arch="arm64")
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in out.iterdir()) == sorted([*binaries, "SHA256SUMS", "BUILD-INFO"])
    for name in binaries:
        assert (out / name).read_bytes() == release.binary(name, "arm64")
        assert (out / name).stat().st_mode & 0o777 == 0o755
    info = (out / "BUILD-INFO").read_text().splitlines()
    assert info[0] == f"tos_revision {PIN}"
    assert f"source github-release {TAG}" in info
    digest = sha256((release.dir / "release-provenance.json").read_bytes())
    assert f"provenance_sha256 {digest}" in info
    build = sha256((release.dir / "node-build-info-linux-arm64.txt").read_bytes())
    assert f"node_build_info_sha256 {build}" in info
    assert "node_build compiler Ubuntu clang version 21.1.0" in info
    assert "node_build jemalloc_package libjemalloc-dev 5.3.0-2build1" in info
    assert f"node_build slhdsa_sha256 {SLHDSA['arm64']}" in info
    assert any(
        line.startswith("node_build flags ") and "TOS_USE_JEMALLOC=ON" in line for line in info
    )
    assert "host_glibc 2.39" in info
    check = subprocess.run(
        ["bash", str(CHECK), str(out), PIN, *binaries], capture_output=True, text=True
    )
    assert check.returncode == 0, check.stderr


def test_a_release_without_the_services_is_refused_for_rpc_only(served, tmp_path):
    release, url = served
    release.services = False
    release.publish()
    out = tmp_path / "out"
    refused(run(release, url, out, role="rpc"), "has no asset tos-rpc-linux-x86_64")
    assert not out.exists()
    assert run(release, url, tmp_path / "fullnode", role="fullnode").returncode == 0


@pytest.mark.parametrize("name", SERVICES)
def test_a_service_binary_that_is_not_the_zips_copy_is_refused(served, tmp_path, name):
    release, url = served
    (release.dir / f"{name}-linux-x86_64").write_bytes(b"another build\n")
    release.write_sums()
    refused(
        run(release, url, tmp_path / "out", role="rpc"),
        f"{name}-linux-x86_64 is not the {name} in",
    )


@pytest.mark.parametrize("name", SERVICES)
def test_a_service_without_a_needed_line_is_refused(served, tmp_path, name):
    release, url = served
    release.needed_override[name] = None
    release.publish()
    refused(
        run(release, url, tmp_path / "out", role="rpc"),
        f"the node build record has needed lines, but none for {name}",
    )


def test_a_host_without_the_services_library_is_refused(served, tmp_path):
    release, url = served
    result = run(
        release, url, tmp_path / "out", role="rpc", env={"FAKE_MISSING": "libjemalloc.so.2"}
    )
    refused(result, "tos-wallet-index needs libjemalloc.so.2")
    assert "tos-rpc needs libjemalloc.so.2" in result.stderr


def test_the_base_url_comes_from_the_environment(served, tmp_path):
    release, url = served
    result = fetch(
        None, tmp_path / "out", role="dht", env={**release.env, "TOS_RELEASE_BASE_URL": url}
    )
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------- provenance


def test_a_release_of_another_commit_is_refused(served, tmp_path):
    release, url = served
    out = tmp_path / "out"
    refused(run(release, url, out, rev=OTHER), f"tag_commit '{PIN}', expected '{OTHER}'")
    assert not out.exists()


def test_a_provenance_record_of_another_tag_is_refused(served, tmp_path):
    release, url = served
    edit_provenance(release, lambda r: r.update(tag="v0.9.0"))
    refused(run(release, url, tmp_path / "out"), "records tag 'v0.9.0', expected 'v0.9.1'")


def test_a_provenance_record_of_another_repository_is_refused(served, tmp_path):
    release, url = served
    edit_provenance(release, lambda r: r.update(repository="someone/tos"))
    refused(run(release, url, tmp_path / "out"), "records repository 'someone/tos'")


def test_a_node_artifact_built_from_another_commit_is_refused(served, tmp_path):
    release, url = served
    edit_provenance(release, lambda r: node_record(r).update(head_sha=OTHER))
    refused(run(release, url, tmp_path / "out"), f"was built from '{OTHER}', not {PIN}")


def test_a_node_artifact_from_another_workflow_is_refused(served, tmp_path):
    release, url = served
    release.workflow = "build-tos-linux-x86-64-appimage.yml"
    release.publish()
    refused(
        run(release, url, tmp_path / "out"),
        f"came from workflow 'build-tos-linux-x86-64-appimage.yml', not {NODE_WORKFLOW}",
    )


def test_a_release_whose_provenance_has_no_node_artifact_is_refused(served, tmp_path):
    release, url = served
    edit_provenance(
        release,
        lambda r: r.update(
            artifacts=[e for e in r["artifacts"] if "node" not in e["artifact_name"]]
        ),
    )
    refused(run(release, url, tmp_path / "out"), "0 records of artifact tos-node-x86_64-linux")


def test_an_artifact_digest_mismatch_is_refused(served, tmp_path):
    release, url = served
    edit_provenance(release, lambda r: node_record(r).update(artifact_digest="sha256:" + "0" * 64))
    refused(
        run(release, url, tmp_path / "out"),
        "release-provenance.json records artifact tos-node-x86_64-linux",
    )


def test_the_appimage_zip_does_not_stand_in_for_the_node_zip(served, tmp_path):
    release, url = served

    # The node artifact's digest names the AppImage zip: the node zip no longer matches.
    def swap(record):
        (appimage,) = [e for e in record["artifacts"] if e["artifact_name"] == "tos-x86_64-linux"]
        node_record(record)["artifact_digest"] = appimage["artifact_digest"]

    edit_provenance(release, swap)
    refused(run(release, url, tmp_path / "out"), "tos-node-linux-x86_64.zip has sha256")


# ---------------------------------------------------------------- SHA256SUMS and the zip


def test_a_tampered_binary_is_refused(served, tmp_path):
    release, url = served
    with open(release.dir / "validator-engine-linux-x86_64", "ab") as handle:
        handle.write(b"x")
    out = tmp_path / "out"
    refused(run(release, url, out), "validator-engine-linux-x86_64 has sha256")
    assert not out.exists()


def test_a_binary_that_is_not_the_zips_copy_is_refused(served, tmp_path):
    release, url = served
    # Consistent with SHA256SUMS, but not the bytes of the recorded node artifact.
    (release.dir / "lite-client-linux-x86_64").write_bytes(b"another build\n")
    release.write_sums()
    refused(
        run(release, url, tmp_path / "out"), "lite-client-linux-x86_64 is not the lite-client in"
    )


def test_a_missing_asset_is_refused(served, tmp_path):
    release, url = served
    (release.dir / "validator-engine-linux-x86_64").unlink()
    release.write_sums()
    out = tmp_path / "out"
    refused(run(release, url, out), "has no asset validator-engine-linux-x86_64")
    assert not out.exists()


def test_a_release_without_the_node_zip_is_refused(served, tmp_path):
    release, url = served
    (release.dir / "tos-node-linux-x86_64.zip").unlink()
    release.write_sums()
    refused(run(release, url, tmp_path / "out"), "has no asset tos-node-linux-x86_64.zip")


def test_a_release_without_provenance_is_refused(served, tmp_path):
    release, url = served
    (release.dir / "release-provenance.json").unlink()
    refused(run(release, url, tmp_path / "out"), "has no asset release-provenance.json")


def test_a_file_not_in_sha256sums_is_refused(served, tmp_path):
    release, url = served
    sums = release.dir / "SHA256SUMS"
    lines = sums.read_text().splitlines(keepends=True)
    sums.write_text("".join(x for x in lines if not x.endswith("  dht-server-linux-x86_64\n")))
    refused(
        run(release, url, tmp_path / "out", role="dht"),
        "dht-server-linux-x86_64 is not listed in the release's SHA256SUMS",
    )


def test_provenance_not_matching_sha256sums_is_refused(served, tmp_path):
    release, url = served
    record = release.provenance()
    record["note"] = "edited after SHA256SUMS"
    release.write_provenance(record)
    refused(run(release, url, tmp_path / "out"), "release-provenance.json has sha256")


def test_a_malformed_sha256sums_is_refused(served, tmp_path):
    release, url = served
    with open(release.dir / "SHA256SUMS", "a") as handle:
        handle.write("not a digest line\n")
    refused(run(release, url, tmp_path / "out"), "SHA256SUMS line")


# ---------------------------------------------------------------- the node build record


def test_a_release_without_the_node_build_record_is_refused(served, tmp_path):
    release, url = served
    (release.dir / "node-build-info-linux-x86_64.txt").unlink()
    release.write_sums()
    refused(run(release, url, tmp_path / "out"), "has no asset node-build-info-linux-x86_64.txt")


def test_a_node_zip_without_build_info_is_refused(served, tmp_path):
    release, url = served
    release.build_info_member = False
    release.publish()
    refused(
        run(release, url, tmp_path / "out"),
        "tos-node-linux-x86_64.zip has 0 members named BUILD-INFO",
    )


def test_a_build_record_that_is_not_the_zips_copy_is_refused(served, tmp_path):
    release, url = served
    path = release.dir / "node-build-info-linux-x86_64.txt"
    path.write_bytes(path.read_bytes() + b"extra line\n")
    release.write_sums()
    refused(
        run(release, url, tmp_path / "out"),
        "node-build-info-linux-x86_64.txt is not the BUILD-INFO in tos-node-linux-x86_64.zip",
    )


def test_a_build_record_of_another_commit_is_refused(served, tmp_path):
    release, url = served
    release.build_commit = OTHER
    release.publish()
    refused(
        run(release, url, tmp_path / "out"),
        f"the node build record names tos_revision '{OTHER}', not {PIN}",
    )


def test_a_build_record_with_another_binary_digest_is_refused(served, tmp_path):
    release, url = served
    original = release.build_info

    def build_info(arch):
        good = sha256(release.binary("lite-client", arch))
        return original(arch).replace(f"sha256 {good}".encode(), b"sha256 " + b"1" * 64)

    release.build_info = build_info
    release.publish()
    refused(run(release, url, tmp_path / "out"), "the node build record lists lite-client as")


# ---------------------------------------------------------------- can this host run them


def test_a_host_without_libjemalloc_is_refused_naming_the_package(served, tmp_path):
    release, url = served
    out = tmp_path / "out"
    result = run(release, url, out, env={"FAKE_MISSING": "libjemalloc.so.2"})
    refused(result, "this host lacks libraries the binaries need: validator-engine needs")
    assert "install the packages libjemalloc2" in result.stderr
    assert not out.exists()


def test_a_dht_host_without_libjemalloc_is_refused(served, tmp_path):
    release, url = served
    result = run(
        release, url, tmp_path / "out", role="dht", env={"FAKE_MISSING": "libjemalloc.so.2"}
    )
    refused(result, "dht-server needs libjemalloc.so.2; install the packages libjemalloc2")


@pytest.mark.parametrize(
    ("soname", "package", "arch", "needers"),
    [
        ("libgsl.so.27", "libgsl27", "x86_64", ["validator-engine"]),
        ("libblas.so.3", "libblas3", "x86_64", ["validator-engine"]),
        (
            "libreadline.so.8",
            "libreadline8t64",
            "x86_64",
            ["validator-engine-console", "lite-client"],
        ),
        ("libatomic.so.1", "libatomic1", "arm64", NODE),
    ],
)
def test_each_missing_release_library_is_refused_naming_its_package(
    served, tmp_path, soname, package, arch, needers
):
    release, url = served
    validator_cpuinfo(tmp_path, arch)
    result = run(release, url, tmp_path / "out", arch=arch, env={"FAKE_MISSING": soname})
    refused(result, f"; install the packages {package}")
    for name in needers:
        assert f"{name} needs {soname}" in result.stderr
    for name in set(NODE) - set(needers):
        assert f"{name} needs" not in result.stderr


def test_every_missing_package_is_named_at_once(served, tmp_path):
    release, url = served
    missing = "libjemalloc.so.2 libgsl.so.27 libblas.so.3 libreadline.so.8"
    result = run(release, url, tmp_path / "out", env={"FAKE_MISSING": missing})
    refused(
        result,
        "validator-engine needs libblas.so.3, libgsl.so.27, libjemalloc.so.2; "
        "validator-engine-console needs libreadline.so.8; lite-client needs libreadline.so.8; "
        "install the packages libblas3 libgsl27 libjemalloc2 libreadline8t64",
    )


def test_an_unknown_missing_library_is_refused_without_a_package_hint(served, tmp_path):
    release, url = served
    release.linked_override["validator-engine"] = sorted(
        linked("validator-engine", "x86_64") + ["libunknown.so.4"]
    )
    release.publish()
    result = run(release, url, tmp_path / "out", env={"FAKE_MISSING": "libunknown.so.4"})
    refused(
        result, "validator-engine needs libunknown.so.4; no known package provides libunknown.so.4"
    )
    assert "install the packages" not in result.stderr


def test_a_needed_line_that_differs_from_the_binary_is_refused(served, tmp_path):
    release, url = served
    release.needed_override["validator-engine"] = [
        lib for lib in linked("validator-engine", "x86_64") if lib != "libgsl.so.27"
    ]
    release.publish()
    refused(
        run(release, url, tmp_path / "out"),
        "validator-engine links libblas.so.3 libc.so.6 libgcc_s.so.1 libgsl.so.27",
    )


def test_a_binary_linking_more_than_its_needed_line_is_refused(served, tmp_path):
    release, url = served
    # The build record still says what the build linked; the binary links more.
    release.linked_override["lite-client"] = sorted(linked("lite-client", "x86_64") + ["libz.so.1"])
    release.needed_override["lite-client"] = linked("lite-client", "x86_64")
    release.publish()
    refused(run(release, url, tmp_path / "out"), "but the node build record says")


def test_a_record_with_needed_lines_must_cover_every_binary(served, tmp_path):
    release, url = served
    release.needed_override["lite-client"] = None
    release.publish()
    refused(
        run(release, url, tmp_path / "out"),
        "the node build record has needed lines, but none for lite-client",
    )


def test_a_record_without_needed_lines_relies_on_the_loader_check(served, tmp_path):
    release, url = served
    release.needed_override = dict.fromkeys(release.shipped())
    release.publish()
    assert run(release, url, tmp_path / "out").returncode == 0
    result = run(release, url, tmp_path / "out2", env={"FAKE_MISSING": "libgsl.so.27"})
    refused(result, "validator-engine needs libgsl.so.27; install the packages libgsl27")


def test_a_binary_the_loader_cannot_load_is_refused(served, tmp_path):
    release, url = served
    result = run(release, url, tmp_path / "out", env={"FAKE_NOT_DYNAMIC": "1"})
    refused(result, "this host's loader cannot load")


@pytest.mark.parametrize("glibc", ["2.35", "2.38", "1.99"])
def test_an_older_glibc_is_refused(served, tmp_path, glibc):
    release, url = served
    result = run(release, url, tmp_path / "out", env={"FAKE_GLIBC": glibc})
    refused(result, f"this host's glibc is {glibc}; the release binaries need glibc 2.39")


def test_a_newer_glibc_is_accepted(served, tmp_path):
    release, url = served
    result = run(release, url, tmp_path / "out", env={"FAKE_GLIBC": "2.41"})
    assert result.returncode == 0, result.stderr


def test_a_binary_reporting_another_commit_is_refused(served, tmp_path):
    release, url = served
    release.binary_commit = OTHER
    release.publish()
    out = tmp_path / "out"
    refused(run(release, url, out), f"-V does not report Commit: {PIN}")
    assert not out.exists()


# ---------------------------------------------------------------- validator host


@pytest.mark.parametrize("arch", ARCHES)
def test_a_validator_is_fetched_on_each_architecture_with_its_hardware_sha256(
    served, tmp_path, arch
):
    release, url = served
    validator_cpuinfo(tmp_path, arch)
    out = tmp_path / "out"
    result = run(release, url, out, arch=arch)
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in out.iterdir()) == sorted([*NODE, "SHA256SUMS", "BUILD-INFO"])
    for name in NODE:
        assert (out / name).read_bytes() == release.binary(name, arch)
    info = (out / "BUILD-INFO").read_text().splitlines()
    assert f"arch {arch}" in info
    assert f"node_build slhdsa_sha256 {SLHDSA[arch]}" in info
    # Right after the flags line, as the build record has it.
    assert info[info.index(f"node_build slhdsa_sha256 {SLHDSA[arch]}") - 1].startswith(
        "node_build flags "
    )
    check = subprocess.run(["bash", str(CHECK), str(out), PIN, *NODE], capture_output=True)
    assert check.returncode == 0, check.stderr


@pytest.mark.parametrize(
    ("arch", "flag"), [(arch, flag) for arch in ARCHES for flag in VALIDATOR_CPU[arch][2]]
)
def test_a_validator_host_without_a_required_cpu_flag_is_refused(served, tmp_path, arch, flag):
    release, url = served
    key, good, needed = VALIDATOR_CPU[arch]
    validator_cpuinfo(tmp_path, arch, " ".join(f for f in good.split() if f != flag))
    out = tmp_path / "out"
    label = {"x86_64": "x86-64", "arm64": "arm64"}[arch]
    refused(
        run(release, url, out, arch=arch),
        f"this host's CPU does not show {flag} in the {key} line of {tmp_path / 'cpuinfo'}; "
        f"a validator on {label} needs {' '.join(needed)}, on the host",
    )
    assert not out.exists()


@pytest.mark.parametrize("arch", ARCHES)
def test_a_validator_host_is_read_from_its_own_architectures_cpuinfo_line(served, tmp_path, arch):
    # A file that lists the right names under the other architecture's key
    # says nothing about this one: every flag is reported missing.
    release, url = served
    (other,) = [a for a in ARCHES if a != arch]
    key, good, needed = VALIDATOR_CPU[arch]
    (tmp_path / "cpuinfo").write_text(cpuinfo_text(good, VALIDATOR_CPU[other][0]))
    out = tmp_path / "out"
    refused(
        run(release, url, out, arch=arch),
        f"this host's CPU does not show {' '.join(needed)} in the {key} line of",
    )
    assert not out.exists()


def test_a_validator_host_is_read_from_the_first_cpu_of_cpuinfo(served, tmp_path):
    # The first Features line decides, as the first flags line does on x86-64.
    release, url = served
    first = cpuinfo_text("fp asimd", "Features")
    (tmp_path / "cpuinfo").write_text(first + cpuinfo_text(ARM64_FEATURES, "Features"))
    refused(
        run(release, url, tmp_path / "out", arch="arm64"),
        "this host's CPU does not show aes pmull sha1 sha2 in the Features line",
    )


@pytest.mark.parametrize("role", ["fullnode", "rpc", "dht", "tosctl"])
def test_the_other_roles_are_not_asked_for_a_validators_cpu_or_backend(served, tmp_path, role):
    # Neither the CPU nor the build's backend line concerns them: they are
    # fetched from a release without the line, on a CPU without the features.
    release, url = served
    release.slhdsa = dict.fromkeys(ARCHES)
    release.publish()
    (tmp_path / "cpuinfo").write_text(cpuinfo_text("fpu sse2"))
    for arch in ARCHES:
        out = tmp_path / f"out-{arch}"
        result = run(release, url, out, role=role, arch=arch)
        assert result.returncode == 0, result.stderr
        assert "slhdsa_sha256" not in (out / "BUILD-INFO").read_text()
    (tmp_path / "cpuinfo").unlink()
    assert run(release, url, tmp_path / "unread", role=role).returncode == 0


@pytest.mark.parametrize("arch", ARCHES)
def test_a_validator_host_whose_cpu_flags_cannot_be_read_is_refused(served, tmp_path, arch):
    release, url = served
    (tmp_path / "cpuinfo").unlink()
    refused(run(release, url, tmp_path / "out", arch=arch), "cannot read this host's CPU flags")


def test_an_architecture_without_a_hardware_backend_is_refused_for_a_validator():
    module = load_module()
    with pytest.raises(module.Refused, match="exists for x86-64 and arm64, not for riscv64"):
        module.check_validator_host("riscv64")
    assert set(module.VALIDATOR_HOSTS) == set(module.ARCHES)


# ---------------------------------------------------------------- the build's SHA-256 backend


def test_an_x86_64_release_without_the_backend_line_serves_a_validator(served, tmp_path):
    # A release published before the record carried the line: its x86-64
    # build had the backend by default.
    release, url = served
    release.slhdsa["x86_64"] = None
    release.publish()
    assert b"slhdsa_sha256" not in (release.dir / "node-build-info-linux-x86_64.txt").read_bytes()
    out = tmp_path / "out"
    result = run(release, url, out)
    assert result.returncode == 0, result.stderr
    assert "slhdsa_sha256" not in (out / "BUILD-INFO").read_text()


def test_an_arm64_release_without_the_backend_line_is_refused_for_a_validator(served, tmp_path):
    release, url = served
    release.slhdsa["arm64"] = None
    release.publish()
    validator_cpuinfo(tmp_path, "arm64")
    out = tmp_path / "out"
    refused(
        run(release, url, out, arch="arm64"),
        "this release was built without the arm64 hardware SHA-256 backend: its node build "
        "record has no slhdsa_sha256 line; a validator needs a release whose build record "
        "has that line with TOS_SLHDSA_ARMV8_SHA2=ON",
    )
    assert not out.exists()
    # The full node of the same release is not concerned.
    assert run(release, url, tmp_path / "fullnode", role="fullnode", arch="arm64").returncode == 0


@pytest.mark.parametrize("arch", ARCHES)
@pytest.mark.parametrize("other", ["ON", "OFF"])
def test_a_release_built_without_the_architectures_backend_is_refused_for_a_validator(
    served, tmp_path, arch, other
):
    # Only this architecture's switch counts, whatever the other one says.
    release, url = served
    (other_arch,) = [a for a in ARCHES if a != arch]
    line = {BACKEND[arch]: "OFF", BACKEND[other_arch]: other}
    release.slhdsa[arch] = " ".join(f"{switch}={line[switch]}" for switch in BACKEND.values())
    release.publish()
    validator_cpuinfo(tmp_path, arch)
    out = tmp_path / "out"
    label = {"x86_64": "x86-64", "arm64": "arm64"}[arch]
    refused(
        run(release, url, out, arch=arch),
        f"this release was built without the {label} hardware SHA-256 backend: its node "
        f"build record says {BACKEND[arch]}=OFF; a validator needs {BACKEND[arch]}=ON",
    )
    assert not out.exists()
    result = run(release, url, tmp_path / "fullnode", role="fullnode", arch=arch)
    assert result.returncode == 0, result.stderr
    assert (
        f"node_build slhdsa_sha256 {release.slhdsa[arch]}"
        in (tmp_path / "fullnode" / "BUILD-INFO").read_text().splitlines()
    )


def test_a_build_with_both_backends_serves_a_validator(served, tmp_path):
    release, url = served
    release.slhdsa["arm64"] = "TOS_SLHDSA_ARMV8_SHA2=ON TOS_SLHDSA_SHA_NI=ON"
    release.publish()
    validator_cpuinfo(tmp_path, "arm64")
    result = run(release, url, tmp_path / "out", arch="arm64")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "line",
    [
        "",
        "TOS_SLHDSA_SHA_NI=ON",
        "TOS_SLHDSA_ARMV8_SHA2=OFF",
        "TOS_SLHDSA_SHA_NI=ON TOS_SLHDSA_ARMV8_SHA2=OFF TOS_SLHDSA_AVX2=ON",
        "TOS_SLHDSA_SHA_NI=ON TOS_SLHDSA_AVX2=ON",
        "TOS_SLHDSA_SHA_NI=ON TOS_SLHDSA_ARMV8_SHA2",
        "TOS_SLHDSA_SHA_NI=ON TOS_SLHDSA_ARMV8_SHA2=",
        "TOS_SLHDSA_SHA_NI=ON TOS_SLHDSA_ARMV8_SHA2=1",
        "TOS_SLHDSA_SHA_NI=on TOS_SLHDSA_ARMV8_SHA2=OFF",
        "TOS_SLHDSA_SHA_NI=ON TOS_SLHDSA_SHA_NI=ON",
        "TOS_SLHDSA_SHA_NI=ON TOS_SLHDSA_SHA_NI=OFF TOS_SLHDSA_ARMV8_SHA2=OFF",
        "TOS_SLHDSA_SHA_NI=ON portable TOS_SLHDSA_ARMV8_SHA2=OFF",
    ],
)
@pytest.mark.parametrize("role", ["validator", "fullnode", "dht", "tosctl"])
def test_a_malformed_backend_line_is_refused_for_every_role(served, tmp_path, line, role):
    release, url = served
    release.slhdsa["x86_64"] = line
    release.publish()
    out = tmp_path / "out"
    refused(
        run(release, url, out, role=role),
        f"the node build record's slhdsa_sha256 line is {line!r}, expected exactly "
        "TOS_SLHDSA_SHA_NI=<ON|OFF> TOS_SLHDSA_ARMV8_SHA2=<ON|OFF>",
    )
    assert not out.exists()


@pytest.mark.parametrize("role", ["validator", "fullnode"])
def test_a_build_record_with_two_backend_lines_is_refused(served, tmp_path, role):
    # The first would say ON and the second OFF: neither is taken.
    release, url = served
    release.slhdsa["x86_64"] = (
        f"{SLHDSA['x86_64']}\nslhdsa_sha256 TOS_SLHDSA_SHA_NI=OFF TOS_SLHDSA_ARMV8_SHA2=OFF"
    )
    release.publish()
    refused(
        run(release, url, tmp_path / "out", role=role),
        "the node build record has two slhdsa_sha256 lines",
    )


def test_the_validator_table_names_each_architectures_backend():
    module = load_module()
    for arch, (key, _, needed) in VALIDATOR_CPU.items():
        host = module.VALIDATOR_HOSTS[arch]
        assert (host.cpuinfo_key, list(host.cpu_flags), host.backend) == (
            key,
            needed,
            BACKEND[arch],
        )
    assert not module.VALIDATOR_HOSTS["x86_64"].line_required
    assert module.VALIDATOR_HOSTS["arm64"].line_required
    for role in NODE_ROLES:
        assert "slhdsa_sha256" in module.ROLE_RECIPE_KEYS[role]
    assert "slhdsa_sha256" not in module.ROLE_RECIPE_KEYS["tosctl"]


# ---------------------------------------------------------------- arguments and output


def test_an_existing_out_is_refused_and_left_alone(served, tmp_path):
    release, url = served
    out = tmp_path / "out"
    out.mkdir()
    (out / "keep").write_text("operator data\n")
    refused(run(release, url, out), "already exists")
    assert [p.name for p in out.iterdir()] == ["keep"]


def test_a_role_this_tool_does_not_know_is_refused(served, tmp_path):
    release, url = served
    refused(run(release, url, tmp_path / "out", role="observer"), "invalid choice: 'observer'")


def test_an_arch_this_tool_does_not_know_is_refused(served, tmp_path):
    release, url = served
    refused(run(release, url, tmp_path / "out", arch="riscv64"), "invalid choice: 'riscv64'")


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
    release, url = served
    refused(run(release, url, tmp_path / "out", tag=tag, rev=rev), text)


def test_plain_http_is_refused_off_loopback(tmp_path):
    refused(fetch("http://releases.example.invalid", tmp_path / "out"), "must be https://")


def load_module():
    spec = importlib.util.spec_from_file_location("fetch_release", FETCH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------- the tosctl role


@pytest.mark.parametrize("arch", ARCHES)
def test_the_tosctl_role_writes_tosctl_alone_in_the_layout_check_release_accepts(
    served, tmp_path, arch
):
    release, url = served
    # Neither the architecture nor the CPU flags of a validator are asked of it.
    (tmp_path / "cpuinfo").write_text(cpuinfo_text("fpu sse2"))
    out = tmp_path / f"tosctl-{PIN}"
    result = run(release, url, out, role="tosctl", arch=arch)
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in out.iterdir()) == ["BUILD-INFO", "SHA256SUMS", "tosctl"]
    assert (out / "tosctl").read_bytes() == release.binary(TOSCTL, arch)
    assert (out / "tosctl").stat().st_mode & 0o777 == 0o755
    digest = sha256(release.binary(TOSCTL, arch))
    assert (out / "SHA256SUMS").read_text() == f"{digest}  tosctl\n"
    info = (out / "BUILD-INFO").read_text().splitlines()
    assert info[0] == f"tos_revision {PIN}"
    assert f"source github-release {TAG}" in info
    assert "repository tosnetwork/tos" in info
    provenance = sha256((release.dir / "release-provenance.json").read_bytes())
    assert f"provenance_sha256 {provenance}" in info
    record = node_record(release.provenance(), arch)
    assert (
        f"artifact tos-node-{arch}-linux run {record['run_id']} {record['artifact_digest']}" in info
    )
    for line in RUST_LINES:
        assert f"node_build {line}" in info
    assert "node_build compiler Ubuntu clang version 21.1.0" in info
    assert not any(line.startswith("node_build jemalloc") for line in info)
    check = subprocess.run(["bash", str(CHECK), str(out), PIN, "tosctl"], capture_output=True)
    assert check.returncode == 0, check.stderr
    assert f"install: install-tosctl.sh --release {out} --rev {PIN}" in result.stdout
    assert "install-node.sh" not in result.stdout


def test_a_release_without_tosctl_is_refused_as_a_missing_asset(served, tmp_path):
    release, url = served
    release.tosctl = False
    release.publish()
    out = tmp_path / "out"
    result = run(release, url, out, role="tosctl")
    refused(result, f"release {TAG} has no asset tosctl-linux-x86_64")
    assert "this release does not ship the binaries this role needs" in result.stderr
    assert not out.exists()


@pytest.mark.parametrize(("role", "binaries"), sorted(NODE_ROLES.items()))
def test_the_node_roles_do_not_need_tosctl_in_the_release(served, tmp_path, role, binaries):
    release, url = served
    release.tosctl = False
    release.publish()
    assert not (release.dir / "tosctl-linux-x86_64").exists()
    assert b"tosctl" not in (release.dir / "node-build-info-linux-x86_64.txt").read_bytes()
    out = tmp_path / "out"
    result = run(release, url, out, role=role)
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in out.iterdir()) == sorted([*binaries, "SHA256SUMS", "BUILD-INFO"])
    assert f"install: install-node.sh binaries --role {role} --release {out}" in result.stdout


@pytest.mark.parametrize(("role", "binaries"), sorted(NODE_ROLES.items()))
def test_the_node_roles_leave_tosctl_out_of_a_release_that_has_it(served, tmp_path, role, binaries):
    release, url = served
    out = tmp_path / "out"
    assert run(release, url, out, role=role).returncode == 0
    assert sorted(p.name for p in out.iterdir()) == sorted([*binaries, "SHA256SUMS", "BUILD-INFO"])
    info = (out / "BUILD-INFO").read_text()
    assert "rust_flags" not in info and "node_build rustc" not in info
    # tosctl missing from the host does not stop a node role either.
    result = run(release, url, tmp_path / "again", role=role, env={"FAKE_MISSING": "libssl.so.3"})
    assert result.returncode == 0, result.stderr


def test_a_tampered_tosctl_is_refused(served, tmp_path):
    release, url = served
    with open(release.dir / "tosctl-linux-x86_64", "ab") as handle:
        handle.write(b"x")
    out = tmp_path / "out"
    refused(run(release, url, out, role="tosctl"), "tosctl-linux-x86_64 has sha256")
    assert not out.exists()


def test_a_tosctl_that_is_not_the_zips_copy_is_refused(served, tmp_path):
    release, url = served
    (release.dir / "tosctl-linux-x86_64").write_bytes(b"another build\n")
    release.write_sums()
    out = tmp_path / "out"
    refused(
        run(release, url, out, role="tosctl"),
        "tosctl-linux-x86_64 is not the tosctl in tos-node-linux-x86_64.zip",
    )
    assert not out.exists()


@pytest.mark.parametrize(
    "line",
    [
        f"COMMIT_ID: {OTHER}",
        # The line must be exactly the commit, not a line that contains it.
        f"COMMIT_ID: {PIN}-dirty",
        f"PARENT_COMMIT_ID: {PIN}",
        f"Commit: {PIN}",
    ],
)
def test_a_tosctl_that_does_not_report_the_commit_is_refused(served, tmp_path, line):
    release, url = served
    release.tosctl_commit_line = line
    release.publish()
    out = tmp_path / "out"
    refused(
        run(release, url, out, role="tosctl"),
        f"tosctl --version does not report COMMIT_ID: {PIN}",
    )
    assert not out.exists()


def test_tosctl_without_a_needed_line_is_refused(served, tmp_path):
    release, url = served
    release.needed_override[TOSCTL] = None
    release.publish()
    refused(
        run(release, url, tmp_path / "out", role="tosctl"),
        "the node build record has needed lines, but none for tosctl",
    )


def test_a_tosctl_linking_more_than_its_needed_line_is_refused(served, tmp_path):
    release, url = served
    release.linked_override[TOSCTL] = sorted([*linked(TOSCTL, "x86_64"), "libz.so.1"])
    release.needed_override[TOSCTL] = linked(TOSCTL, "x86_64")
    release.publish()
    refused(
        run(release, url, tmp_path / "out", role="tosctl"),
        "tosctl links ld-linux-x86-64.so.2 libc.so.6 libcrypto.so.3 libgcc_s.so.1 libm.so.6 "
        "libssl.so.3 libz.so.1, but the node build record says",
    )


@pytest.mark.parametrize("missing", ["libssl.so.3", "libcrypto.so.3", "libcrypto.so.3 libssl.so.3"])
def test_a_host_without_tosctls_tls_library_is_refused_naming_the_package(
    served, tmp_path, missing
):
    release, url = served
    out = tmp_path / "out"
    result = run(release, url, out, role="tosctl", env={"FAKE_MISSING": missing})
    refused(
        result,
        "this host lacks libraries the binaries need: "
        f"tosctl needs {', '.join(missing.split())}; install the packages libssl3t64\n",
    )
    assert not out.exists()


@pytest.mark.parametrize("key", ["rustc", "cargo", "rust_flags"])
def test_a_build_record_without_tosctls_recipe_is_refused(served, tmp_path, key):
    release, url = served
    release.rust_lines = [x for x in RUST_LINES if x.split()[0] != key]
    release.publish()
    out = tmp_path / "out"
    refused(
        run(release, url, out, role="tosctl"),
        f"the node build record has no {key} line; it does not record how tosctl was built",
    )
    assert not out.exists()
    # The node binaries' recipe does not depend on it.
    assert run(release, url, tmp_path / "dht", role="dht").returncode == 0


def test_tosctl_is_asked_for_its_commit_its_own_way():
    module = load_module()
    assert module.ROLE_BINARIES["tosctl"] == ["tosctl"]
    for role in NODE_ROLES:
        assert "tosctl" not in module.ROLE_BINARIES[role]
        assert module.ROLE_BINARIES[role] == NODE_ROLES[role]
    report = module.VERSIONED["tosctl"]
    assert (report.option, report.expected(PIN), report.whole_line) == (
        "--version",
        f"COMMIT_ID: {PIN}",
        True,
    )
    for name in set(module.VERSIONED) - {"tosctl"}:
        node = module.VERSIONED[name]
        assert (node.option, node.expected(PIN), node.whole_line) == ("-V", f"Commit: {PIN}", False)
    assert module.LIBRARY_PACKAGES["libssl.so.3"] == "libssl3t64"
    assert module.LIBRARY_PACKAGES["libcrypto.so.3"] == "libssl3t64"


def test_a_host_without_readelf_is_refused_naming_binutils(served, tmp_path, monkeypatch):
    release, url = served
    monkeypatch.setenv("PATH", release.env["PATH"])
    module = load_module()
    which = module.shutil.which
    monkeypatch.setattr(
        module.shutil, "which", lambda name: None if name == "readelf" else which(name)
    )
    out = tmp_path / "out"
    with pytest.raises(module.Refused, match=r"readelf is not installed \(package binutils\)"):
        module.fetch(tag=TAG, rev=PIN, role="dht", arch="x86_64", out=out, base_url=url)
    assert not out.exists()


def test_a_result_check_release_refuses_is_not_moved_into_place(served, tmp_path, monkeypatch):
    release, url = served
    monkeypatch.setenv("PATH", release.env["PATH"])
    module = load_module()
    refuse = tmp_path / "refuse.sh"
    refuse.write_text("echo 'check-release: refused for the test' >&2; exit 1\n")
    module.CHECK_RELEASE = refuse
    out = tmp_path / "out"
    with pytest.raises(module.Refused, match="check-release.sh refused the result"):
        module.fetch(tag=TAG, rev=PIN, role="dht", arch="x86_64", out=out, base_url=url)
    assert not out.exists()


def test_the_host_build_links_gsl_statically_when_the_source_supports_it():
    build = (SCRIPTS / "build-node-binaries.sh").read_text()
    # The option is passed only when the source defines it, and the build
    # record says so, so the flags line never claims a static link it lacks.
    assert "if grep -q 'TOS_STATIC_GSL' \"$SRC/CMakeLists.txt\"; then" in build
    assert "STATIC_GSL=(-DTOS_STATIC_GSL=ON)" in build
    assert 'STATIC_GSL_FLAG=" TOS_STATIC_GSL=ON"' in build
    assert 'cmake -S "$SRC" -B "$BUILD" -G Ninja "${STATIC_GSL[@]}"' in build
    assert 'TOS_USE_JEMALLOC=ON Release$STATIC_GSL_FLAG"' in build


def test_the_role_binaries_are_the_ones_the_host_build_builds():
    module = load_module()
    build = (SCRIPTS / "build-node-binaries.sh").read_text()
    assert f"validator|fullnode) TARGETS=({' '.join(module.ROLE_BINARIES['validator'])})" in build
    assert f"dht) TARGETS=({' '.join(module.ROLE_BINARIES['dht'])})" in build
    assert f"rpc) TARGETS=({' '.join(module.ROLE_BINARIES['rpc'])})" in build
    assert module.ROLE_BINARIES["fullnode"] == module.ROLE_BINARIES["validator"]
    assert set(JEMALLOC) <= set(module.VERSIONED)
    assert "tos-pq-consensus-key" not in module.VERSIONED
    assert not set(SERVICES) & set(module.VERSIONED)
    assert os.path.basename(str(module.CHECK_RELEASE)) == "check-release.sh"
