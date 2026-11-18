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
        # Overrides of what a binary links, and of what the build record says.
        self.linked_override: dict[str, list[str]] = {}
        self.needed_override: dict[str, list[str] | None] = {}
        self.publish()

    def links(self, name: str, arch: str) -> list[str]:
        return self.linked_override.get(name, linked(name, arch))

    def binary(self, name: str, arch: str) -> bytes:
        body = f"#!/bin/sh\n# {name} {arch}\n"
        body += "".join(f"# NEEDED {lib}\n" for lib in self.links(name, arch))
        if name not in UNVERSIONED:
            body += f'echo "{name} build"\necho "Commit: {self.binary_commit}"\n'
        return body.encode()

    def build_info(self, arch: str) -> bytes:
        lines = [
            f"tos_revision {self.build_commit}",
            "source_date_epoch 1761400000",
            f"architecture {'aarch64' if arch == 'arm64' else arch}",
            "compiler Ubuntu clang version 21.1.0",
            "flags CMAKE_BUILD_TYPE=Release TOS_ARCH=x86-64-v2 PORTABLE=x86-64-v2 TOS_USE_JEMALLOC=ON",
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
        return [n for n in ALL if self.services or n not in SERVICES]

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


def cpuinfo_text(flags):
    return f"processor\t: 0\nmodel name\t: test cpu\nflags\t\t: {flags}\n\nprocessor\t: 1\n"


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


# On arm64, which the validator role refuses: the full node installs the same binaries.
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
    # The same binaries under the role each architecture allows.
    role = "validator" if arch == "x86_64" else "fullnode"
    result = run(release, url, tmp_path / "out", role=role, arch=arch, env={"FAKE_MISSING": soname})
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
    release.needed_override = dict.fromkeys(ALL)
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


def test_the_validator_role_is_refused_on_arm64(served, tmp_path):
    release, url = served
    out = tmp_path / "out"
    refused(
        run(release, url, out, arch="arm64"),
        "a validator must run on x86-64 with SHA-NI, not arm64",
    )
    assert not out.exists()


@pytest.mark.parametrize("role", ["fullnode", "rpc", "dht"])
def test_the_other_roles_are_not_refused_for_arm64_or_cpu_flags(served, tmp_path, role):
    # They get past the validator-host check: the refusal, if any, is about
    # the release, never the architecture or the CPU.
    release, url = served
    (tmp_path / "cpuinfo").write_text(cpuinfo_text("fpu sse2"))
    for arch in ("arm64", "x86_64"):
        result = run(release, url, tmp_path / f"out-{arch}", role=role, arch=arch)
        assert "a validator must run" not in result.stderr, result.stderr
        assert "does not show" not in result.stderr, result.stderr


@pytest.mark.parametrize("flag", ["sha_ni", "ssse3", "sse4_1", "sse4_2"])
def test_a_validator_host_without_a_required_cpu_flag_is_refused(served, tmp_path, flag):
    release, url = served
    flags = " ".join(f for f in VALIDATOR_FLAGS.split() if f != flag)
    (tmp_path / "cpuinfo").write_text(cpuinfo_text(flags))
    out = tmp_path / "out"
    refused(run(release, url, out), f"this host's CPU does not show {flag} in")
    assert not out.exists()


def test_a_validator_host_whose_cpu_flags_cannot_be_read_is_refused(served, tmp_path):
    release, url = served
    (tmp_path / "cpuinfo").unlink()
    refused(run(release, url, tmp_path / "out"), "cannot read this host's CPU flags")


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


def test_the_role_binaries_are_the_ones_the_host_build_builds():
    module = load_module()
    build = (SCRIPTS / "build-node-binaries.sh").read_text()
    assert f"validator|fullnode) TARGETS=({' '.join(module.ROLE_BINARIES['validator'])})" in build
    assert f"dht) TARGETS=({' '.join(module.ROLE_BINARIES['dht'])})" in build
    assert f"rpc) TARGETS=({' '.join(module.ROLE_BINARIES['rpc'])})" in build
    assert module.ROLE_BINARIES["fullnode"] == module.ROLE_BINARIES["validator"]
    assert set(JEMALLOC) <= set(module.VERSIONED)
    assert "tos-pq-consensus-key" not in module.VERSIONED
    assert not set(SERVICES) & module.VERSIONED
    assert os.path.basename(str(module.CHECK_RELEASE)) == "check-release.sh"
