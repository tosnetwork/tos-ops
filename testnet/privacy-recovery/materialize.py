#!/usr/bin/env python3
"""Build an isolated PRI recovery candidate from the reviewed frozen source.

No network access, keys, signing or sends. Existing source/output is never edited.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--driver-source", type=Path, required=True)
p.add_argument("--tos-source", type=Path, required=True)
p.add_argument("--transport-source", type=Path, required=True)
p.add_argument("--recipient", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
p.add_argument("--rustfmt", default="rustfmt")
a = p.parse_args()
expected = {
    "Cargo.toml": "20a63413d9d063fcbd924c017b3dc644db7cb31c0f4ef18e7eed2709de86dbab",
    "Cargo.lock": "db879361856e347b02178fb8ef636184cb5a861fe8304ea6e62dd7fd6c84cb30",
    "pri-driver.py": "6b39f7462af832ed32c852445da76b9da9654461d41bb536457cbf9121fa5630",
    "src/lib.rs": "74bed3b6473a8878719a0e54546fce9709d1e770c4ff447abefbb036e0f046d9",
    "src/bin/pri-core.rs": "95c286949f2816a2195368f530b8b888b7f506cbd9d03e61bbf9e2193bc094dc",
    "src/bin/pri-sandbox.rs": "9c9e9953e6e629eebb08343c2f5f20514f9086242a875de88dcc1618abce79ae",
}
for name, digest in expected.items():
    if hashlib.sha256((a.driver_source / name).read_bytes()).hexdigest() != digest:
        p.error("reviewed driver source mismatch: " + name)
# Exact frozen dependency/contract subtrees, including all path dependencies.
source_digest = hashlib.sha256()
source_files = []
for prefix in ("tosctl", "tools", "crypto/smartcont"):
    directory = a.tos_source / prefix
    if not directory.is_dir() or directory.is_symlink():
        p.error("frozen source subtree missing: " + prefix)
    for path in directory.rglob("*"):
        if path.is_symlink():
            p.error("symlink in frozen source subtree")
        if path.is_file():
            source_files.append(path)
for path in sorted(source_files):
    relative = path.relative_to(a.tos_source).as_posix()
    source_digest.update(relative.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
if (
    len(source_files) != 3728
    or source_digest.hexdigest()
    != "d16dc8f86fefbe7923a0eee7b06bb12d1a11b701cf02b4de05d2ef7f4cd56751"
):
    p.error("frozen tos source content mismatch (expected c1cb3b8d dependency/contract trees)")
transport = a.transport_source.read_bytes()
if (
    hashlib.sha256(transport).hexdigest()
    != "ce95ee51e4e81919264334a1bf0a1811df01b615c3b41466ce9583cb0dfa40c5"
):
    p.error("reviewed transport source mismatch")
if a.output.exists():
    p.error("output already exists; use a new candidate directory")
# Check all inputs before creating any output. No private/run directories copied.
files = [
    "Cargo.toml",
    "Cargo.lock",
    "pri-driver.py",
    "src/lib.rs",
    "src/bin/pri-core.rs",
    "src/bin/pri-sandbox.rs",
]
inputs = {name: (a.driver_source / name).read_bytes() for name in files}
recipient = (a.recipient / "state-init.boc").read_bytes()
if (
    hashlib.sha256(recipient).hexdigest()
    != "62684fd4c83ba5ace8b3521ee5a2cdcf616e46467af029adda2bbe77ea1ce531"
):
    p.error("frozen recipient StateInit mismatch")
for name, digest in {
    "code.boc": "39aac5cf9b3fb277672b1665e53e0f767415c4fc57ad4ddd7afaedcb228f3474",
    "data.boc": "f0a62863db479a2c8b5a6fd1da6f2382d145ca7d77067fdadf6a79f4699d4643",
}.items():
    if hashlib.sha256((a.recipient / name).read_bytes()).hexdigest() != digest:
        p.error("frozen recipient code/data mismatch: " + name)
for name, data in inputs.items():
    dest = a.output / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
formatter = subprocess.check_output([a.rustfmt, "--version"], text=True).strip()
if formatter != "rustfmt 1.8.0-stable (e408947bfd 2026-03-25)":
    p.error("the frozen patch requires rustfmt 1.8.0-stable (e408947bfd 2026-03-25)")
for name in ("src/lib.rs", "src/bin/pri-core.rs", "src/bin/pri-sandbox.rs"):
    subprocess.run([a.rustfmt, "--edition", "2021", str(a.output / name)], check=True)
subprocess.run(
    [
        "patch",
        "--batch",
        "--forward",
        "-p1",
        "-i",
        str(Path(__file__).with_name("driver.patch").resolve()),
    ],
    cwd=a.output,
    check=True,
)
manifest = a.output / "Cargo.toml"
text = manifest.read_text()
for line in text.splitlines():
    if 'path = "' in line:
        old = line.split('path = "', 1)[1].split('"', 1)[0]
        new = str(a.tos_source.resolve()) + old.removeprefix("/datax/pri-e6-20261027/src")
        text = text.replace(json.dumps(old), json.dumps(new, ensure_ascii=False))
text = text.replace('name = "pri-core"', 'name = "pri-e6-core"').replace(
    'name = "pri-sandbox"', 'name = "pri-e6-sandbox"'
)
manifest.write_text(text)
# Sandbox artifact location is explicit and independent of the node source tree.
sandbox = a.output / "src/bin/pri-sandbox.rs"
text = sandbox.read_text().replace(
    '"FROZEN_RECIPIENT_PATH"', json.dumps(str(a.recipient.resolve()), ensure_ascii=False)
)
sandbox.write_text(text)

# Derive a hash-pinned sibling adapter; never alter the installed transport.
text = transport.decode().replace(
    'Path(os.environ.get("PRI_DRIVER", "/datax/pri-e6-20261027/driver/pri-driver.py"))',
    'Path(os.environ.get("PRI_DRIVER", str(Path(__file__).with_name("pri-driver.py"))))',
)
text = text.replace(
    "6b39f7462af832ed32c852445da76b9da9654461d41bb536457cbf9121fa5630",
    hashlib.sha256((a.output / "pri-driver.py").read_bytes()).hexdigest(),
)
(a.output / "pri-transport-e6-recovery.py").write_text(text)
shutil.copytree(Path(__file__).with_name("tests"), a.output / "tests")

print(json.dumps({"result": "MATERIALIZED-NO-SEND", "output": str(a.output)}))
