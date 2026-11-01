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
text = manifest.read_text().replace("/datax/pri-e6-20261027/src", str(a.tos_source.resolve()))
text = text.replace('name = "pri-core"', 'name = "pri-e6-core"').replace(
    'name = "pri-sandbox"', 'name = "pri-e6-sandbox"'
)
manifest.write_text(text)
# Sandbox artifact location is explicit and independent of the node source tree.
sandbox = a.output / "src/bin/pri-sandbox.rs"
text = sandbox.read_text().replace("FROZEN_RECIPIENT_PATH", str(a.recipient.resolve()))
sandbox.write_text(text)
print(json.dumps({"result": "MATERIALIZED-NO-SEND", "output": str(a.output)}))

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
