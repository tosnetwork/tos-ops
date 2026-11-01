"""Exercise the real no-send materializer with frozen public source inputs."""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
for arg in ("driver-source", "transport-source", "tos-source", "recipient", "rustfmt"):
    parser.add_argument("--" + arg, required=True, type=Path)
a = parser.parse_args()
materializer = Path(__file__).resolve().parents[1] / "materialize.py"


def invoke(output, source=None, recipient=None):
    return subprocess.run(
        [
            sys.executable,
            str(materializer),
            "--driver-source",
            str(a.driver_source),
            "--transport-source",
            str(a.transport_source),
            "--tos-source",
            str(source or a.tos_source),
            "--recipient",
            str(recipient or a.recipient),
            "--rustfmt",
            str(a.rustfmt),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )


with tempfile.TemporaryDirectory() as directory:
    temp = Path(directory)
    # Copy public source only, with no run directory or secrets.
    source = temp / 'source"quoted'
    for prefix in ("tosctl", "tools", "crypto/smartcont"):
        shutil.copytree(a.tos_source / prefix, source / prefix, copy_function=shutil.copyfile)
    recipient = temp / 'recipient"quoted'
    recipient.mkdir()
    for name in ("code.boc", "data.boc", "state-init.boc"):
        shutil.copyfile(a.recipient / name, recipient / name)
    output = temp / "candidate"
    result = invoke(output, source, recipient)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.splitlines()[-1])["result"] == "MATERIALIZED-NO-SEND"
    cargo = tomllib.loads((output / "Cargo.toml").read_text())
    assert cargo["dependencies"]["shielded-pool-circuit"]["path"] == str(
        source / "tools/shielded-pool-circuit"
    )
    assert (
        json.dumps(str(recipient), ensure_ascii=False)
        in (output / "src/bin/pri-sandbox.rs").read_text()
    )
    assert (output / "pri-transport-e6-recovery.py").exists() and (output / "tests").is_dir()
    result = invoke(output, source, recipient)
    assert result.returncode != 0 and "output already exists" in result.stderr
    target = source / "tools/shielded-pool-wallet/src/import.rs"
    original = target.read_bytes()
    target.unlink()
    target.write_bytes(original + b"\n// mutation\n")
    refused = temp / "bad-source"
    result = invoke(refused, source, recipient)
    assert (
        result.returncode != 0
        and "source content mismatch" in result.stderr
        and not refused.exists()
    )
    target.write_bytes(original)
    target = recipient / "code.boc"
    original = target.read_bytes()
    target.write_bytes(original + b"\0")
    refused = temp / "bad-code"
    result = invoke(refused, source, recipient)
    assert result.returncode != 0 and "code/data mismatch" in result.stderr and not refused.exists()
print(
    "PASS actual materializer: frozen source/code mismatch refused before output; quoted paths preserved; existing output refused; success emitted after all artifacts exist"
)
