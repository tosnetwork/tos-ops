"""Masterchain addresses on the command line.

argparse reads a separate token that starts with "-" and is not a negative number
as an option, so `--pool -1:<hex>` fails with "expected one argument". Printed and
documented commands use `--pool=-1:<hex>`, and the scripts join a space-separated
-1: address to its option before parsing (testnet_lib.cli_argv). These tests run
the real parsers on the exact command strings.
"""

import argparse
import importlib.util
import re
import shlex

import pytest
import testnet_lib as lib
from conftest import SCRIPTS

POOL = "-1:" + "5c" * 32
OWNER = "-1:" + "0e" * 32
OPERATOR = "-1:" + "6b" * 32
DOCS = SCRIPTS.parent


def load(name, module):
    spec = importlib.util.spec_from_file_location(module, SCRIPTS / name)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


operator_tool = load("testnet-operator.py", "testnet_operator_argv")
elections = load("testnet-elections.py", "testnet_elections_argv")


class Parsed(Exception):
    """Raised right after parsing, carrying the namespace."""


def parse(module, argv, monkeypatch):
    """The namespace the script's own main() parses from `argv`, before it acts."""
    real = argparse.ArgumentParser.parse_args

    def capture(self, args=None, namespace=None):
        raise Parsed(real(self, args, namespace))

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", capture)
    with pytest.raises(Parsed) as info:
        module.main(argv)
    return info.value.args[0]


def script_argv(command: str, script: str) -> list[str]:
    """The arguments after `script` in a shell command line."""
    words = shlex.split(command.replace("\\\n", " "), comments=True)
    index = next(i for i, w in enumerate(words) if w.endswith(script))
    return words[index + 1 :]


# ---------------------------------------------------------------- the printed hand-off


def test_the_printed_operator_command_parses_on_the_host(monkeypatch):
    command = elections.operator_command("node-3", POOL, OWNER)
    assert f"--pool={POOL}" in command and f"--owner={OWNER}" in command
    args = parse(operator_tool, script_argv(command, "testnet-operator.py"), monkeypatch)
    assert (args.command, args.name, args.pool, args.owner) == ("onboard", "node-3", POOL, OWNER)


def test_the_printed_command_parses_without_the_join_too(monkeypatch):
    # The `=` form is what makes it work; the join is only a second line of defense.
    monkeypatch.setattr(operator_tool.lib, "cli_argv", lambda argv: list(argv))
    command = elections.operator_command("node-3", POOL, OWNER)
    args = parse(operator_tool, script_argv(command, "testnet-operator.py"), monkeypatch)
    assert (args.pool, args.owner) == (POOL, OWNER)


# Operator hosts run the system python3 (Ubuntu 24.04: 3.12), whose argparse
# refuses `--pool -1:<hex>`; some newer releases accept it. The host-side parse is
# checked with every system interpreter found here, not only the test runner's.
DRIVER = """
import argparse, importlib.util, json, sys
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location("op", sys.argv[1] + "/testnet-operator.py")
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)
if sys.argv[2] == "nojoin":
    op.lib.cli_argv = lambda argv: list(argv)
real = argparse.ArgumentParser.parse_args
def capture(self, args=None, namespace=None):
    ns = real(self, args, namespace)
    print(json.dumps({"pool": ns.pool, "owner": ns.owner}))
    raise SystemExit(0)
argparse.ArgumentParser.parse_args = capture
op.main(sys.argv[3:])
"""


def system_pythons():
    import shutil

    found = []
    for name in ("python3", "python3.10", "python3.11", "python3.12", "python3.13"):
        path = shutil.which(name, path="/usr/bin:/usr/local/bin")
        if path and path not in found:
            found.append(path)
    return found


def host_parse(python, argv, join=True):
    import json
    import subprocess

    run = subprocess.run(
        [python, "-I", "-c", DRIVER, str(SCRIPTS), "join" if join else "nojoin", *argv],
        capture_output=True,
        text=True,
    )
    try:
        return json.loads(run.stdout)
    except ValueError:
        return run.stdout + run.stderr


@pytest.mark.parametrize("python", system_pythons() or [None])
def test_the_printed_command_parses_with_the_system_python(python):
    if python is None:
        pytest.skip("no system python3")
    command = elections.operator_command("node-3", POOL, OWNER)
    argv = script_argv(command, "testnet-operator.py")
    first = host_parse(python, argv)
    if isinstance(first, str) and "Traceback" in first:
        pytest.skip(f"{python} cannot import the scripts: {first[-200:]}")
    assert first == {"pool": POOL, "owner": OWNER}
    assert host_parse(python, argv, join=False) == {"pool": POOL, "owner": OWNER}
    spaced = ["onboard", "--name", "node-3", "--pool", POOL, "--owner", OWNER]
    # The space form: joined, it parses; without the join an older argparse
    # refuses it, the defect the rehearsal found.
    assert host_parse(python, spaced) == {"pool": POOL, "owner": OWNER}
    probe = host_parse(python, spaced, join=False)
    import subprocess

    version = subprocess.run(
        [python, "-c", "import sys; print(sys.version_info[1])"], capture_output=True, text=True
    ).stdout.strip()
    if int(version) <= 12:
        # Ubuntu 24.04's 3.12 and older: the defect, reproduced.
        assert isinstance(probe, str) and "expected one argument" in probe


def test_the_space_separated_form_is_accepted(monkeypatch):
    args = parse(
        operator_tool,
        ["onboard", "--name", "node-3", "--pool", POOL, "--owner", OWNER],
        monkeypatch,
    )
    assert (args.pool, args.owner) == (POOL, OWNER)


# ---------------------------------------------------------------- the join itself


@pytest.mark.parametrize(
    "argv, joined",
    [
        (["--pool", POOL], [f"--pool={POOL}"]),
        (["--pool=" + POOL], ["--pool=" + POOL]),
        (["--to", "0:" + "ab" * 32], ["--to", "0:" + "ab" * 32]),  # parses already
        (
            ["--dry-run", "--to", POOL, "--amount", "5"],
            ["--dry-run", f"--to={POOL}", "--amount", "5"],
        ),
        (["-x", POOL], ["-x", POOL]),  # short options are left alone
        (["--to", "-1:abc"], ["--to", "-1:abc"]),  # not an address
        (["--pool"], ["--pool"]),
    ],
)
def test_the_join_touches_only_option_address_pairs(argv, joined):
    assert lib.join_address_values(argv) == joined


# ---------------------------------------------------------------- every documented form


def documented(path: str, script: str, subcommand: str) -> list[str]:
    """Every fenced command in a document that runs `script subcommand`."""
    text = (DOCS / path).read_text()
    found = []
    for block in re.findall(r"```bash\n(.*?)```", text, re.S):
        # CEREMONY.md runs testnet-elections.py as "$S".
        joined = re.sub(r"\\\n\s*", " ", block).replace('"$S"', "testnet-elections.py")
        for line in joined.splitlines():
            if f"{script} {subcommand} " in line:
                found.append(line)
    return found


def fill(command: str) -> str:
    """Placeholders and shell variables replaced with real values."""
    values = {
        "<POOL_ADDRESS>": POOL,
        "<POOL_OWNER_ADDRESS>": OWNER,
        "<VALIDATOR_ID>": POOL,
        "<ADDRESS>": OPERATOR,
        "<RECORDED_OPERATOR_WALLET>": OPERATOR,
        "$VALIDATOR_ID": POOL,
        "$NEW": OPERATOR,
        "ADDR": OPERATOR,
        "$OPERATOR_LABEL": "op-label",
        "$PUBLIC_IPV4": "44.0.0.1",
        '"${C[@]}"': "--ceremony c --tos-root t --fift f --rpc r",
        "$TOS_ROOT": "/t",
    }
    for key in sorted(values, key=len, reverse=True):
        command = command.replace(key, values[key])
    return re.sub(r"<([A-Za-z_-]+)>", r"x\1", command)


@pytest.mark.parametrize(
    "path",
    ["OPERATOR.md", "CEREMONY.md", "ANNOUNCEMENT-20261205.md"],
)
def test_documented_record_and_onboard_commands_parse(path, monkeypatch):
    lines = documented(path, "testnet-operator.py", "record") + documented(
        path, "testnet-operator.py", "onboard"
    )
    assert lines, f"{path} documents no record or onboard command"
    for line in lines:
        assert "--validator-id=" in line or "--pool=" in line, line
        args = parse(operator_tool, script_argv(fill(line), "testnet-operator.py"), monkeypatch)
        if args.command == "record":
            assert args.validator_id == POOL
        else:
            assert (args.pool, args.owner) == (POOL, OWNER)
        # Typed with a space instead, it still parses the same.
        spaced = (
            fill(line)
            .replace("--validator-id=", "--validator-id ")
            .replace("--pool=", "--pool ")
            .replace("--owner=", "--owner ")
        )
        again = parse(operator_tool, script_argv(spaced, "testnet-operator.py"), monkeypatch)
        assert vars(again) == vars(args)


@pytest.mark.parametrize(
    "subcommand, option, expected",
    [
        ("pool", "--operator=", OPERATOR),
        ("fund", "--to=", OPERATOR),
        ("change-validator", "--to=", OPERATOR),
        ("baseline", "--wallet=", OPERATOR),
    ],
)
def test_documented_coordinator_commands_parse(subcommand, option, expected, monkeypatch):
    lines = [
        line
        for line in documented("CEREMONY.md", "testnet-elections.py", subcommand)
        if option in line
    ]
    assert lines, f"CEREMONY.md documents no `{subcommand} {option}` command"
    for line in lines:
        argv = script_argv(fill(line), "testnet-elections.py")
        args = parse(elections, argv, monkeypatch)
        assert args.command == subcommand
        assert getattr(args, option.strip("-=").replace("-", "_")) == expected
