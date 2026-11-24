"""The host-side steps that make a validator host ready for elections.

One implementation, two callers:

- testnet-elections.py onboard --host runs them over SSH on a host the team
  operates;
- testnet-operator.py onboard runs them on the operator's own host, where only
  the operator logs in.

A `host` here is anything with run(command, timeout) -> stdout and
tosctl(arguments, timeout) -> output that raises lib.TestnetError on failure:
the SSH Host in testnet-elections.py, or LocalHost below. Nothing here moves
value or reads a key.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testnet_lib as lib  # noqa: E402

# The operator tool's state on a validator host, owned by its own non-login user.
TOSCTL_USER = "tos-ctl"
TOSCTL_DIR = "/var/lib/tos-ctl"
TOSCTL_ENV = "/etc/tos/tosctl.env"
SCRIPTS = "/opt/tos-testnet/scripts"

# What the node logs at start-up for each consensus key it holds (tos
# doc/validator-operator-guide.md, "Bind the node to the staking account").
CUSTODY_LINE = re.compile(r"post-quantum consensus custody: validator_id ([0-9a-f]{64}) ")
CUSTODY_COMMAND = (
    "{ journalctl -u tos-testnet-validator -o cat --no-pager 2>/dev/null; "
    "cat /var/log/tos/validator/node.log* 2>/dev/null; } "
    "| grep -a 'post-quantum consensus custody' | tail -n 1 || true"
)


def tosctl_command(arguments: str, timeout: int) -> str:
    """tosctl as its own user; root only reads the root-owned env file.

    runuser keeps the exported environment (the vault URL with its master key),
    so the key never appears on a command line, and every file tosctl writes
    under the state directory stays owned by that user.
    """
    return (
        f"set -a; . {TOSCTL_ENV}; set +a; cd {TOSCTL_DIR}; "
        f"timeout {timeout} runuser -u {TOSCTL_USER} -- tosctl {arguments} 2>&1"
    )


class LocalHost:
    """The host this process runs on, for the operator's own onboarding (as root)."""

    def __init__(self, run=subprocess.run):
        self._run = run

    def run(self, command: str, timeout: int = 300) -> str:
        try:
            result = self._run(
                ["bash", "-c", command], capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired as exc:
            raise lib.TestnetError(f"{command[:80]!r} did not finish within {timeout} s") from exc
        if result.returncode != 0:
            raise lib.TestnetError(
                f"{command[:80]!r} failed: {(result.stdout + result.stderr)[-800:]}"
            )
        return result.stdout

    def tosctl(self, arguments: str, timeout: int = 240) -> str:
        return self.run(tosctl_command(arguments, timeout), timeout=timeout + 30)


# ---------------------------------------------------------------- addresses


def raw_from_friendly(friendly: str) -> str:
    """A user-friendly address (36 bytes, base64 or base64url) as workchain:hex."""
    data = base64.urlsafe_b64decode(
        friendly.replace("+", "-").replace("/", "_") + "=" * (-len(friendly) % 4)
    )
    if len(data) != 36:
        raise lib.TestnetError(f"not a user-friendly address: {friendly!r}")
    workchain = int.from_bytes(data[1:2], "big", signed=True)
    return f"{workchain}:{data[2:34].hex()}"


def std_address(cell: lib.Cell) -> str:
    """A MsgAddressInt cell holding addr_std without anycast, as workchain:hex."""
    s = lib.Slice(cell)
    if s.bits(3) != 0b100:
        raise lib.TestnetError("not an addr_std without anycast")
    workchain = s.bits(8)
    workchain -= 256 if workchain > 127 else 0
    address = f"{workchain}:{s.bytes(32).hex()}"
    if not s.end():
        raise lib.TestnetError("trailing data after an address")
    return address


def decode_pool_roles(result: dict, address: str) -> tuple[str, str]:
    """A single-nominator pool's get_roles answer as (owner, validator).

    The node lists a getter's results top of stack first, so the stack reads
    validator, owner."""
    stack = result.get("stack") or []
    if result.get("exit_code") != 0 or len(stack) != 2:
        raise lib.TestnetError(f"get_roles of {address} failed: {result}")
    roles = []
    for entry in stack:
        if (
            not isinstance(entry, list)
            or len(entry) != 2
            or entry[0] != "slice"
            or not isinstance(entry[1], dict)
            or not isinstance(entry[1].get("bytes"), str)
        ):
            raise lib.TestnetError(f"get_roles of {address}: not an address slice: {entry}")
        roles.append(std_address(lib.parse_boc(base64.b64decode(entry[1]["bytes"]))))
    validator, owner = roles
    return owner, validator


# ---------------------------------------------------------------- host-side steps


def operator_wallet(init_output: str, name: str) -> str:
    """The operator wallet init-operator.sh printed on its last line, `op-NAME <address>`."""
    lines = init_output.strip().splitlines()
    words = lines[-1].split() if lines else []
    if len(words) != 2 or words[0] != f"op-{name}":
        raise lib.TestnetError(f"init-operator.sh printed no operator wallet: {init_output[-300:]}")
    return raw_from_friendly(words[1])


def node_staking_account(host) -> str:
    """The validator id the node on the host last reported holding its key for."""
    found = CUSTODY_LINE.search(host.run(CUSTODY_COMMAND))
    if not found:
        raise lib.TestnetError(
            "the node reports no post-quantum consensus custody line; check that it is bound "
            "(install-node.sh activate --validator-id) and running"
        )
    return found.group(1)


# A probe of the host's tosctl on a throwaway copy of its configuration: the
# same two commands enable-elections.sh runs, then the factor read back. The
# host's own configuration is not touched.
MAX_FACTOR_MARKER = "MAX-FACTOR-PROBE"


def max_factor_probe_command(factor: str, stake_tos: int) -> str:
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)?", factor) or not isinstance(stake_tos, int):
        raise lib.TestnetError(f"not a max factor and stake: {factor!r} {stake_tos!r}")
    as_ctl = f"runuser -u {TOSCTL_USER} --"
    read = (
        "import json,sys; c=json.load(open(sys.argv[1])); "
        "print(sys.argv[2], c['elections']['max_factor'])"
    )
    return (
        f"set -a; . {TOSCTL_ENV}; set +a; cd {TOSCTL_DIR}; "
        f"probe=$({as_ctl} mktemp -d) && trap 'rm -rf \"$probe\"' EXIT && "
        f'{as_ctl} cp "$CONFIG_PATH" "$probe/config.json" && '
        f'{as_ctl} tosctl config --config "$probe/config.json" elections stake-policy '
        f"--fixed {stake_tos} >/dev/null 2>&1 && "
        f'{as_ctl} tosctl config --config "$probe/config.json" elections max-factor {factor} '
        "2>&1 && "
        f'python3 -c "{read}" "$probe/config.json" {MAX_FACTOR_MARKER} 2>&1 '
        "|| echo PROBE-REFUSED"
    )


def check_tosctl_max_factor(host, factor: str, stake_tos: int) -> None:
    """Refuse a host whose tosctl does not accept `factor` (a team pool's), read back
    from a throwaway copy of its configuration. A tosctl that caps the factor at 3.0
    would stake a team pool with a smaller one and cut the team's weight silently."""
    output = host.run(max_factor_probe_command(factor, stake_tos), timeout=120)
    found = [line.split()[1:] for line in output.splitlines() if line.startswith(MAX_FACTOR_MARKER)]
    try:
        accepted = len(found) == 1 and abs(float(found[0][0]) - float(factor)) < 1e-6
    except (IndexError, ValueError):
        accepted = False
    if not accepted:
        raise lib.TestnetError(
            f"the host's tosctl does not accept max factor {factor} (a team pool's); install a "
            f"tosctl release that accepts 1.0..100.0 before onboarding: {output.strip()[-300:]}"
        )


def check_custody(host, pool: str) -> None:
    """The node must sign stake authorizations for the pool: the Elector refuses others."""
    bound = node_staking_account(host)
    if bound != pool.split(":")[1]:
        raise lib.TestnetError(
            f"the node signs stake authorizations for {bound}, not the pool {pool}; the Elector "
            "refuses a stake signed for another account"
        )


def configure_pool(host, name, pool, owner, step) -> None:
    """The host's tosctl configuration: each step decided by what is there, never nested."""

    def config() -> dict:
        return json.loads(host.run(f"cat {TOSCTL_DIR}/tosctl-config.json"))

    entry = config().get("pools", {}).get(f"pool-{name}")
    if entry is None:
        step(f"config pool add pool-{name}")
        host.tosctl(f"config pool add --name pool-{name} --address {pool} --owner {owner}")
    elif (entry.get("address"), entry.get("owner")) != (pool, owner):
        raise lib.TestnetError(f"pool-{name} is configured on the host as {entry}")
    binding = config().get("bindings", {}).get(name)
    if binding is None or not binding.get("pool"):
        step(f"config bind add {name}")
        host.tosctl(f"config bind add --node {name} --wallet op-{name} --pool pool-{name}")
        binding = config().get("bindings", {}).get(name) or {}
    if (binding.get("wallet"), binding.get("pool")) != (f"op-{name}", f"pool-{name}"):
        raise lib.TestnetError(f"node {name} is bound on the host as {binding}")
