"""Public-testnet test paths and cell builders; never import another suite's conftest."""

from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
DATA = Path(__file__).resolve().parent / "data"


def serialize_boc(root) -> bytes:
    import testnet_lib as lib

    return lib.serialize_boc(root)


def one_key_list(key: int):
    """A Hashmap 32 True holding only `key` (hml_long label), like a ConfigParam 9 without 48."""
    import testnet_lib as lib

    bits = "10" + format(32, "06b") + format(key, "032b")
    data = int(bits, 2).to_bytes(5, "big")
    return lib.Cell(data, len(bits), [])
