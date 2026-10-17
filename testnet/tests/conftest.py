import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
DATA = Path(__file__).resolve().parent / "data"
sys.path.insert(0, str(SCRIPTS))


def serialize_boc(root) -> bytes:
    """A single-root bag of ordinary cells (testnet_lib.Cell), as a node's answer carries one."""
    import testnet_lib as lib

    order, seen = [], set()

    def visit(cell):
        if id(cell) in seen:
            return
        seen.add(id(cell))
        for ref in cell.refs:
            visit(ref)
        order.append(cell)

    visit(root)
    order.reverse()
    index = {id(cell): i for i, cell in enumerate(order)}
    ref_size = 1 if len(order) < 256 else 2
    body = bytearray()
    for cell in order:
        full, rem = divmod(cell.bits, 8)
        data = cell.data[:full]
        if rem:
            data += bytes([(cell.data[full] & (0xFF << (8 - rem)) & 0xFF) | (0x80 >> rem)])
        body += bytes([len(cell.refs), full * 2 + (1 if rem else 0)]) + data
        for ref in cell.refs:
            body += index[id(ref)].to_bytes(ref_size, "big")
    count = len(order).to_bytes(ref_size, "big")
    header = bytes([ref_size, 4]) + count + (1).to_bytes(ref_size, "big") + bytes(ref_size)
    return lib.BOC_MAGIC + header + len(body).to_bytes(4, "big") + bytes(ref_size) + bytes(body)


def one_key_list(key: int):
    """A Hashmap 32 True holding only `key` (hml_long label), like a ConfigParam 9 without 48."""
    import testnet_lib as lib

    bits = "10" + format(32, "06b") + format(key, "032b")
    data = int(bits, 2).to_bytes(5, "big")
    return lib.Cell(data, len(bits), [])
