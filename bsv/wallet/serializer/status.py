from typing import Dict, List

from bsv.wallet.substrates.serializer import Reader, Writer

# Go compatibility mapping for SendWithResult status codes
# actionResultStatusCodeUnproven = 1
# actionResultStatusCodeSending  = 2
# actionResultStatusCodeFailed   = 3
STATUS_TO_CODE: dict[str, int] = {
    "unproven": 1,
    "sending": 2,
    "failed": 3,
}

CODE_TO_STATUS: dict[int, str] = {v: k for k, v in STATUS_TO_CODE.items()}


def txid_wire_bytes(txid: str | bytes) -> bytes:
    """32 txid bytes as Go writes them: bytes pass through, a hex txid string is reversed."""
    raw = bytes.fromhex(txid)[::-1] if isinstance(txid, str) else bytes(txid)
    if len(raw) != 32:
        raise ValueError("txid must be 32 bytes")
    return raw


def write_txid_slice_with_status(writer: Writer, results: list[dict[str, bytes]]) -> None:
    """Write a slice of {txid, status} pairs.

    - txid: 32-byte little-endian hash as bytes (written as-is), or a hex txid string
    - status: one of {"unproven", "sending", "failed"}
    Layout: varint(len) then for each item: 32 bytes txid + 1 byte status code.
    """
    if not results:
        writer.write_varint(0)
        return

    writer.write_varint(len(results))
    for item in results:
        try:
            writer.write_bytes(txid_wire_bytes(item.get("txid", b"")))
        except (TypeError, ValueError):
            raise ValueError("sendWithResults.txid must be 32 bytes")

        status_str = item.get("status")
        code = STATUS_TO_CODE.get(status_str)
        if code is None:
            raise ValueError(f"invalid status {status_str}")
        writer.write_byte(code)


def read_txid_slice_with_status(reader: Reader) -> list[dict[str, bytes]]:
    """Read a slice of {txid, status} pairs written by write_txid_slice_with_status."""
    count = reader.read_varint()
    out: list[dict[str, bytes]] = []
    for _ in range(int(count)):
        txid = reader.read_bytes(32)
        code = reader.read_byte()
        status = CODE_TO_STATUS.get(code)
        if status is None:
            raise ValueError(f"invalid status code {code}")
        out.append({"txid": txid, "status": status})
    return out


__all__ = [
    "CODE_TO_STATUS",
    "STATUS_TO_CODE",
    "read_txid_slice_with_status",
    "txid_wire_bytes",
    "write_txid_slice_with_status",
]
