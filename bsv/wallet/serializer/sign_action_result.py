from typing import Any, Dict, List

from bsv.wallet.serializer.status import (
    CODE_TO_STATUS as _code_to_status,
)
from bsv.wallet.serializer.status import (
    STATUS_TO_CODE as _status_to_code,
)
from bsv.wallet.serializer.status import (
    read_txid_slice_with_status,
    write_txid_slice_with_status,
)
from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_sign_action_result(result: dict[str, Any]) -> bytes:
    w = Writer()
    # optional txid (with presence flag and fixed 32 bytes)
    txid: bytes = result.get("txid", b"")
    if txid:
        if len(txid) != 32:
            raise ValueError("txid must be 32 bytes")
        w.write_byte(1)
        w.write_bytes(txid)
    else:
        w.write_byte(0)
    # optional tx (with presence flag and length prefix)
    tx: bytes = result.get("tx", b"")
    if tx:
        w.write_byte(1)
        w.write_varint(len(tx))
        w.write_bytes(tx)
    else:
        w.write_byte(0)
    # sendWithResults: list of {txid: bytes32, status: str}
    results: list[dict[str, Any]] = result.get("sendWithResults", []) or []
    # delegate to shared helper for Go-compatible encoding
    write_txid_slice_with_status(w, results)  # type: ignore[arg-type]
    return w.to_bytes()


def deserialize_sign_action_result(data: bytes) -> dict[str, Any]:
    r = Reader(data)
    out: dict[str, Any] = {}
    # optional txid
    if r.read_byte() == 1:
        out["txid"] = r.read_bytes(32)
    # optional tx
    if r.read_byte() == 1:
        ln = r.read_varint()
        out["tx"] = r.read_bytes(int(ln)) if ln > 0 else b""
    # sendWithResults
    out["sendWithResults"] = read_txid_slice_with_status(r)
    return out
