import base64
from typing import Any

from bsv.wallet.serializer.status import (
    read_txid_slice_with_status,
    txid_wire_bytes,
    write_txid_slice_with_status,
)
from bsv.wallet.substrates.serializer import Reader, Writer, decode_outpoint, encode_outpoint

_NEGATIVE_ONE = (1 << 64) - 1


def serialize_create_action_result(result: dict[str, Any]) -> bytes:
    """Serialize CreateActionResult in the Go SerializeCreateActionResult layout.

    [txid flag][txid 32][tx flag][varint len][tx][noSendChange as optional bytes]
    [sendWithResults][signableTransaction flag][varint len][tx][varint len][reference]
    """
    w = Writer()
    txid = result.get("txid")
    if txid:
        w.write_byte(1)
        w.write_bytes(txid_wire_bytes(txid))
    else:
        w.write_byte(0)

    tx = bytes(result.get("tx") or b"")
    if tx:
        w.write_byte(1)
        w.write_int_bytes(tx)
    else:
        w.write_byte(0)

    no_send_change = result.get("noSendChange")
    if no_send_change is None:
        w.write_negative_one()
    else:
        outpoints = Writer()
        outpoints.write_varint(len(no_send_change))
        for outpoint in no_send_change:
            outpoints.write_bytes(encode_outpoint(outpoint))
        w.write_int_bytes(outpoints.to_bytes())

    write_txid_slice_with_status(w, result.get("sendWithResults") or [])

    stx = result.get("signableTransaction")
    if stx is None:
        w.write_byte(0)
    else:
        reference = stx.get("reference", b"")
        if isinstance(reference, str):
            reference = base64.b64decode(reference)  # BRC-100 references are base64 strings
        w.write_byte(1)
        w.write_int_bytes(bytes(stx.get("tx") or b""))
        w.write_int_bytes(bytes(reference))
    return w.to_bytes()


def deserialize_create_action_result(data: bytes) -> dict[str, Any]:
    r = Reader(data)
    out: dict[str, Any] = {}
    if r.read_byte() == 1:
        out["txid"] = r.read_bytes(32)[::-1].hex()
    if r.read_byte() == 1:
        out["tx"] = r.read_bytes(r.read_varint())

    length = r.read_varint()
    if length != _NEGATIVE_ONE:
        outpoints = Reader(r.read_bytes(length))
        out["noSendChange"] = [decode_outpoint(outpoints) for _ in range(outpoints.read_varint())]

    send_with_results = read_txid_slice_with_status(r)
    if send_with_results:
        out["sendWithResults"] = send_with_results

    if r.read_byte() == 1:
        tx = r.read_bytes(r.read_varint())
        reference = r.read_bytes(r.read_varint())
        out["signableTransaction"] = {"tx": tx, "reference": reference}
    return out
