from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_create_hmac_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    proto = args.get("protocolID", {})
    w.write_byte(int(proto.get("securityLevel", 0)))
    w.write_string(proto.get("protocol", ""))
    w.write_string(args.get("keyID", ""))
    # counterparty: 0/11/12 or 33 bytes
    cp = args.get("counterparty", {})
    cp_type = cp.get("type", 0)
    if cp_type in (0, 11, 12):
        w.write_byte(cp_type)
    else:
        w.write_bytes(cp.get("counterparty", b""))
    # privileged / reason
    priv = args.get("privileged")
    if priv is not None:
        w.write_byte(1 if priv else 0)
    else:
        w.write_negative_one_byte()
    reason = args.get("privilegedReason", "")
    if reason:
        w.write_string(reason)
    else:
        w.write_negative_one()
    # data
    data = args.get("data", b"")
    w.write_varint(len(data))
    w.write_bytes(data)
    # seek
    seek = args.get("seekPermission")
    if seek is not None:
        w.write_byte(1 if seek else 0)
    else:
        w.write_negative_one_byte()
    return w.to_bytes()


def deserialize_create_hmac_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    out: Dict[str, Any] = {"encryption_args": {}}
    sec = r.read_byte()
    proto = r.read_string()
    out["encryption_args"]["protocol_id"] = {"securityLevel": int(sec), "protocol": proto}
    out["encryption_args"]["key_id"] = r.read_string()
    # counterparty
    first = r.read_byte()
    if first in (0, 11, 12):
        if first == 0:
            out["encryption_args"]["counterparty"] = {"type": 0}
        else:
            out["encryption_args"]["counterparty"] = {"type": int(first)}
    else:
        rest = r.read_bytes(32)
        out["encryption_args"]["counterparty"] = bytes([first]) + rest
    # privileged / reason
    b = r.read_byte()
    out["encryption_args"]["privileged"] = None if b == 0xFF else (b == 1)
    out["encryption_args"]["privilegedReason"] = r.read_string()
    # data
    ln = r.read_varint()
    data_bytes = r.read_bytes(int(ln)) if ln > 0 else b""
    out["data"] = data_bytes
    # seek
    b2 = r.read_byte()
    out["seekPermission"] = None if b2 == 0xFF else (b2 == 1)
    return out


def serialize_create_hmac_result(result: Any) -> bytes:
    if isinstance(result, (bytes, bytearray)):
        return bytes(result)
    if isinstance(result, dict):
        h = result.get("hmac")
        if isinstance(h, (bytes, bytearray)):
            return bytes(h)
    return b""
