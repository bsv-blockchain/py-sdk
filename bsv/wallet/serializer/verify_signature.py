from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_verify_signature_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    proto = args.get("protocolID", {})
    w.write_byte(int(proto.get("securityLevel", 0)))
    w.write_string(proto.get("protocol", ""))
    w.write_string(args.get("keyID", ""))
    # counterparty
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
    # forSelf
    for_self = args.get("forSelf")
    if for_self is not None:
        w.write_byte(1 if for_self else 0)
    else:
        w.write_negative_one_byte()
    # signature
    w.write_int_bytes(args.get("signature", b""))
    # data or hash
    data = args.get("data")
    hash_to_verify = args.get("hashToDirectlyVerify")
    if data is not None and len(data) > 0:
        w.write_byte(1)
        w.write_int_bytes(data)
    else:
        w.write_byte(2)
        w.write_bytes(hash_to_verify or b"")
    # seekPermission
    seek = args.get("seekPermission")
    if seek is not None:
        w.write_byte(1 if seek else 0)
    else:
        w.write_negative_one_byte()
    return w.to_bytes()


def deserialize_verify_signature_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    out: Dict[str, Any] = {"encryption_args": {}}
    sec = r.read_byte()
    proto = r.read_string()
    out["encryption_args"]["protocol_id"] = {"securityLevel": int(sec), "protocol": proto}
    out["encryption_args"]["key_id"] = r.read_string()
    # counterparty
    first = r.read_byte()
    if first in (0, 11, 12):
        out["encryption_args"]["counterparty"] = {"type": int(first)} if first != 0 else {"type": 0}
    else:
        rest = r.read_bytes(32)
        out["encryption_args"]["counterparty"] = bytes([first]) + rest
    # privileged / reason
    b = r.read_byte()
    out["encryption_args"]["privileged"] = None if b == 0xFF else (b == 1)
    out["encryption_args"]["privilegedReason"] = r.read_string()
    # forSelf
    b2 = r.read_byte()
    out["encryption_args"]["forSelf"] = None if b2 == 0xFF else (b2 == 1)
    # signature
    out["signature"] = r.read_int_bytes() or b""
    # data or hash
    which = r.read_byte()
    if which == 1:
        out["data"] = r.read_int_bytes() or b""
    else:
        out["hash_to_verify"] = r.read_bytes(32)
    # seek
    b3 = r.read_byte()
    out["seekPermission"] = None if b3 == 0xFF else (b3 == 1)
    return out


def serialize_verify_signature_result(result: Any) -> bytes:
    if isinstance(result, (bytes, bytearray)):
        return bytes(result)
    if isinstance(result, dict):
        if "valid" in result:
            return b"\x01" if bool(result.get("valid")) else b"\x00"
    if isinstance(result, bool):
        return b"\x01" if result else b"\x00"
    return b"\x00"
