from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_get_public_key_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    # identityKey: bool
    identity = bool(args.get("identityKey", False))
    w.write_byte(1 if identity else 0)
    if not identity:
        # ProtocolID, keyID, counterparty, privileged, privilegedReason, forSelf
        proto = args.get("protocolID", {})
        w.write_byte(int(proto.get("securityLevel", 0)))
        w.write_string(proto.get("protocol", ""))
        w.write_string(args.get("keyID", ""))
        cp = args.get("counterparty", {})
        cp_type = cp.get("type", 0)
        if cp_type in (0, 1, 2, 11, 12):
            w.write_byte(cp_type)
        else:
            w.write_bytes(cp.get("counterparty", b""))
        priv = args.get("privileged")
        if priv is None:
            w.write_negative_one_byte()
        else:
            w.write_byte(1 if priv else 0)
        reason = args.get("privilegedReason", "")
        if reason:
            w.write_string(reason)
        else:
            w.write_negative_one()
        # forSelf
        fs = args.get("forSelf")
        if fs is None:
            w.write_negative_one_byte()
        else:
            w.write_byte(1 if fs else 0)
    # seekPermission
    seek = args.get("seekPermission")
    if seek is None:
        w.write_negative_one_byte()
    else:
        w.write_byte(1 if seek else 0)
    return w.to_bytes()


def deserialize_get_public_key_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    out: Dict[str, Any] = {}
    identity = r.read_byte() == 1
    out["identityKey"] = identity
    if not identity:
        sec = r.read_byte()
        proto = r.read_string()
        out["protocolID"] = {"securityLevel": int(sec), "protocol": proto}
        out["keyID"] = r.read_string()
        first = r.read_byte()
        if first in (0, 1, 2, 11, 12):
            out["counterparty"] = {"type": int(first)}
        else:
            rest = r.read_bytes(32)
            out["counterparty"] = {"type": 13, "counterparty": bytes([first]) + rest}
        b = r.read_byte()
        out["privileged"] = None if b == 0xFF else (b == 1)
        out["privilegedReason"] = r.read_string()
        b2 = r.read_byte()
        out["forSelf"] = None if b2 == 0xFF else (b2 == 1)
    b3 = r.read_byte()
    out["seekPermission"] = None if b3 == 0xFF else (b3 == 1)
    return out


def serialize_get_public_key_result(result: Dict[str, Any]) -> bytes:
    # Compressed public key 33 bytes
    w = Writer()
    pub = result.get("publicKey", b"")
    if isinstance(pub, str):
        try:
            pub = bytes.fromhex(pub)
        except Exception:
            pub = b""
    w.write_bytes(pub)
    return w.to_bytes()


def deserialize_get_public_key_result(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    # if empty, return empty
    if r.is_complete():
        return {"publicKey": b""}
    return {"publicKey": r.read_bytes(33)}
