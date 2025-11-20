from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_get_public_key_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    identity = bool(args.get("identityKey", False))
    w.write_byte(1 if identity else 0)
    if not identity:
        _serialize_protocol_and_key_info(w, args)
    _serialize_seek_permission(w, args.get("seekPermission"))
    return w.to_bytes()

def _serialize_protocol_and_key_info(w: Writer, args: Dict[str, Any]):
    """Serialize protocol ID, key ID, and related fields."""
    proto = args.get("protocolID", {})
    w.write_byte(int(proto.get("securityLevel", 0)))
    w.write_string(proto.get("protocol", ""))
    w.write_string(args.get("keyID", ""))
    _serialize_counterparty(w, args.get("counterparty", {}))
    _serialize_optional_bool(w, args.get("privileged"))
    _serialize_optional_string(w, args.get("privilegedReason", ""))
    _serialize_optional_bool(w, args.get("forSelf"))

def _serialize_counterparty(w: Writer, cp: Dict[str, Any]):
    """Serialize counterparty information."""
    cp_type = cp.get("type", 0)
    if cp_type in (0, 1, 2, 11, 12):
        w.write_byte(cp_type)
    else:
        w.write_bytes(cp.get("counterparty", b""))

def _serialize_optional_bool(w: Writer, value):
    """Serialize optional boolean."""
    if value is None:
        w.write_negative_one_byte()
    else:
        w.write_byte(1 if value else 0)

def _serialize_optional_string(w: Writer, value: str):
    """Serialize optional string."""
    if value:
        w.write_string(value)
    else:
        w.write_negative_one()

def _serialize_seek_permission(w: Writer, seek):
    """Serialize seek permission."""
    _serialize_optional_bool(w, seek)


def deserialize_get_public_key_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    out = {"identityKey": r.read_byte() == 1}
    if not out["identityKey"]:
        out.update(_deserialize_protocol_and_key_info(r))
    out["seekPermission"] = _deserialize_optional_bool(r)
    return out

def _deserialize_protocol_and_key_info(r: Reader) -> Dict[str, Any]:
    """Deserialize protocol ID, key ID, and related fields."""
    sec = r.read_byte()
    proto = r.read_string()
    key_id = r.read_string()
    return {
        "protocolID": {"securityLevel": int(sec), "protocol": proto},
        "keyID": key_id,
        "counterparty": _deserialize_counterparty(r),
        "privileged": _deserialize_optional_bool(r),
        "privilegedReason": r.read_string(),
        "forSelf": _deserialize_optional_bool(r),
    }

def _deserialize_counterparty(r: Reader) -> Dict[str, Any]:
    """Deserialize counterparty information."""
    first = r.read_byte()
    if first in (0, 1, 2, 11, 12):
        return {"type": int(first)}
    rest = r.read_bytes(32)
    return {"type": 13, "counterparty": bytes([first]) + rest}

def _deserialize_optional_bool(r: Reader):
    """Deserialize optional boolean."""
    b = r.read_byte()
    return None if b == 0xFF else (b == 1)


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
