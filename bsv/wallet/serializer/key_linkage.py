from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_reveal_counterparty_key_linkage_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    # privileged, privilegedReason
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
    # counterparty, verifier (33 bytes each)
    w.write_bytes(args.get("counterparty", b""))
    w.write_bytes(args.get("verifier", b""))
    # seekPermission
    seek = args.get("seekPermission")
    if seek is None:
        w.write_negative_one_byte()
    else:
        w.write_byte(1 if seek else 0)
    return w.to_bytes()


def deserialize_reveal_counterparty_key_linkage_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    b = r.read_byte()
    priv = None if b == 0xFF else (b == 1)
    reason = r.read_string()
    counterparty = r.read_bytes(33)
    verifier = r.read_bytes(33)
    b2 = r.read_byte()
    seek = None if b2 == 0xFF else (b2 == 1)
    return {"privileged": priv, "privilegedReason": reason, "counterparty": counterparty, "verifier": verifier, "seekPermission": seek}


def serialize_reveal_specific_key_linkage_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    _serialize_protocol_id(w, args.get("protocolID", {}))
    w.write_string(args.get("keyID", ""))
    _serialize_counterparty_type(w, args.get("counterparty", {}))
    _serialize_privileged_info(w, args.get("privileged"), args.get("privilegedReason", ""))
    w.write_bytes(args.get("verifier", b""))
    _serialize_seek(w, args.get("seekPermission"))
    return w.to_bytes()

def _serialize_protocol_id(w: Writer, proto: Dict[str, Any]):
    """Serialize protocol ID."""
    w.write_byte(int(proto.get("securityLevel", 0)))
    w.write_string(proto.get("protocol", ""))

def _serialize_counterparty_type(w: Writer, cp: Dict[str, Any]):
    """Serialize counterparty type."""
    cp_type = cp.get("type", 0)
    if cp_type in (0, 1, 2, 11, 12):
        w.write_byte(cp_type)
    else:
        w.write_bytes(cp.get("counterparty", b""))

def _serialize_privileged_info(w: Writer, priv, reason: str):
    """Serialize privileged and reason."""
    if priv is None:
        w.write_negative_one_byte()
    else:
        w.write_byte(1 if priv else 0)
    if reason:
        w.write_string(reason)
    else:
        w.write_negative_one()

def _serialize_seek(w: Writer, seek):
    """Serialize seek permission."""
    if seek is None:
        w.write_negative_one_byte()
    else:
        w.write_byte(1 if seek else 0)


def deserialize_reveal_specific_key_linkage_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    protocol_id = _deserialize_protocol_id(r)
    key_id = r.read_string()
    counterparty = _deserialize_counterparty_type(r)
    priv, reason = _deserialize_privileged_info(r)
    verifier = r.read_bytes(33)
    seek = _deserialize_seek(r)
    return {
        "protocolID": protocol_id,
        "keyID": key_id,
        "counterparty": counterparty,
        "privileged": priv,
        "privilegedReason": reason,
        "verifier": verifier,
        "seekPermission": seek,
    }

def _deserialize_protocol_id(r: Reader) -> Dict[str, Any]:
    """Deserialize protocol ID."""
    sec = r.read_byte()
    proto = r.read_string()
    return {"securityLevel": int(sec), "protocol": proto}

def _deserialize_counterparty_type(r: Reader) -> Dict[str, Any]:
    """Deserialize counterparty type."""
    first = r.read_byte()
    if first in (0, 1, 2, 11, 12):
        return {"type": int(first)}
    rest = r.read_bytes(32)
    return {"type": 13, "counterparty": bytes([first]) + rest}

def _deserialize_privileged_info(r: Reader) -> tuple:
    """Deserialize privileged and reason."""
    b = r.read_byte()
    priv = None if b == 0xFF else (b == 1)
    reason = r.read_string()
    return priv, reason

def _deserialize_seek(r: Reader):
    """Deserialize seek permission."""
    b = r.read_byte()
    return None if b == 0xFF else (b == 1)


def serialize_key_linkage_result(_: Dict[str, Any] = None) -> bytes:
    # Minimal: no payload; use frame status for success/error
    return b""


def deserialize_key_linkage_result(_: bytes) -> Dict[str, Any]:
    return {}
