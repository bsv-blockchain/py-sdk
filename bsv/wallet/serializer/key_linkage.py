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
    # ProtocolID
    proto = args.get("protocolID", {})
    w.write_byte(int(proto.get("securityLevel", 0)))
    w.write_string(proto.get("protocol", ""))
    # keyID
    w.write_string(args.get("keyID", ""))
    # counterparty type/bytes
    cp = args.get("counterparty", {})
    cp_type = cp.get("type", 0)
    if cp_type in (0, 1, 2, 11, 12):
        w.write_byte(cp_type)
    else:
        w.write_bytes(cp.get("counterparty", b""))
    # privileged/reason
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
    # verifier
    w.write_bytes(args.get("verifier", b""))
    # seekPermission
    seek = args.get("seekPermission")
    if seek is None:
        w.write_negative_one_byte()
    else:
        w.write_byte(1 if seek else 0)
    return w.to_bytes()


def deserialize_reveal_specific_key_linkage_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    sec = r.read_byte()
    proto = r.read_string()
    key_id = r.read_string()
    first = r.read_byte()
    if first in (0, 1, 2, 11, 12):
        cp = {"type": int(first)}
    else:
        rest = r.read_bytes(32)
        cp = {"type": 13, "counterparty": bytes([first]) + rest}
    b = r.read_byte()
    priv = None if b == 0xFF else (b == 1)
    reason = r.read_string()
    verifier = r.read_bytes(33)
    b2 = r.read_byte()
    seek = None if b2 == 0xFF else (b2 == 1)
    return {
        "protocolID": {"securityLevel": int(sec), "protocol": proto},
        "keyID": key_id,
        "counterparty": cp,
        "privileged": priv,
        "privilegedReason": reason,
        "verifier": verifier,
        "seekPermission": seek,
    }


def serialize_key_linkage_result(result: Dict[str, Any]) -> bytes:
    # Minimal: no payload; use frame status for success/error
    return b""


def deserialize_key_linkage_result(_: bytes) -> Dict[str, Any]:
    return {}
