from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer
from .common import (
    serialize_encryption_args,
    deserialize_encryption_args,
    serialize_seek_permission,
    deserialize_seek_permission,
)


def serialize_verify_signature_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    # Common encryption args
    serialize_encryption_args(
        w,
        args.get("protocolID", {}),
        args.get("keyID", ""),
        args.get("counterparty", {}),
        args.get("privileged"),
        args.get("privilegedReason", ""),
    )
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
    serialize_seek_permission(w, args.get("seekPermission"))
    return w.to_bytes()


def deserialize_verify_signature_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    # Common encryption args
    out = deserialize_encryption_args(r)
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
    out["seekPermission"] = deserialize_seek_permission(r)
    return out


def serialize_verify_signature_result(result: Any) -> bytes:
    if isinstance(result, (bytes, bytearray)):
        return bytes(result)
    if isinstance(result, dict) and "valid" in result:
        return b"\x01" if bool(result.get("valid")) else b"\x00"
    if isinstance(result, bool):
        return b"\x01" if result else b"\x00"
    return b"\x00"
