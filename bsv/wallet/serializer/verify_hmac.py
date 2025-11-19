from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer
from .common import (
    serialize_encryption_args,
    deserialize_encryption_args,
    serialize_seek_permission,
    deserialize_seek_permission,
)


def serialize_verify_hmac_args(args: Dict[str, Any]) -> bytes:
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
    # hmac and data as int-bytes
    w.write_int_bytes(args.get("hmac", b""))
    w.write_int_bytes(args.get("data", b""))
    # seek
    serialize_seek_permission(w, args.get("seekPermission"))
    return w.to_bytes()


def deserialize_verify_hmac_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    # Common encryption args
    out = deserialize_encryption_args(r)
    # hmac and data
    out["hmac"] = r.read_int_bytes() or b""
    out["data"] = r.read_int_bytes() or b""
    # seek
    out["seekPermission"] = deserialize_seek_permission(r)
    return out


def serialize_verify_hmac_result(result: Any) -> bytes:
    if isinstance(result, (bytes, bytearray)):
        return bytes(result)
    if isinstance(result, dict):
        if "valid" in result:
            return b"\x01" if bool(result.get("valid")) else b"\x00"
    if isinstance(result, bool):
        return b"\x01" if result else b"\x00"
    # default to non-empty to satisfy wire contract
    return b"\x00"
