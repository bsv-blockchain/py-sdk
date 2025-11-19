from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer
from .common import (
    serialize_encryption_args,
    deserialize_encryption_args,
    serialize_seek_permission,
    deserialize_seek_permission,
)


def serialize_create_hmac_args(args: Dict[str, Any]) -> bytes:
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
    # data
    data = args.get("data", b"")
    w.write_varint(len(data))
    w.write_bytes(data)
    # seek
    serialize_seek_permission(w, args.get("seekPermission"))
    return w.to_bytes()


def deserialize_create_hmac_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    # Common encryption args
    out = deserialize_encryption_args(r)
    # data
    ln = r.read_varint()
    data_bytes = r.read_bytes(int(ln)) if ln > 0 else b""
    out["data"] = data_bytes
    # seek
    out["seekPermission"] = deserialize_seek_permission(r)
    return out


def serialize_create_hmac_result(result: Any) -> bytes:
    if isinstance(result, (bytes, bytearray)):
        return bytes(result)
    if isinstance(result, dict):
        h = result.get("hmac")
        if isinstance(h, (bytes, bytearray)):
            return bytes(h)
    return b""
