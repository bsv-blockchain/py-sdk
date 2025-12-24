from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer
from .common import (
    serialize_encryption_args,
    deserialize_encryption_args,
    serialize_seek_permission,
    deserialize_seek_permission,
)


def serialize_create_signature_args(args: Dict[str, Any]) -> bytes:
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
    # data or hashToDirectlySign
    data = args.get("data")
    hash_to_sign = args.get("hashToDirectlySign")
    if data is not None:
        w.write_byte(1)
        w.write_varint(len(data))
        w.write_bytes(data)
    else:
        w.write_byte(2)
        w.write_bytes(hash_to_sign or b"")
    # seekPermission
    serialize_seek_permission(w, args.get("seekPermission"))
    return w.to_bytes()


def deserialize_create_signature_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    # Common encryption args
    out = deserialize_encryption_args(r)
    # data or hash
    which = r.read_byte()
    if which == 1:
        ln = r.read_varint()
        out["data"] = r.read_bytes(int(ln)) if ln > 0 else b""
    else:
        out["hash_to_sign"] = r.read_bytes(32)
    # seek
    out["seekPermission"] = deserialize_seek_permission(r)
    return out


def serialize_create_signature_result(result: Any) -> bytes:
    # result is raw signature bytes
    if isinstance(result, (bytes, bytearray)):
        return bytes(result)
    if isinstance(result, dict):
        sig = result.get("signature")
        if isinstance(sig, (bytes, bytearray)):
            return bytes(sig)
    return b""
