from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer
from .discovery_common import (
    serialize_discover_certificates_result,
    deserialize_discover_certificates_result,
)


def serialize_discover_by_attributes_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    attrs: Dict[str, str] = args.get("attributes", {})
    keys = sorted(attrs.keys())
    w.write_varint(len(keys))
    for k in keys:
        w.write_int_bytes(k.encode())
        w.write_int_bytes(attrs[k].encode())
    w.write_optional_uint32(args.get("limit"))
    w.write_optional_uint32(args.get("offset"))
    w.write_optional_bool(args.get("seekPermission"))
    return w.to_bytes()


def deserialize_discover_by_attributes_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    cnt = r.read_varint()
    attrs: Dict[str, str] = {}
    for _ in range(int(cnt)):
        k = (r.read_int_bytes() or b"").decode()
        v = (r.read_int_bytes() or b"").decode()
        attrs[k] = v
    return {
        "attributes": attrs,
        "limit": r.read_optional_uint32(),
        "offset": r.read_optional_uint32(),
        "seekPermission": r.read_optional_bool(),
    }


# Re-export common functions for backwards compatibility
__all__ = [
    "serialize_discover_by_attributes_args",
    "deserialize_discover_by_attributes_args",
    "serialize_discover_certificates_result",
    "deserialize_discover_certificates_result",
]
