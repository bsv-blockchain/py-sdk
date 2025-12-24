from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer
from .discovery_common import (
    serialize_discover_certificates_result,
    deserialize_discover_certificates_result,
)


def serialize_discover_by_identity_key_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    w.write_bytes(args.get("identityKey", b""))
    w.write_optional_uint32(args.get("limit"))
    w.write_optional_uint32(args.get("offset"))
    w.write_optional_bool(args.get("seekPermission"))
    return w.to_bytes()


def deserialize_discover_by_identity_key_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    return {
        "identityKey": r.read_bytes(33),
        "limit": r.read_optional_uint32(),
        "offset": r.read_optional_uint32(),
        "seekPermission": r.read_optional_bool(),
    }


# Re-export common functions for backwards compatibility
__all__ = [
    "serialize_discover_by_identity_key_args",
    "deserialize_discover_by_identity_key_args",
    "serialize_discover_certificates_result",
    "deserialize_discover_certificates_result",
]
