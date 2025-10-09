# Thin re-exports from substrates serializer (to be replaced with local implementations)
from bsv.wallet.substrates.serializer import (
    _encode_key_related_params as encode_key_related_params,
    _decode_key_related_params as decode_key_related_params,
    encode_privileged_params,
    encode_outpoint,
)
from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer

# Re-export certificate base helpers from dedicated module
from .certificate import (
    serialize_certificate_base,
    deserialize_certificate_base,
)


def serialize_relinquish_certificate_result(_: Dict[str, Any]) -> bytes:
    return b""


def deserialize_relinquish_certificate_result(_: bytes) -> Dict[str, Any]:
    return {}


__all__ = [
    'encode_key_related_params',
    'decode_key_related_params',
    'encode_privileged_params',
    'encode_outpoint',
    'serialize_certificate_base',
    'deserialize_certificate_base',
]
