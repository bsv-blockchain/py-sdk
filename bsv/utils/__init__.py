"""
BSV Utils Package

This package contains various utility functions for BSV blockchain operations.
"""

# Import commonly used utilities from submodules
from bsv.hash import hash256
from bsv.utils.address import decode_address, validate_address
from bsv.utils.base58_utils import from_base58, from_base58_check, to_base58, to_base58_check
from bsv.utils.binary import encode, from_hex, to_base64, to_hex, to_utf8, unsigned_to_varint, varint_to_unsigned
from bsv.utils.encoding import Bytes32Base64, Bytes33Hex, BytesHex, BytesList, Signature, StringBase64

# Import legacy functions in a clean, maintainable way
from bsv.utils.legacy import (
    address_to_public_key_hash,
    decode_wif,
    deserialize_ecdsa_der,
    deserialize_ecdsa_recoverable,
    encode_int,
    reverse_hex_byte_order,
    serialize_ecdsa_der,
    serialize_ecdsa_recoverable,
    stringify_ecdsa_recoverable,
    text_digest,
    to_bytes,
    to_legacy_script,
    to_legacy_transaction,
    unsigned_to_bytes,
    unstringify_ecdsa_recoverable,
)
from bsv.utils.misc import bits_to_bytes, bytes_to_bits, ensure_bytes, ensure_string, pad_bytes, randbytes
from bsv.utils.pushdata import decode_pushdata, encode_pushdata, get_pushdata_code
from bsv.utils.reader import Reader
from bsv.utils.script_chunks import read_script_chunks, serialize_chunks
from bsv.utils.writer import Writer

__all__ = [
    "Bytes32Base64",
    "Bytes33Hex",
    "BytesHex",
    # Encoding classes
    "BytesList",
    # Reader/Writer classes
    "Reader",
    "Signature",
    "StringBase64",
    "Writer",
    "address_to_public_key_hash",
    "bits_to_bytes",
    "bytes_to_bits",
    # Address helpers
    "decode_address",
    # Functions from main utils.py
    "decode_wif",
    "deserialize_ecdsa_der",
    "deserialize_ecdsa_recoverable",
    "encode",
    "encode_int",
    # Pushdata functions
    "encode_pushdata",
    # Base58 functions
    "from_base58",
    "from_base58_check",
    "from_hex",
    "get_pushdata_code",
    # Hash helpers
    "hash256",
    # Random bytes utility re-exported from bsv/utils.py
    "randbytes",
    "read_script_chunks",
    "reverse_hex_byte_order",
    "serialize_ecdsa_der",
    "serialize_ecdsa_recoverable",
    "stringify_ecdsa_recoverable",
    "text_digest",
    "to_base58",
    "to_base58_check",
    "to_base64",
    "to_bytes",
    # Binary functions
    "to_hex",
    # binary.py から追加
    "to_utf8",
    "unsigned_to_bytes",
    "unsigned_to_varint",
    "unstringify_ecdsa_recoverable",
    "validate_address",
    "varint_to_unsigned",
]
