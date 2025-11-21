"""
BSV Utils Package

This package contains various utility functions for BSV blockchain operations.
"""

# Import commonly used utilities from submodules
from bsv.utils.base58_utils import from_base58, to_base58, from_base58_check, to_base58_check
from bsv.utils.binary import to_hex, from_hex, unsigned_to_varint, varint_to_unsigned, to_utf8, encode, to_base64
from bsv.utils.encoding import BytesList, BytesHex, Bytes32Base64, Bytes33Hex, StringBase64, Signature
from bsv.utils.pushdata import encode_pushdata, get_pushdata_code
from bsv.utils.script_chunks import read_script_chunks
from bsv.utils.reader import Reader
from bsv.utils.writer import Writer
from bsv.utils.misc import randbytes, bytes_to_bits, bits_to_bytes
from bsv.hash import hash256
from bsv.utils.address import decode_address, validate_address

# Import legacy functions in a clean, maintainable way
from bsv.utils.legacy import (
    decode_wif,
    text_digest,
    stringify_ecdsa_recoverable,
    unstringify_ecdsa_recoverable,
    deserialize_ecdsa_recoverable,
    serialize_ecdsa_der,
    address_to_public_key_hash,
    encode_int,
    unsigned_to_bytes,
    deserialize_ecdsa_der,
    to_bytes,
    reverse_hex_byte_order,
    serialize_ecdsa_recoverable,
)

__all__ = [
    # Base58 functions
    'from_base58', 'to_base58', 'from_base58_check', 'to_base58_check',
    # Binary functions
    'to_hex', 'from_hex', 'unsigned_to_varint', 'varint_to_unsigned',
    # Encoding classes
    'BytesList', 'BytesHex', 'Bytes32Base64', 'Bytes33Hex', 'StringBase64', 'Signature',
    # Pushdata functions
    'encode_pushdata', 'get_pushdata_code', 'read_script_chunks',
    # Reader/Writer classes
    'Reader', 'Writer',
    # Random bytes utility re-exported from bsv/utils.py
    'randbytes', 'bytes_to_bits', 'bits_to_bytes',
    # Hash helpers
    'hash256',
    # Address helpers
    'decode_address', 'validate_address',
    # Functions from main utils.py
    'decode_wif', 'text_digest', 'stringify_ecdsa_recoverable', 
    'unstringify_ecdsa_recoverable', 'deserialize_ecdsa_recoverable', 
    'serialize_ecdsa_der', 'address_to_public_key_hash', 'encode_int', 'unsigned_to_bytes', 'deserialize_ecdsa_der', 'to_bytes', 'reverse_hex_byte_order',
    'serialize_ecdsa_recoverable',
    # binary.py から追加
    'to_utf8', 'encode', 'to_base64',
]
