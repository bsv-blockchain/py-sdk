"""
Legacy utility functions from the main utils.py module.
This module provides a clean interface to functions that were originally in utils.py.
"""

import math
import re
import struct
from base64 import b64encode, b64decode
from contextlib import suppress
from typing import Tuple, Optional, Union, Literal, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..transaction import Transaction

from ..base58 import base58check_decode
from ..constants import Network, ADDRESS_PREFIX_NETWORK_DICT, WIF_PREFIX_NETWORK_DICT, NUMBER_BYTE_LENGTH
from ..constants import OpCode
from ..curve import curve


def decode_wif(wif: str) -> Tuple[bytes, bool, Network]:
    """
    Decode WIF (Wallet Import Format) string to private key bytes.
    
    Args:
        wif: WIF string to decode
        
    Returns:
        Tuple of (private_key_bytes, compressed, network)
        
    Raises:
        ValueError: If WIF format is invalid
    """
    decoded = base58check_decode(wif)
    prefix = decoded[:1]
    network = WIF_PREFIX_NETWORK_DICT.get(prefix)
    if not network:
        raise ValueError(f'unknown WIF prefix {prefix.hex()}')
    if len(wif) == 52 and decoded[-1] == 1:
        return decoded[1:-1], True, network
    return decoded[1:], False, network


def address_to_public_key_hash(address: str) -> bytes:
    """
    Convert P2PKH address to the corresponding public key hash.
    
    Args:
        address: Bitcoin address string
        
    Returns:
        Public key hash bytes
        
    Raises:
        ValueError: If address format is invalid
    """
    if not re.match(r'^[1mn][a-km-zA-HJ-NP-Z1-9]{24,33}$', address):
        raise ValueError(f'invalid P2PKH address {address}')
    decoded = base58check_decode(address)
    return decoded[1:]


def text_digest(text: str) -> bytes:
    """
    Create digest for signing arbitrary text with bitcoin private key.
    
    Args:
        text: Text to create digest for
        
    Returns:
        Digest bytes ready for signing
    """
    def serialize_text(text: str) -> bytes:
        message: bytes = text.encode('utf-8')
        return unsigned_to_varint(len(message)) + message
    
    return serialize_text('Bitcoin Signed Message:\n') + serialize_text(text)


def unsigned_to_varint(num: int) -> bytes:
    """
    Convert unsigned integer to variable length integer.
    
    Args:
        num: Integer to encode (0 to 2^64-1)
        
    Returns:
        Varint encoded bytes
        
    Raises:
        OverflowError: If number is out of valid range
    """
    if num < 0 or num > 0xffffffffffffffff:
        raise OverflowError(f"can't convert {num} to varint")
    if num <= 0xfc:
        return num.to_bytes(1, 'little')
    elif num <= 0xffff:
        return b'\xfd' + num.to_bytes(2, 'little')
    elif num <= 0xffffffff:
        return b'\xfe' + num.to_bytes(4, 'little')
    else:
        return b'\xff' + num.to_bytes(8, 'little')


def deserialize_ecdsa_recoverable(signature: bytes) -> Tuple[int, int, int]:
    """
    Deserialize recoverable ECDSA signature from bytes to (r, s, recovery_id).
    
    Args:
        signature: 65-byte signature (r + s + recovery_id)
        
    Returns:
        Tuple of (r, s, recovery_id)
        
    Raises:
        AssertionError: If signature format is invalid
    """
    assert len(signature) == 65, 'invalid length of recoverable ECDSA signature'
    rec_id = signature[-1]
    assert 0 <= rec_id <= 3, f'invalid recovery id {rec_id}'
    r = int.from_bytes(signature[:32], 'big')
    s = int.from_bytes(signature[32:-1], 'big')
    return r, s, rec_id


def serialize_ecdsa_recoverable(signature: Tuple[int, int, int]) -> bytes:
    """
    Serialize recoverable ECDSA signature from (r, s, recovery_id) to 65-byte form.
    """
    r, s, rec_id = signature
    assert 0 <= rec_id <= 3, f'invalid recovery id {rec_id}'
    r_bytes = int(r).to_bytes(32, 'big')
    s_bytes = int(s).to_bytes(32, 'big')
    return r_bytes + s_bytes + int(rec_id).to_bytes(1, 'big')


def serialize_ecdsa_der(signature: Tuple[int, int]) -> bytes:
    """
    Serialize ECDSA signature (r, s) to bitcoin strict DER format.
    
    Args:
        signature: Tuple of (r, s) integers
        
    Returns:
        DER encoded signature bytes
    """
    r, s = signature
    # Enforce low s value
    if s > curve.n // 2:
        s = curve.n - s
    
    # Encode r
    r_bytes = r.to_bytes(32, 'big').lstrip(b'\x00')
    if r_bytes[0] & 0x80:
        r_bytes = b'\x00' + r_bytes
    serialized = bytes([2, len(r_bytes)]) + r_bytes
    
    # Encode s
    s_bytes = s.to_bytes(32, 'big').lstrip(b'\x00')
    if s_bytes[0] & 0x80:
        s_bytes = b'\x00' + s_bytes
    serialized += bytes([2, len(s_bytes)]) + s_bytes
    
    return bytes([0x30, len(serialized)]) + serialized


def deserialize_ecdsa_der(signature: bytes) -> Tuple[int, int]:
    """
    Deserialize ECDSA signature from bitcoin strict DER to (r, s).

    Args:
        signature: DER-encoded ECDSA signature bytes

    Returns:
        Tuple of integers (r, s)

    Raises:
        ValueError: If signature encoding is invalid
    """
    try:
        assert signature[0] == 0x30
        assert int(signature[1]) == len(signature) - 2
        # r
        assert signature[2] == 0x02
        r_len = int(signature[3])
        r = int.from_bytes(signature[4: 4 + r_len], 'big')
        # s
        assert signature[4 + r_len] == 0x02
        s_len = int(signature[5 + r_len])
        s = int.from_bytes(signature[-s_len:], 'big')
        return r, s
    except Exception:
        raise ValueError(f'invalid DER encoded {signature.hex()}')


def stringify_ecdsa_recoverable(signature: bytes, compressed: bool = True) -> str:
    """
    Stringify recoverable ECDSA signature to base64 format.
    
    Args:
        signature: 65-byte recoverable signature
        compressed: Whether public key is compressed
        
    Returns:
        Base64 encoded signature string
    """
    _, _, recovery_id = deserialize_ecdsa_recoverable(signature)
    prefix: int = 27 + recovery_id + (4 if compressed else 0)
    signature_bytes: bytes = prefix.to_bytes(1, 'big') + signature[:-1]
    return b64encode(signature_bytes).decode('ascii')


def unstringify_ecdsa_recoverable(signature: str) -> Tuple[bytes, bool]:
    """
    Unstringify recoverable ECDSA signature from base64 format.
    
    Args:
        signature: Base64 encoded signature string
        
    Returns:
        Tuple of (signature_bytes, was_compressed)
    """
    serialized = b64decode(signature)
    assert len(serialized) == 65, 'invalid length of recoverable ECDSA signature'
    prefix = serialized[0]
    assert 27 <= prefix < 35, f'invalid recoverable ECDSA signature prefix {prefix}'
    
    compressed = False
    if prefix >= 31:
        compressed = True
        prefix -= 4
    recovery_id = prefix - 27
    return serialized[1:] + recovery_id.to_bytes(1, 'big'), compressed


def encode_int(num: int) -> bytes:
    """
    Encode signed integer for bitcoin script push operation.
    
    Args:
        num: Integer to encode
        
    Returns:
        Encoded bytes ready for script
    """
    if num == 0:
        return OpCode.OP_0
    
    negative: bool = num < 0
    octets: bytearray = bytearray(unsigned_to_bytes(-num if negative else num, 'little'))
    if octets[-1] & 0x80:
        octets += b'\x00'
    if negative:
        octets[-1] |= 0x80
    
    # Import encode_pushdata from the utils package
    from .pushdata import encode_pushdata
    return encode_pushdata(octets)


def unsigned_to_bytes(num: int, byteorder: Literal['big', 'little'] = 'big') -> bytes:
    """
    Convert unsigned integer to minimum number of bytes.
    
    Args:
        num: Integer to convert
        byteorder: Byte order ('big' or 'little')
        
    Returns:
        Bytes representation
    """
    if num < 0:
        raise OverflowError(f"can't convert negative number {num} to bytes")
    return num.to_bytes(math.ceil(num.bit_length() / 8) or 1, byteorder)


def to_bytes(msg: Union[bytes, str, List[int]], enc: Optional[str] = None) -> bytes:
    """
    Convert various message formats into a bytes object.

    - If msg is bytes, return as-is
    - If msg is str and enc == 'hex', parse hex string (len odd handled)
    - If msg is str and enc == 'base64', decode base64
    - If msg is str and enc is None, UTF-8 encode
    - If msg is a list of ints, convert to bytes
    - If msg is falsy, return empty bytes
    """
    if isinstance(msg, bytes):
        return msg
    if not msg:
        return bytes()
    if isinstance(msg, str):
        if enc == 'hex':
            cleaned = ''.join(filter(str.isalnum, msg))
            if len(cleaned) % 2 != 0:
                cleaned = '0' + cleaned
            return bytes(int(cleaned[i:i + 2], 16) for i in range(0, len(cleaned), 2))
        if enc == 'base64':
            return b64decode(msg)
        return msg.encode('utf-8')
    return bytes(msg)


def reverse_hex_byte_order(hex_str: str) -> str:
    """
    Reverse the byte order of a hex string (little-endian <-> big-endian view).
    """
    return bytes.fromhex(hex_str)[::-1].hex()


def to_legacy_script(script: bytes) -> bytes:
    """
    Convert script to legacy format.

    Args:
        script: Script bytes to convert

    Returns:
        Legacy format script bytes
    """
    # For now, just return the script as-is
    # This is a placeholder implementation
    return script


def to_legacy_transaction(tx: "Transaction") -> bytes:
    """
    Convert transaction to legacy format.

    Args:
        tx: Transaction object to convert

    Returns:
        Legacy format transaction bytes
    """
    # For now, just return the transaction hex
    # This is a placeholder implementation
    return tx.to_hex()
