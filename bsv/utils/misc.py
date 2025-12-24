"""
misc.py - Utilities for random generation, bits<->bytes conversion, and reverse hex byte order.
"""
import math
from secrets import randbits
from typing import Union, Optional

def bytes_to_bits(octets: Union[str, bytes]) -> str:
    b: bytes = octets if isinstance(octets, bytes) else bytes.fromhex(octets)
    bits: str = bin(int.from_bytes(b, 'big'))[2:]
    if len(bits) < len(b) * 8:
        bits = '0' * (len(b) * 8 - len(bits)) + bits
    return bits

def bits_to_bytes(bits: str) -> bytes:
    byte_length = math.ceil(len(bits) / 8) or 1
    return int(bits, 2).to_bytes(byte_length, byteorder='big')

def randbytes(length: int) -> bytes:
    return randbits(length * 8).to_bytes(length, 'big')

def reverse_hex_byte_order(hex_str: str):
    return bytes.fromhex(hex_str)[::-1].hex()


def ensure_bytes(data: Union[str, bytes], encoding: Optional[str] = None) -> bytes:
    """
    Ensure data is bytes, converting if necessary.

    Args:
        data: Input data (string, bytes, or hex string)
        encoding: Optional encoding for string conversion ('hex' for hex strings)

    Returns:
        Data as bytes

    Raises:
        TypeError: If data type is unsupported
    """
    if isinstance(data, bytes):
        return data
    elif isinstance(data, str):
        if encoding == 'hex':
            return bytes.fromhex(data)
        else:
            return data.encode('utf-8')
    else:
        raise TypeError(f"Unsupported data type: {type(data)}")


def ensure_string(data: Union[str, bytes]) -> str:
    """
    Ensure data is string, converting if necessary.

    Args:
        data: Input data (string or bytes)

    Returns:
        Data as string

    Raises:
        TypeError: If data type is unsupported
    """
    if isinstance(data, str):
        return data
    elif isinstance(data, bytes):
        return data.decode('utf-8')
    else:
        raise TypeError(f"Unsupported data type: {type(data)}")


def pad_bytes(data: bytes, length: int, side: str = 'left') -> bytes:
    """
    Pad bytes to specified length.

    Args:
        data: Input bytes to pad
        length: Target length
        side: Which side to pad ('left' or 'right')

    Returns:
        Padded bytes (or original data if already long enough)

    Raises:
        ValueError: If side is not 'left' or 'right'
    """
    if len(data) >= length:
        return data

    padding_needed = length - len(data)
    padding = b'\x00' * padding_needed

    if side == 'left':
        return padding + data
    elif side == 'right':
        return data + padding
    else:
        raise ValueError(f"Invalid side parameter: {side}. Must be 'left' or 'right'")