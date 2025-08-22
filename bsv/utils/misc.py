"""
misc.py - Utilities for random generation, bits<->bytes conversion, and reverse hex byte order.
"""
import math
from secrets import randbits
from typing import Union

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