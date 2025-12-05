"""
base58_utils.py - Utilities for Base58 and Base58Check encoding/decoding.
"""
from typing import List, Optional

base58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def from_base58(str_: str) -> List[int]:
    if not str_ or not isinstance(str_, str):
        raise ValueError(f"Expected base58 string but got '{str_}'")
    if '0' in str_ or 'I' in str_ or 'O' in str_ or 'l' in str_:
        raise ValueError(f"Invalid base58 character in '{str_}'")
    lz = len(str_) - len(str_.lstrip('1'))
    psz = lz
    acc = 0
    for char in str_:
        acc = acc * 58 + base58chars.index(char)
    result = []
    while acc > 0:
        result.append(acc % 256)
        acc //= 256
    return [0] * psz + list(reversed(result))

def to_base58(bin_: List[int]) -> str:
    acc = 0
    for byte in bin_:
        acc = acc * 256 + byte
    result = ''
    while acc > 0:
        acc, mod = divmod(acc, 58)
        result = base58chars[mod] + result
    for byte in bin_:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result

def to_base58_check(bin_: List[int], prefix: Optional[List[int]] = None) -> str:
    import hashlib
    if prefix is None:
        prefix = [0]
    hash_ = hashlib.sha256(hashlib.sha256(bytes(prefix + bin_)).digest()).digest()
    return to_base58(prefix + bin_ + list(hash_[:4]))

def from_base58_check(str_: str, enc: Optional[str] = None, prefix_length: int = 1):
    import hashlib
    try:
        from .binary import to_hex
    except ImportError:
        # Fallback if relative import fails
        def to_hex(data):
            return data.hex()
    bin_ = from_base58(str_)
    prefix = bin_[:prefix_length]
    data = bin_[prefix_length:-4]
    checksum = bin_[-4:]
    hash_ = hashlib.sha256(hashlib.sha256(bytes(prefix + data)).digest()).digest()
    if list(hash_[:4]) != checksum:
        raise ValueError('Invalid checksum')
    if enc == 'hex':
        prefix = to_hex(bytes(prefix))
        data = to_hex(bytes(data))
    return {'prefix': prefix, 'data': data}