"""
ecdsa.py - Utilities for ECDSA signature serialization/deserialization.
"""
from base64 import b64encode, b64decode
from typing import Tuple
from ..constants import NUMBER_BYTE_LENGTH
from ..curve import curve

def deserialize_ecdsa_der(signature: bytes) -> Tuple[int, int]:
    try:
        assert signature[0] == 0x30
        assert int(signature[1]) == len(signature) - 2
        assert signature[2] == 0x02
        r_len = int(signature[3])
        r = int.from_bytes(signature[4: 4 + r_len], 'big')
        assert signature[4 + r_len] == 0x02
        s_len = int(signature[5 + r_len])
        s = int.from_bytes(signature[-s_len:], 'big')
        return r, s
    except Exception:
        raise ValueError(f'invalid DER encoded {signature.hex()}')

def serialize_ecdsa_der(signature: Tuple[int, int]) -> bytes:
    r, s = signature
    if s > curve.n // 2:
        s = curve.n - s
    r_bytes = r.to_bytes(NUMBER_BYTE_LENGTH, 'big').lstrip(b'\x00')
    if r_bytes[0] & 0x80:
        r_bytes = b'\x00' + r_bytes
    serialized = bytes([2, len(r_bytes)]) + r_bytes
    s_bytes = s.to_bytes(NUMBER_BYTE_LENGTH, 'big').lstrip(b'\x00')
    if s_bytes[0] & 0x80:
        s_bytes = b'\x00' + s_bytes
    serialized += bytes([2, len(s_bytes)]) + s_bytes
    return bytes([0x30, len(serialized)]) + serialized

def deserialize_ecdsa_recoverable(signature: bytes) -> Tuple[int, int, int]:
    assert len(signature) == 65, 'invalid length of recoverable ECDSA signature'
    rec_id = signature[-1]
    assert 0 <= rec_id <= 3, f'invalid recovery id {rec_id}'
    r = int.from_bytes(signature[:NUMBER_BYTE_LENGTH], 'big')
    s = int.from_bytes(signature[NUMBER_BYTE_LENGTH:-1], 'big')
    return r, s, rec_id

def serialize_ecdsa_recoverable(signature: Tuple[int, int, int]) -> bytes:
    _r, _s, _rec_id = signature
    assert 0 <= _rec_id < 4, f'invalid recovery id {_rec_id}'
    r = _r.to_bytes(NUMBER_BYTE_LENGTH, 'big')
    s = _s.to_bytes(NUMBER_BYTE_LENGTH, 'big')
    rec_id = _rec_id.to_bytes(1, 'big')
    return r + s + rec_id

def stringify_ecdsa_recoverable(signature: bytes, compressed: bool = True) -> str:
    _, _, recovery_id = deserialize_ecdsa_recoverable(signature)
    prefix: int = 27 + recovery_id + (4 if compressed else 0)
    signature: bytes = prefix.to_bytes(1, 'big') + signature[:-1]
    return b64encode(signature).decode('ascii')

def unstringify_ecdsa_recoverable(signature: str) -> Tuple[bytes, bool]:
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