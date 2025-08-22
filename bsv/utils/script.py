"""
script.py - Utilities for Bitcoin Script pushdata and integer encoding.
"""
from ..constants import OpCode
from .binary import unsigned_to_bytes

def get_pushdata_code(byte_length: int) -> bytes:
    if byte_length <= 0x4b:
        return byte_length.to_bytes(1, 'little')
    elif byte_length <= 0xff:
        return OpCode.OP_PUSHDATA1 + byte_length.to_bytes(1, 'little')
    elif byte_length <= 0xffff:
        return OpCode.OP_PUSHDATA2 + byte_length.to_bytes(2, 'little')
    elif byte_length <= 0xffffffff:
        return OpCode.OP_PUSHDATA4 + byte_length.to_bytes(4, 'little')
    else:
        raise ValueError("data too long to encode in a PUSHDATA opcode")

def encode_pushdata(pushdata: bytes, minimal_push: bool = True) -> bytes:
    if minimal_push:
        if pushdata == b'':
            return OpCode.OP_0
        if len(pushdata) == 1 and 1 <= pushdata[0] <= 16:
            return bytes([OpCode.OP_1[0] + pushdata[0] - 1])
        if len(pushdata) == 1 and pushdata[0] == 0x81:
            return OpCode.OP_1NEGATE
    else:
        assert pushdata, 'empty pushdata'
    return get_pushdata_code(len(pushdata)) + pushdata

def encode_int(num: int) -> bytes:
    if num == 0:
        return OpCode.OP_0
    negative: bool = num < 0
    octets: bytearray = bytearray(unsigned_to_bytes(-num if negative else num, 'little'))
    if octets[-1] & 0x80:
        octets += b'\x00'
    if negative:
        octets[-1] |= 0x80
    return encode_pushdata(octets)