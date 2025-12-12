"""
Pushdata encoding utilities from main utils.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from constants import OpCode


def get_pushdata_code(length: int) -> bytes:
    """get the pushdata opcode based on length of data you want to push onto the stack"""
    if length <= 75:
        return length.to_bytes(1, 'little')
    elif length <= 255:
        return OpCode.OP_PUSHDATA1 + length.to_bytes(1, 'little')
    elif length <= 65535:
        return OpCode.OP_PUSHDATA2 + length.to_bytes(2, 'little')
    elif length <= 4294967295:
        return OpCode.OP_PUSHDATA4 + length.to_bytes(4, 'little')
    else:
        raise ValueError("data too long to encode in a PUSHDATA opcode")


def encode_pushdata(pushdata: bytes, minimal_push: bool = True) -> bytes:
    """encode pushdata with proper opcode
    https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.0.10/src/script/interpreter.cpp#L310-L337
    :param pushdata: bytes you want to push onto the stack in bitcoin script
    :param minimal_push: if True then push data following the minimal push rule
    """
    if minimal_push:
        if pushdata == b'':
            return OpCode.OP_0
        if len(pushdata) == 1 and 1 <= pushdata[0] <= 16:
            return bytes([OpCode.OP_1[0] + pushdata[0] - 1])
        if len(pushdata) == 1 and pushdata[0] == 0x81:
            return OpCode.OP_1NEGATE
    else:
        # non-minimal push requires pushdata != b''
        assert pushdata, 'empty pushdata'
    return get_pushdata_code(len(pushdata)) + pushdata
