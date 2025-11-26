from typing import Union, Optional, List

from bsv.constants import OpCode, OPCODE_VALUE_NAME_DICT
# Import from utils package that should have these functions available
from bsv.utils import encode_pushdata, unsigned_to_varint, Reader

# BRC-106 compliance: Opcode aliases for parsing
# Build a comprehensive mapping of all opcode names (including aliases) to their byte values
OPCODE_ALIASES = {
    'OP_FALSE': b'\x00',
    'OP_0': b'\x00',
    'OP_TRUE': b'\x51',
    'OP_1': b'\x51'
}

# Build name->value mapping for all OpCodes
OPCODE_NAME_VALUE_DICT = {item.name: item.value for item in OpCode}
# Merge with aliases
OPCODE_NAME_VALUE_DICT.update(OPCODE_ALIASES)

class ScriptChunk:
    """
    A representation of a chunk of a script, which includes an opcode.
    For push operations, the associated data to push onto the stack is also included.
    """

    def __init__(self, op: bytes, data: Optional[bytes] = None):
        self.op = op
        self.data = data

    def __str__(self):
        if self.data is not None:
            return self.data.hex()
        return OPCODE_VALUE_NAME_DICT[self.op]

    def __repr__(self):
        return self.__str__()


class Script:

    def __init__(self, script: Union[str, bytes, None] = None):
        """
        Create script from hex string or bytes
        """
        if script is None:
            self.script: bytes = b''
        elif isinstance(script, str):
            # script in hex string
            self.script: bytes = bytes.fromhex(script)
        elif isinstance(script, bytes):
            # script in bytes
            self.script: bytes = script
        else:
            raise TypeError('unsupported script type')
        # An array of script chunks that make up the script.
        self.chunks: List[ScriptChunk] = []
        self._build_chunks()

    def _build_chunks(self):
        self.chunks = []
        reader = Reader(self.script)
        while not reader.eof():
            op = reader.read_bytes(1)
            chunk = ScriptChunk(op)
            data = None
            if b'\x01' <= op <= b'\x4b':
                data = reader.read_bytes(int.from_bytes(op, 'big'))
            elif op == OpCode.OP_PUSHDATA1:  # 0x4c
                length = reader.read_uint8()
                if length is not None:
                    data = reader.read_bytes(length)
            elif op == OpCode.OP_PUSHDATA2:
                length = reader.read_uint16_le()
                if length is not None:
                    data = reader.read_bytes(length)
            elif op == OpCode.OP_PUSHDATA4:
                length = reader.read_uint32_le()
                if length is not None:
                    data = reader.read_bytes(length)
            chunk.data = data
            self.chunks.append(chunk)

    def serialize(self) -> bytes:
        return self.script

    def hex(self) -> str:
        return self.script.hex()

    def byte_length(self) -> int:
        return len(self.script)

    size = byte_length

    def byte_length_varint(self) -> bytes:
        return unsigned_to_varint(self.byte_length())

    size_varint = byte_length_varint

    def is_push_only(self) -> bool:
        """
        Checks if the script contains only push data operations.
        :return: True if the script is push-only, otherwise false.
        """
        for chunk in self.chunks:
            if chunk.op > OpCode.OP_16:
                return False
        return True

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Script):
            return self.script == o.script
        return super().__eq__(o)

    def __str__(self) -> str:
        return self.script.hex()

    def __repr__(self) -> str:
        return self.__str__()

    @classmethod
    def from_chunks(cls, chunks: List[ScriptChunk]) -> 'Script':
        script = b''
        for chunk in chunks:
            script += encode_pushdata(chunk.data) if chunk.data is not None else chunk.op
        s = Script(script)
        s.chunks = chunks
        return s

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Script':
        """
        Create a Script object from bytes data.
        
        Args:
            data: Raw script bytes
            
        Returns:
            Script: A new Script object
        """
        return cls(data)

    def to_bytes(self) -> bytes:
        """
        Convert the Script object to bytes.
        
        Returns:
            bytes: The serialized script bytes
        """
        return self.serialize()

    @classmethod
    def from_asm(cls, asm: str) -> 'Script':
        chunks: [ScriptChunk] = []
        if not asm:  # Handle empty string
            return Script.from_chunks(chunks)
        tokens = asm.split(' ')
        i = 0
        while i < len(tokens):
            token = tokens[i]
            opcode_value: Optional[bytes] = None
            # BRC-106: Check if token is a recognized opcode (including aliases)
            if token in OPCODE_NAME_VALUE_DICT:
                opcode_value = OPCODE_NAME_VALUE_DICT[token]
                chunks.append(ScriptChunk(opcode_value))
                i += 1
            elif token == '0':
                # Numeric literal 0
                opcode_value = b'\x00'
                chunks.append(ScriptChunk(opcode_value))
                i += 1
            elif token == '-1':
                # Numeric literal -1
                opcode_value = OpCode.OP_1NEGATE
                chunks.append(ScriptChunk(opcode_value))
                i += 1
            else:
                # Assume it's hex data to push
                hex_string = token
                if len(hex_string) % 2 != 0:
                    hex_string = '0' + hex_string
                hex_bytes = bytes.fromhex(hex_string)
                if hex_bytes.hex() != hex_string.lower():
                    raise ValueError('invalid hex string in script')
                hex_len = len(hex_bytes)
                if 0 <= hex_len < int.from_bytes(OpCode.OP_PUSHDATA1, 'big'):
                    op_value = int.to_bytes(hex_len, 1, 'big')
                elif hex_len < pow(2, 8):
                    op_value = OpCode.OP_PUSHDATA1
                elif hex_len < pow(2, 16):
                    op_value = OpCode.OP_PUSHDATA2
                elif hex_len < pow(2, 32):
                    op_value = OpCode.OP_PUSHDATA4
                chunks.append(ScriptChunk(op_value, hex_bytes))
                i = i + 1
        return Script.from_chunks(chunks)

    def to_asm(self) -> str:
        return ' '.join(str(chunk) for chunk in self.chunks)

    @classmethod
    def find_and_delete(cls, source: 'Script', pattern: 'Script') -> 'Script':
        chunks = []
        for chunk in source.chunks:
            if Script.from_chunks([chunk]).hex() != pattern.hex():
                chunks.append(chunk)
        return Script.from_chunks(chunks)

    @classmethod
    def write_bin(cls, octets: bytes) -> 'Script':
        return Script(encode_pushdata(octets))
