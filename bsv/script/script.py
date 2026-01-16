from typing import List, Optional, Union

from bsv.constants import OPCODE_VALUE_NAME_DICT, OpCode

# Import from utils package that should have these functions available
from bsv.utils import Reader, encode_pushdata, unsigned_to_varint

# BRC-106 compliance: Opcode aliases for parsing
# Build a comprehensive mapping of all opcode names (including aliases) to their byte values
OPCODE_ALIASES = {"OP_FALSE": b"\x00", "OP_0": b"\x00", "OP_TRUE": b"\x51", "OP_1": b"\x51"}

# Build name->value mapping for all OpCodes
OPCODE_NAME_VALUE_DICT = {item.name: item.value for item in OpCode}
# Merge with aliases
OPCODE_NAME_VALUE_DICT.update(OPCODE_ALIASES)

# Maximum data size for OP_PUSHDATA4 (2^32 - 1 bytes)
MAX_PUSH_DATA_SIZE = 2**32 - 1


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
            self.script_bytes: bytes = b""
        elif isinstance(script, str):
            # script in hex string
            self.script_bytes: bytes = bytes.fromhex(script)
        elif isinstance(script, bytes):
            # script in bytes
            self.script_bytes: bytes = script
        else:
            raise TypeError("unsupported script type")
        # An array of script chunks that make up the script.
        self.chunks: list[ScriptChunk] = []
        self._build_chunks()

    @property
    def script(self) -> bytes:
        """Backward compatibility property for script field."""
        return self.script_bytes

    def _build_chunks(self):
        self.chunks = []
        reader = Reader(self.script_bytes)
        while not reader.eof():
            op = reader.read_bytes(1)
            chunk = ScriptChunk(op)
            data = None
            if b"\x01" <= op <= b"\x4b":
                data = reader.read_bytes(int.from_bytes(op, "big"))
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
        if self.script_bytes:
            return self.script_bytes
        # Serialize from chunks if script bytes not set
        result = bytearray()
        for chunk in self.chunks:
            result.extend(chunk.op)
            if chunk.data is not None:
                result.extend(chunk.data)
        return bytes(result)

    def hex(self) -> str:
        return self.script_bytes.hex()

    def byte_length(self) -> int:
        return len(self.script_bytes)

    size = byte_length

    def byte_length_varint(self) -> bytes:
        return unsigned_to_varint(self.byte_length())

    size_varint = byte_length_varint

    def is_push_only(self) -> bool:
        """
        Checks if the script contains only push data operations.
        :return: True if the script is push-only, otherwise false.
        """
        return all(chunk.op <= OpCode.OP_16 for chunk in self.chunks)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Script):
            return self.script_bytes == o.script_bytes
        return super().__eq__(o)

    def __str__(self) -> str:
        return self.script_bytes.hex()

    def __repr__(self) -> str:
        return self.__str__()

    @classmethod
    def from_chunks(cls, chunks: list[ScriptChunk]) -> "Script":
        script = b""
        for chunk in chunks:
            script += encode_pushdata(chunk.data) if chunk.data is not None else chunk.op
        s = Script(script)
        s.chunks = chunks
        return s

    @classmethod
    def from_bytes(cls, data: bytes) -> "Script":
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
    def from_asm(cls, asm: str) -> "Script":
        chunks: [ScriptChunk] = []
        if not asm:  # Handle empty string
            return Script.from_chunks(chunks)

        tokens = asm.split(" ")
        i = 0
        while i < len(tokens):
            token = tokens[i]
            # BRC-106: Check if token is a recognized opcode (including aliases)
            if token in OPCODE_NAME_VALUE_DICT:
                chunks.append(ScriptChunk(OPCODE_NAME_VALUE_DICT[token]))
                i += 1
            elif token == "0":
                # Numeric literal 0
                chunks.append(ScriptChunk(b"\x00"))
                i += 1
            elif token == "-1":
                # Numeric literal -1
                chunks.append(ScriptChunk(OpCode.OP_1NEGATE))
                i += 1
            else:
                # Assume it's hex data to push
                chunk = cls._parse_hex_token(token)
                chunks.append(chunk)
                i += 1
        return Script.from_chunks(chunks)

    @classmethod
    def _parse_hex_token(cls, token: str) -> ScriptChunk:
        """Parse a hex token into a script chunk."""
        hex_string = token
        if len(hex_string) % 2 != 0:
            hex_string = "0" + hex_string
        hex_bytes = bytes.fromhex(hex_string)
        if hex_bytes.hex() != hex_string.lower():
            raise ValueError("invalid hex string in script")

        hex_len = len(hex_bytes)
        op_value = cls._get_push_opcode(hex_len)
        return ScriptChunk(op_value, hex_bytes)

    @classmethod
    def _get_push_opcode(cls, data_length: int) -> bytes:
        """Get the appropriate push opcode for the given data length."""
        pushdata1_threshold = int.from_bytes(OpCode.OP_PUSHDATA1, "big")
        if 0 <= data_length < pushdata1_threshold:
            return int.to_bytes(data_length, 1, "big")
        elif data_length < pow(2, 8):
            return OpCode.OP_PUSHDATA1
        elif data_length < pow(2, 16):
            return OpCode.OP_PUSHDATA2
        elif data_length < pow(2, 32):
            return OpCode.OP_PUSHDATA4
        else:
            raise ValueError(f"data too large: {data_length} bytes (maximum allowed: {MAX_PUSH_DATA_SIZE} bytes)")

    def to_asm(self) -> str:
        return " ".join(str(chunk) for chunk in self.chunks)

    @classmethod
    def find_and_delete(cls, source: "Script", pattern: "Script") -> "Script":
        chunks = []
        for chunk in source.chunks:
            if Script.from_chunks([chunk]).hex() != pattern.hex():
                chunks.append(chunk)
        return Script.from_chunks(chunks)

    @classmethod
    def write_bin(cls, octets: bytes) -> "Script":
        return Script(encode_pushdata(octets))
