from typing import List, Optional, Union

from bsv.constants import OPCODE_VALUE_NAME_DICT, OpCode

# Import from utils package that should have these functions available
from bsv.utils import Reader, encode_pushdata, unsigned_to_varint

# BRC-106 compliance: Opcode aliases for parsing
# Build a comprehensive mapping of all opcode names (including aliases) to their byte values
OPCODE_ALIASES = {
    "OP_FALSE": b"\x00",
    "OP_0": b"\x00",
    "OP_TRUE": b"\x51",
    "OP_1": b"\x51",
    # Chronicle backward-compatible aliases
    "OP_NOP4": b"\xb3",
    "OP_NOP5": b"\xb4",
    "OP_NOP6": b"\xb5",
    "OP_NOP7": b"\xb6",
    "OP_NOP8": b"\xb7",
}

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
    def __init__(self, script: str | bytes | None = None):
        """
        Create script from hex string or bytes
        """
        if script is None:
            self._bytes: bytes = b""
        elif isinstance(script, str):
            # script in hex string
            self._bytes: bytes = bytes.fromhex(script)
        elif isinstance(script, bytes):
            # script in bytes
            self._bytes: bytes = script
        else:
            raise TypeError("unsupported script type")
        # An array of script chunks that make up the script.
        self.chunks: list[ScriptChunk] = []
        self._build_chunks()

    @property
    def script(self) -> bytes:
        """Backward compatibility property for script field."""
        return self._bytes

    @property
    def script_bytes(self) -> bytes:
        """Backward compatibility property for script_bytes field."""
        return self._bytes

    def _update_conditional_depth(self, op: bytes, depth: int) -> int:
        """Update conditional block depth based on opcode."""
        if op == OpCode.OP_IF or op == OpCode.OP_NOTIF or op == OpCode.OP_VERIF or op == OpCode.OP_VERNOTIF:
            return depth + 1
        if op == OpCode.OP_ENDIF:
            return max(0, depth - 1)
        return depth

    def _handle_op_return(self, reader: Reader, chunk: ScriptChunk) -> bool:
        """Handle OP_RETURN opcode. Returns True if parsing should terminate."""
        remaining_length = len(reader.getvalue()) - reader.tell()
        if remaining_length > 0:
            chunk.data = reader.read_bytes(remaining_length)
        else:
            chunk.data = None
        self.chunks.append(chunk)
        return True  # Terminate parsing

    def _read_push_data(self, reader: Reader, op: bytes) -> Optional[bytes]:
        """Read push data based on opcode. Returns data bytes or None."""
        if b"\x01" <= op <= b"\x4b":
            return reader.read_bytes(int.from_bytes(op, "big"))
        if op == OpCode.OP_PUSHDATA1:
            length = reader.read_uint8()
            return reader.read_bytes(length) if length is not None else None
        if op == OpCode.OP_PUSHDATA2:
            length = reader.read_uint16_le()
            return reader.read_bytes(length) if length is not None else None
        if op == OpCode.OP_PUSHDATA4:
            length = reader.read_uint32_le()
            return reader.read_bytes(length) if length is not None else None
        return None

    def _build_chunks(self):
        self.chunks = []
        reader = Reader(self._bytes)
        in_conditional_block = 0

        while not reader.eof():
            op = reader.read_bytes(1)
            chunk = ScriptChunk(op)

            in_conditional_block = self._update_conditional_depth(op, in_conditional_block)

            if op == OpCode.OP_RETURN and in_conditional_block == 0:
                if self._handle_op_return(reader, chunk):
                    break
                continue

            data = self._read_push_data(reader, op)
            chunk.data = data
            self.chunks.append(chunk)

    def serialize(self) -> bytes:
        if self._bytes:
            return self._bytes
        # Serialize from chunks if script bytes not set
        result = bytearray()
        for chunk in self.chunks:
            result.extend(chunk.op)
            if chunk.data is not None:
                result.extend(chunk.data)
        return bytes(result)

    def hex(self) -> str:
        return self._bytes.hex()

    def byte_length(self) -> int:
        return len(self._bytes)

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
            return self._bytes == o._bytes
        return super().__eq__(o)

    def __str__(self) -> str:
        return self._bytes.hex()

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
    def _parse_opcode_token(cls, token: str) -> Optional[bytes]:
        """Parse a single token as an opcode. Returns opcode bytes or None."""
        if token in OPCODE_NAME_VALUE_DICT:
            return OPCODE_NAME_VALUE_DICT[token]
        if token == "0":
            return b"\x00"
        if token == "-1":
            return OpCode.OP_1NEGATE
        return None

    @classmethod
    def _parse_data_token(cls, token: str) -> tuple[bytes, bytes]:
        """Parse a token as hex data. Returns (opcode, data) tuple."""
        hex_string = token
        if len(hex_string) % 2 != 0:
            hex_string = "0" + hex_string
        hex_bytes = bytes.fromhex(hex_string)
        if hex_bytes.hex() != hex_string.lower():
            raise ValueError("invalid hex string in script")

        hex_len = len(hex_bytes)
        if 0 <= hex_len < int.from_bytes(OpCode.OP_PUSHDATA1, "big"):
            opcode_value = int.to_bytes(hex_len, 1, "big")
        elif hex_len < pow(2, 8):
            opcode_value = OpCode.OP_PUSHDATA1
        elif hex_len < pow(2, 16):
            opcode_value = OpCode.OP_PUSHDATA2
        else:
            opcode_value = OpCode.OP_PUSHDATA4
        return (opcode_value, hex_bytes)

    @classmethod
    def from_asm(cls, asm: str) -> "Script":
        chunks: [ScriptChunk] = []
        if not asm:
            return Script.from_chunks(chunks)

        tokens = asm.split(" ")
        i = 0
        while i < len(tokens):
            token = tokens[i]
            opcode_value = cls._parse_opcode_token(token)

            if opcode_value is not None:
                chunks.append(ScriptChunk(opcode_value))
                i += 1
            else:
                opcode_value, hex_bytes = cls._parse_data_token(token)
                chunks.append(ScriptChunk(opcode_value, hex_bytes))
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
