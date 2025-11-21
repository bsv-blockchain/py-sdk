"""
Opcode parser for script interpreter.

Ported from go-sdk/script/interpreter/opcodeparser.go
"""

from typing import List, Optional

from bsv.script.script import Script, ScriptChunk
from bsv.constants import OpCode


class ParsedOpcode:
    """Represents a parsed opcode."""

    def __init__(self, opcode: bytes, data: Optional[bytes] = None):
        self.opcode = opcode
        self.data = data

    def is_disabled(self) -> bool:
        """Check if opcode is disabled."""
        return (
            self.opcode == OpCode.OP_2MUL
            or self.opcode == OpCode.OP_2DIV
            or self.opcode == OpCode.OP_VERIF
            or self.opcode == OpCode.OP_VERNOTIF
            or self.opcode == OpCode.OP_VER
        )

    def is_conditional(self) -> bool:
        """Check if opcode is conditional."""
        return (
            self.opcode == OpCode.OP_IF
            or self.opcode == OpCode.OP_NOTIF
            or self.opcode == OpCode.OP_ELSE
            or self.opcode == OpCode.OP_ENDIF
        )

    def name(self) -> str:  # NOSONAR - Complexity (22), requires refactoring
        """Get opcode name."""
        from bsv.constants import OPCODE_VALUE_NAME_DICT
        return OPCODE_VALUE_NAME_DICT.get(self.opcode, f"UNKNOWN_{self.opcode.hex()}")

    def _check_empty_data_push(self) -> Optional[str]:
        """Check if empty data uses OP_0."""
        if self.opcode != OpCode.OP_0:
            return "empty data push must use OP_0"
        return None

    def _check_small_int_push(self, value: int) -> Optional[str]:
        """Check if small integers (1-16) use OP_1 through OP_16."""
        expected_op = bytes([int.from_bytes(OpCode.OP_1, 'big') + value - 1])
        if self.opcode != expected_op:
            return f"data push of {value} should use OP_{value}"
        return None

    def _check_neg_one_push(self) -> Optional[str]:
        """Check if -1 (0x81) uses OP_1NEGATE."""
        if self.opcode != OpCode.OP_1NEGATE:
            return "data push of -1 should use OP_1NEGATE"
        return None

    def _check_direct_push(self, data_len: int) -> Optional[str]:
        """Check if data <= 75 bytes uses direct push."""
        expected_op = bytes([data_len])
        if self.opcode != expected_op:
            return f"data push of {data_len} bytes should use direct push opcode"
        return None

    def _check_pushdata_encoding(self, data_len: int) -> Optional[str]:
        """Check if correct PUSHDATA opcode is used for data length."""
        if data_len <= 255:
            if self.opcode != OpCode.OP_PUSHDATA1:
                return f"data push of {data_len} bytes should use OP_PUSHDATA1"
        elif data_len <= 65535:
            if self.opcode != OpCode.OP_PUSHDATA2:
                return f"data push of {data_len} bytes should use OP_PUSHDATA2"
        else:
            if self.opcode != OpCode.OP_PUSHDATA4:
                return f"data push of {data_len} bytes should use OP_PUSHDATA4"
        return None

    def enforce_minimum_data_push(self) -> Optional[str]:
        """Enforce minimal data push encoding."""
        if self.data is None:
            return None
        
        data_len = len(self.data)
        
        # Empty data should use OP_0
        if data_len == 0:
            return self._check_empty_data_push()
        
        # Single byte 1-16 should use OP_1 through OP_16
        if data_len == 1 and 1 <= self.data[0] <= 16:
            return self._check_small_int_push(self.data[0])
        
        # Single byte 0x81 should use OP_1NEGATE
        if data_len == 1 and self.data[0] == 0x81:
            return self._check_neg_one_push()
        
        # Data length <= 75 should use direct push
        if data_len <= 75:
            return self._check_direct_push(data_len)
        
        # Data length > 75 should use appropriate PUSHDATA opcode
        return self._check_pushdata_encoding(data_len)


ParsedScript = List[ParsedOpcode]


class DefaultOpcodeParser:
    """Default opcode parser implementation."""

    def __init__(self, error_on_check_sig: bool = False):
        self.error_on_check_sig = error_on_check_sig

    def parse(self, script: Script) -> ParsedScript:
        """Parse a script into a list of parsed opcodes."""
        parsed: ParsedScript = []
        
        for chunk in script.chunks:
            opcode = ParsedOpcode(chunk.op, chunk.data)
            parsed.append(opcode)
        
        return parsed

