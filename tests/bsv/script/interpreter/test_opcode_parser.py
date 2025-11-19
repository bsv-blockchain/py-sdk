"""
Comprehensive tests for bsv/script/interpreter/op_parser.py

Tests ParsedOpcode and DefaultOpcodeParser classes.
"""

import pytest
from bsv.script.interpreter.op_parser import ParsedOpcode, DefaultOpcodeParser
from bsv.script.script import Script, ScriptChunk
from bsv.constants import OpCode


class TestParsedOpcodeInit:
    """Test ParsedOpcode initialization."""
    
    def test_init_with_op_only(self):
        """Test creating ParsedOpcode with only opcode."""
        opcode = ParsedOpcode(OpCode.OP_DUP)
        assert opcode.opcode == OpCode.OP_DUP
        assert opcode.data is None
    
    def test_init_with_op_and_data(self):
        """Test creating ParsedOpcode with opcode and data."""
        data = b"test_data"
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA1, data)
        assert opcode.opcode == OpCode.OP_PUSHDATA1
        assert opcode.data == data
    
    def test_init_with_empty_data(self):
        """Test creating ParsedOpcode with empty data."""
        opcode = ParsedOpcode(OpCode.OP_0, b"")
        assert opcode.opcode == OpCode.OP_0
        assert opcode.data == b""


class TestIsDisabled:
    """Test is_disabled method."""
    
    def test_op_2mul_is_disabled(self):
        """Test that OP_2MUL is disabled."""
        opcode = ParsedOpcode(OpCode.OP_2MUL)
        assert opcode.is_disabled() is True
    
    def test_op_2div_is_disabled(self):
        """Test that OP_2DIV is disabled."""
        opcode = ParsedOpcode(OpCode.OP_2DIV)
        assert opcode.is_disabled() is True
    
    def test_op_verif_is_disabled(self):
        """Test that OP_VERIF is disabled."""
        opcode = ParsedOpcode(OpCode.OP_VERIF)
        assert opcode.is_disabled() is True
    
    def test_op_vernotif_is_disabled(self):
        """Test that OP_VERNOTIF is disabled."""
        opcode = ParsedOpcode(OpCode.OP_VERNOTIF)
        assert opcode.is_disabled() is True
    
    def test_op_ver_is_disabled(self):
        """Test that OP_VER is disabled."""
        opcode = ParsedOpcode(OpCode.OP_VER)
        assert opcode.is_disabled() is True
    
    def test_regular_op_not_disabled(self):
        """Test that regular opcodes are not disabled."""
        opcode = ParsedOpcode(OpCode.OP_DUP)
        assert opcode.is_disabled() is False
    
    def test_op_checksig_not_disabled(self):
        """Test that OP_CHECKSIG is not disabled."""
        opcode = ParsedOpcode(OpCode.OP_CHECKSIG)
        assert opcode.is_disabled() is False


class TestIsConditional:
    """Test is_conditional method."""
    
    def test_op_if_is_conditional(self):
        """Test that OP_IF is conditional."""
        opcode = ParsedOpcode(OpCode.OP_IF)
        assert opcode.is_conditional() is True
    
    def test_op_notif_is_conditional(self):
        """Test that OP_NOTIF is conditional."""
        opcode = ParsedOpcode(OpCode.OP_NOTIF)
        assert opcode.is_conditional() is True
    
    def test_op_else_is_conditional(self):
        """Test that OP_ELSE is conditional."""
        opcode = ParsedOpcode(OpCode.OP_ELSE)
        assert opcode.is_conditional() is True
    
    def test_op_endif_is_conditional(self):
        """Test that OP_ENDIF is conditional."""
        opcode = ParsedOpcode(OpCode.OP_ENDIF)
        assert opcode.is_conditional() is True
    
    def test_regular_op_not_conditional(self):
        """Test that regular opcodes are not conditional."""
        opcode = ParsedOpcode(OpCode.OP_DUP)
        assert opcode.is_conditional() is False
    
    def test_op_return_not_conditional(self):
        """Test that OP_RETURN is not conditional."""
        opcode = ParsedOpcode(OpCode.OP_RETURN)
        assert opcode.is_conditional() is False


class TestName:
    """Test name method."""
    
    def test_name_for_known_opcode(self):
        """Test getting name for known opcode."""
        opcode = ParsedOpcode(OpCode.OP_DUP)
        name = opcode.name()
        assert "DUP" in name or name == "OP_DUP"
    
    def test_name_for_op_checksig(self):
        """Test getting name for OP_CHECKSIG."""
        opcode = ParsedOpcode(OpCode.OP_CHECKSIG)
        name = opcode.name()
        assert "CHECKSIG" in name
    
    def test_name_for_unknown_opcode(self):
        """Test getting name for unknown opcode."""
        unknown_op = b'\xff'
        opcode = ParsedOpcode(unknown_op)
        name = opcode.name()
        # Either returns "UNKNOWN_ff" or "OP_INVALIDOPCODE" or similar
        assert "UNKNOWN" in name or "INVALID" in name or "ff" in name.lower()


class TestEnforceMinimumDataPush:
    """Test enforce_minimum_data_push method."""
    
    def test_none_data_returns_none(self):
        """Test that None data returns None."""
        opcode = ParsedOpcode(OpCode.OP_NOP)
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_empty_data_with_op_0_valid(self):
        """Test that empty data with OP_0 is valid."""
        opcode = ParsedOpcode(OpCode.OP_0, b"")
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_empty_data_without_op_0_invalid(self):
        """Test that empty data without OP_0 is invalid."""
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA1, b"")
        result = opcode.enforce_minimum_data_push()
        assert result is not None
        assert "OP_0" in result
    
    def test_single_byte_1_with_op_1_valid(self):
        """Test that single byte value 1 with OP_1 is valid."""
        opcode = ParsedOpcode(OpCode.OP_1, bytes([1]))
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_single_byte_16_with_op_16_valid(self):
        """Test that single byte value 16 with OP_16 is valid."""
        opcode = ParsedOpcode(OpCode.OP_16, bytes([16]))
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_single_byte_value_with_wrong_op_invalid(self):
        """Test that single byte value with wrong opcode is invalid."""
        opcode = ParsedOpcode(bytes([0x01]), bytes([5]))
        result = opcode.enforce_minimum_data_push()
        assert result is not None
        assert "OP_5" in result or "5" in result
    
    def test_single_byte_0x81_with_op_1negate_valid(self):
        """Test that single byte 0x81 with OP_1NEGATE is valid."""
        opcode = ParsedOpcode(OpCode.OP_1NEGATE, bytes([0x81]))
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_single_byte_0x81_without_op_1negate_invalid(self):
        """Test that single byte 0x81 without OP_1NEGATE is invalid."""
        opcode = ParsedOpcode(bytes([0x01]), bytes([0x81]))
        result = opcode.enforce_minimum_data_push()
        assert result is not None
        assert "OP_1NEGATE" in result or "-1" in result
    
    def test_data_length_75_with_direct_push_valid(self):
        """Test that data length <= 75 with direct push is valid."""
        data = b"A" * 10
        opcode = ParsedOpcode(bytes([10]), data)
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_data_length_75_with_wrong_op_invalid(self):
        """Test that data length <= 75 with wrong opcode is invalid."""
        data = b"A" * 10
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA1, data)
        result = opcode.enforce_minimum_data_push()
        assert result is not None
        assert "direct push" in result
    
    def test_data_length_76_to_255_with_op_pushdata1_valid(self):
        """Test that data length 76-255 with OP_PUSHDATA1 is valid."""
        data = b"A" * 100
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA1, data)
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_data_length_76_to_255_with_direct_push_invalid(self):
        """Test that data length 76-255 with direct push is invalid."""
        data = b"A" * 100
        opcode = ParsedOpcode(bytes([100]), data)
        result = opcode.enforce_minimum_data_push()
        assert result is not None
        assert "OP_PUSHDATA1" in result
    
    def test_data_length_256_to_65535_with_op_pushdata2_valid(self):
        """Test that data length 256-65535 with OP_PUSHDATA2 is valid."""
        data = b"A" * 300
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA2, data)
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_data_length_256_to_65535_with_wrong_op_invalid(self):
        """Test that data length 256-65535 with wrong opcode is invalid."""
        data = b"A" * 300
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA1, data)
        result = opcode.enforce_minimum_data_push()
        assert result is not None
        assert "OP_PUSHDATA2" in result
    
    def test_data_length_large_with_op_pushdata4_valid(self):
        """Test that large data with OP_PUSHDATA4 is valid."""
        data = b"A" * 70000
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA4, data)
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_data_length_large_with_wrong_op_invalid(self):
        """Test that large data with wrong opcode is invalid."""
        data = b"A" * 70000
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA2, data)
        result = opcode.enforce_minimum_data_push()
        assert result is not None
        assert "OP_PUSHDATA4" in result
    
    def test_boundary_75_bytes(self):
        """Test boundary at 75 bytes."""
        data = b"A" * 75
        opcode = ParsedOpcode(bytes([75]), data)
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_boundary_76_bytes(self):
        """Test boundary at 76 bytes (requires OP_PUSHDATA1)."""
        data = b"A" * 76
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA1, data)
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_boundary_255_bytes(self):
        """Test boundary at 255 bytes."""
        data = b"A" * 255
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA1, data)
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_boundary_256_bytes(self):
        """Test boundary at 256 bytes (requires OP_PUSHDATA2)."""
        data = b"A" * 256
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA2, data)
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_boundary_65535_bytes(self):
        """Test boundary at 65535 bytes."""
        data = b"A" * 65535
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA2, data)
        result = opcode.enforce_minimum_data_push()
        assert result is None
    
    def test_boundary_65536_bytes(self):
        """Test boundary at 65536 bytes (requires OP_PUSHDATA4)."""
        data = b"A" * 65536
        opcode = ParsedOpcode(OpCode.OP_PUSHDATA4, data)
        result = opcode.enforce_minimum_data_push()
        assert result is None


class TestDefaultOpcodeParserInit:
    """Test DefaultOpcodeParser initialization."""
    
    def test_init_default(self):
        """Test default initialization."""
        parser = DefaultOpcodeParser()
        assert parser.error_on_check_sig is False
    
    def test_init_with_error_on_check_sig(self):
        """Test initialization with error_on_check_sig=True."""
        parser = DefaultOpcodeParser(error_on_check_sig=True)
        assert parser.error_on_check_sig is True
    
    def test_init_with_error_on_check_sig_false(self):
        """Test initialization with error_on_check_sig=False."""
        parser = DefaultOpcodeParser(error_on_check_sig=False)
        assert parser.error_on_check_sig is False


class TestDefaultOpcodeParserParse:
    """Test DefaultOpcodeParser parse method."""
    
    def test_parse_empty_script(self):
        """Test parsing empty script."""
        parser = DefaultOpcodeParser()
        script = Script()
        parsed = parser.parse(script)
        assert len(parsed) == 0
    
    def test_parse_single_opcode(self):
        """Test parsing script with single opcode."""
        parser = DefaultOpcodeParser()
        script = Script()
        script.chunks = [ScriptChunk(op=OpCode.OP_DUP, data=None)]
        
        parsed = parser.parse(script)
        
        assert len(parsed) == 1
        assert parsed[0].opcode == OpCode.OP_DUP
        assert parsed[0].data is None
    
    def test_parse_multiple_opcodes(self):
        """Test parsing script with multiple opcodes."""
        parser = DefaultOpcodeParser()
        script = Script()
        script.chunks = [
            ScriptChunk(op=OpCode.OP_DUP, data=None),
            ScriptChunk(op=OpCode.OP_HASH160, data=None),
            ScriptChunk(op=OpCode.OP_EQUALVERIFY, data=None),
        ]
        
        parsed = parser.parse(script)
        
        assert len(parsed) == 3
        assert parsed[0].opcode == OpCode.OP_DUP
        assert parsed[1].opcode == OpCode.OP_HASH160
        assert parsed[2].opcode == OpCode.OP_EQUALVERIFY
    
    def test_parse_op_with_data(self):
        """Test parsing opcode with data."""
        parser = DefaultOpcodeParser()
        script = Script()
        data = b"test_data_here"
        script.chunks = [ScriptChunk(op=bytes([len(data)]), data=data)]
        
        parsed = parser.parse(script)
        
        assert len(parsed) == 1
        assert parsed[0].data == data
    
    def test_parse_mixed_opcodes_and_data(self):
        """Test parsing mixed opcodes and data pushes."""
        parser = DefaultOpcodeParser()
        script = Script()
        data1 = b"data1"
        data2 = b"data2"
        script.chunks = [
            ScriptChunk(op=OpCode.OP_DUP, data=None),
            ScriptChunk(op=bytes([len(data1)]), data=data1),
            ScriptChunk(op=OpCode.OP_HASH160, data=None),
            ScriptChunk(op=bytes([len(data2)]), data=data2),
            ScriptChunk(op=OpCode.OP_EQUALVERIFY, data=None),
        ]
        
        parsed = parser.parse(script)
        
        assert len(parsed) == 5
        assert parsed[0].opcode == OpCode.OP_DUP
        assert parsed[1].data == data1
        assert parsed[2].opcode == OpCode.OP_HASH160
        assert parsed[3].data == data2
        assert parsed[4].opcode == OpCode.OP_EQUALVERIFY
    
    def test_parse_with_conditional_opcodes(self):
        """Test parsing script with conditional opcodes."""
        parser = DefaultOpcodeParser()
        script = Script()
        script.chunks = [
            ScriptChunk(op=OpCode.OP_IF, data=None),
            ScriptChunk(op=OpCode.OP_DUP, data=None),
            ScriptChunk(op=OpCode.OP_ELSE, data=None),
            ScriptChunk(op=OpCode.OP_DROP, data=None),
            ScriptChunk(op=OpCode.OP_ENDIF, data=None),
        ]
        
        parsed = parser.parse(script)
        
        assert len(parsed) == 5
        assert parsed[0].is_conditional()
        assert parsed[2].is_conditional()
        assert parsed[4].is_conditional()
        assert not parsed[1].is_conditional()
    
    def test_parse_with_disabled_opcodes(self):
        """Test parsing script with disabled opcodes."""
        parser = DefaultOpcodeParser()
        script = Script()
        script.chunks = [
            ScriptChunk(op=OpCode.OP_2MUL, data=None),
            ScriptChunk(op=OpCode.OP_DUP, data=None),
        ]
        
        parsed = parser.parse(script)
        
        assert len(parsed) == 2
        assert parsed[0].is_disabled()
        assert not parsed[1].is_disabled()
    
    def test_parse_returns_parsed_op_instances(self):
        """Test that parse returns ParsedOpcode instances."""
        parser = DefaultOpcodeParser()
        script = Script()
        script.chunks = [ScriptChunk(op=OpCode.OP_1, data=None)]
        
        parsed = parser.parse(script)
        
        assert len(parsed) == 1
        assert isinstance(parsed[0], ParsedOpcode)

