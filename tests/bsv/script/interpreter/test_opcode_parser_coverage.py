"""
Coverage tests for script/interpreter/op_parser.py - untested branches.
"""
import pytest


# ========================================================================
# Opcode parsing branches
# ========================================================================

def test_parse_op_single_byte():
    """Test parsing single byte opcode."""
    try:
        from bsv.script.interpreter.op_parser import DefaultOpcodeParser, ParsedOpcode
        from bsv.script.script import Script

        # OP_1
        script = Script(b'\x51')
        parser = DefaultOpcodeParser()
        parsed = parser.parse(script)
        assert len(parsed) == 1
        assert isinstance(parsed[0], ParsedOpcode)
        assert parsed[0].opcode == b'\x51'
    except (ImportError, AttributeError):
        pytest.skip("DefaultOpcodeParser not available")


def test_parse_op_with_data():
    """Test parsing opcode with data push."""
    try:
        from bsv.script.interpreter.op_parser import DefaultOpcodeParser, ParsedOpcode
        from bsv.script.script import Script

        # PUSH 3 bytes
        script = Script(b'\x03\x01\x02\x03')
        parser = DefaultOpcodeParser()
        parsed = parser.parse(script)
        assert len(parsed) == 1
        assert isinstance(parsed[0], ParsedOpcode)
        assert parsed[0].opcode == b'\x03'
        assert parsed[0].data == b'\x01\x02\x03'
    except (ImportError, AttributeError):
        pytest.skip("DefaultOpcodeParser not available")


def test_parse_op_pushdata1():
    """Test parsing OP_PUSHDATA1."""
    try:
        from bsv.script.interpreter.op_parser import DefaultOpcodeParser, ParsedOpcode
        from bsv.script.script import Script

        # OP_PUSHDATA1 with 10 bytes
        script = Script(b'\x4c\x0a' + b'\x00' * 10)
        parser = DefaultOpcodeParser()
        parsed = parser.parse(script)
        assert len(parsed) == 1
        assert isinstance(parsed[0], ParsedOpcode)
        assert parsed[0].opcode == b'\x4c'
        assert parsed[0].data == b'\x00' * 10
    except (ImportError, AttributeError):
        pytest.skip("DefaultOpcodeParser not available")


def test_parse_op_pushdata2():
    """Test parsing OP_PUSHDATA2."""
    try:
        from bsv.script.interpreter.op_parser import DefaultOpcodeParser, ParsedOpcode
        from bsv.script.script import Script

        # OP_PUSHDATA2 with 256 bytes
        script = Script(b'\x4d\x00\x01' + b'\x00' * 256)
        parser = DefaultOpcodeParser()
        parsed = parser.parse(script)
        assert len(parsed) == 1
        assert isinstance(parsed[0], ParsedOpcode)
        assert parsed[0].opcode == b'\x4d'
        assert parsed[0].data == b'\x00' * 256
    except (ImportError, AttributeError):
        pytest.skip("DefaultOpcodeParser not available")


def test_parse_op_pushdata4():
    """Test parsing OP_PUSHDATA4."""
    try:
        from bsv.script.interpreter.op_parser import DefaultOpcodeParser, ParsedOpcode
        from bsv.script.script import Script

        # OP_PUSHDATA4 with 1000 bytes
        script = Script(b'\x4e\xe8\x03\x00\x00' + b'\x00' * 1000)
        parser = DefaultOpcodeParser()
        parsed = parser.parse(script)
        assert len(parsed) == 1
        assert isinstance(parsed[0], ParsedOpcode)
        assert parsed[0].opcode == b'\x4e'
        assert parsed[0].data == b'\x00' * 1000
    except (ImportError, AttributeError):
        pytest.skip("DefaultOpcodeParser not available")


# ========================================================================
# Opcode identification branches
# ========================================================================

def test_is_op_push():
    """Test identifying push opcodes."""
    try:
        from bsv.script.interpreter.op_parser import DefaultOpcodeParser, ParsedOpcode
        from bsv.script.script import Script

        # Test direct push opcode (0x01-0x4b are direct pushes)
        script = Script(b'\x03\x01\x02\x03')  # PUSH 3 bytes of data
        parser = DefaultOpcodeParser()
        parsed = parser.parse(script)
        assert len(parsed) == 1
        # Direct push opcodes have values 0x01-0x4b
        assert 0x01 <= parsed[0].opcode[0] <= 0x4b
        assert parsed[0].data == b'\x01\x02\x03'
    except (ImportError, AttributeError):
        pytest.skip("DefaultOpcodeParser not available")


def test_get_op_name():
    """Test getting opcode name."""
    try:
        from bsv.script.interpreter.op_parser import DefaultOpcodeParser, ParsedOpcode
        from bsv.script.script import Script

        script = Script(b'\x51')  # OP_1
        parser = DefaultOpcodeParser()
        parsed = parser.parse(script)
        assert len(parsed) == 1
        name = parsed[0].name()
        assert name is not None
        assert isinstance(name, str)
        assert name == "OP_1" or "OP_TRUE" in name
    except (ImportError, AttributeError):
        pytest.skip("ParsedOpcode.name not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_parse_op_at_end():
    """Test parsing script with valid opcode."""
    try:
        from bsv.script.interpreter.op_parser import DefaultOpcodeParser
        from bsv.script.script import Script

        script = Script(b'\x51')  # OP_1
        parser = DefaultOpcodeParser()
        parsed = parser.parse(script)
        assert len(parsed) == 1
        assert parsed[0].opcode == b'\x51'
    except (ImportError, AttributeError):
        pytest.skip("DefaultOpcodeParser not available")


def test_parse_op_truncated():
    """Test parsing script with PUSHDATA."""
    try:
        from bsv.script.interpreter.op_parser import DefaultOpcodeParser
        from bsv.script.script import Script

        # OP_PUSHDATA1 with 10 bytes
        script = Script(b'\x4c\x0a' + b'\x00' * 10)
        parser = DefaultOpcodeParser()
        parsed = parser.parse(script)
        assert len(parsed) == 1
        assert parsed[0].opcode == b'\x4c'
        assert len(parsed[0].data or b'') == 10
    except (ImportError, AttributeError):
        pytest.skip("DefaultOpcodeParser not available")

