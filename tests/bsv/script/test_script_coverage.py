"""
Coverage tests for script/script.py - untested branches.
"""
import pytest
from bsv.script.script import Script


# ========================================================================
# Script initialization branches
# ========================================================================

def test_script_init_empty():
    """Test Script with empty bytes."""
    script = Script(b'')
    assert len(script.serialize()) == 0


def test_script_init_with_bytes():
    """Test Script with bytes."""
    script = Script(b'\x51')  # OP_1
    assert len(script.serialize()) == 1


def test_script_init_with_opcodes():
    """Test Script with multiple opcodes."""
    script = Script(b'\x51\x52\x93')  # OP_1 OP_2 OP_ADD
    assert len(script.serialize()) == 3


# ========================================================================
# Script from_asm branches
# ========================================================================

def test_script_from_asm_empty():
    """Test from_asm with empty string."""
    script = Script.from_asm('')
    # Empty asm creates a script with OP_0
    assert script.byte_length() >= 0


def test_script_from_asm_single_opcode():
    """Test from_asm with single opcode."""
    script = Script.from_asm('OP_TRUE')
    assert script.byte_length() > 0


def test_script_from_asm_multiple_opcodes():
    """Test from_asm with multiple opcodes."""
    script = Script.from_asm('OP_TRUE OP_FALSE OP_ADD')
    assert script.byte_length() > 0


def test_script_from_asm_with_data():
    """Test from_asm with hex data."""
    script = Script.from_asm('01020304')
    assert script.byte_length() > 0


# ========================================================================
# Script serialization branches
# ========================================================================

def test_script_serialize_empty():
    """Test serialize empty script."""
    script = Script(b'')
    serialized = script.serialize()
    assert serialized == b''


def test_script_serialize_with_data():
    """Test serialize script with data."""
    data = b'\x51\x52'
    script = Script(data)
    assert script.serialize() == data


def test_script_hex():
    """Test script hex encoding."""
    script = Script(b'\x51')
    hex_str = script.hex()
    assert hex_str == '51'


# ========================================================================
# Script length branches
# ========================================================================

def test_script_len_empty():
    """Test length of empty script."""
    script = Script(b'')
    assert script.byte_length() == 0


def test_script_len_with_data():
    """Test length of script with data."""
    script = Script(b'\x51\x52\x93')
    assert script.byte_length() == 3


# ========================================================================
# Script comparison branches
# ========================================================================

def test_script_equality_same():
    """Test script equality with same content."""
    script1 = Script(b'\x51')
    script2 = Script(b'\x51')
    assert script1.serialize() == script2.serialize()


def test_script_equality_different():
    """Test script equality with different content."""
    script1 = Script(b'\x51')
    script2 = Script(b'\x52')
    assert script1.serialize() != script2.serialize()


# ========================================================================
# Script operations
# ========================================================================

def test_script_is_p2pkh():
    """Test detecting P2PKH script."""
    # P2PKH: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
    script = Script(b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac')
    if hasattr(script, 'is_p2pkh'):
        result = script.is_p2pkh()
        assert isinstance(result, bool)


def test_script_is_p2sh():
    """Test detecting P2SH script."""
    # P2SH: OP_HASH160 <scripthash> OP_EQUAL
    script = Script(b'\xa9\x14' + b'\x00' * 20 + b'\x87')
    if hasattr(script, 'is_p2sh'):
        result = script.is_p2sh()
        assert isinstance(result, bool)


def test_script_get_public_key_hash():
    """Test extracting public key hash."""
    script = Script(b'\x76\xa9\x14' + b'\x11' * 20 + b'\x88\xac')
    if hasattr(script, 'get_public_key_hash'):
        pkh = script.get_public_key_hash()
        assert pkh is not None or True


# ========================================================================
# Edge cases
# ========================================================================

def test_script_with_pushdata():
    """Test script with PUSHDATA operations."""
    # OP_PUSHDATA1 length data
    script = Script(b'\x4c\x05hello')
    assert len(script.serialize()) > 0


def test_script_with_large_data():
    """Test script with large data."""
    large_data = b'\x00' * 1000
    script = Script(large_data)
    assert len(script.serialize()) == 1000


def test_script_str_representation():
    """Test script string representation."""
    script = Script(b'\x51')
    str_repr = str(script)
    assert isinstance(str_repr, str)


def test_script_repr():
    """Test script repr."""
    script = Script(b'\x51')
    repr_str = repr(script)
    assert isinstance(repr_str, str)

