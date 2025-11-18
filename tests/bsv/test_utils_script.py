"""
Test script-related functions in bsv/utils package
"""

import pytest
from bsv.utils import get_pushdata_code, encode_pushdata, encode_int, text_digest
from bsv.constants import OpCode


class TestGetPushdataCode:
    """Test get_pushdata_code() function."""
    
    def test_pushdata_code_zero_bytes(self):
        """Test pushdata code for zero bytes."""
        result = get_pushdata_code(0)
        assert result == b'\x00'
    
    def test_pushdata_code_one_byte(self):
        """Test pushdata code for one byte."""
        result = get_pushdata_code(1)
        assert result == b'\x01'
    
    def test_pushdata_code_max_direct(self):
        """Test pushdata code for max direct push (75 bytes)."""
        result = get_pushdata_code(0x4b)
        assert result == b'\x4b'
        assert len(result) == 1
    
    def test_pushdata_code_pushdata1_min(self):
        """Test pushdata code for min OP_PUSHDATA1 (76 bytes)."""
        result = get_pushdata_code(0x4c)
        assert result[:1] == OpCode.OP_PUSHDATA1
        assert len(result) == 2
    
    def test_pushdata_code_pushdata1_max(self):
        """Test pushdata code for max OP_PUSHDATA1 (255 bytes)."""
        result = get_pushdata_code(0xff)
        assert result[:1] == OpCode.OP_PUSHDATA1
        assert result[1:] == b'\xff'
        assert len(result) == 2
    
    def test_pushdata_code_pushdata2_min(self):
        """Test pushdata code for min OP_PUSHDATA2 (256 bytes)."""
        result = get_pushdata_code(0x100)
        assert result[:1] == OpCode.OP_PUSHDATA2
        assert len(result) == 3
    
    def test_pushdata_code_pushdata2_max(self):
        """Test pushdata code for max OP_PUSHDATA2 (65535 bytes)."""
        result = get_pushdata_code(0xffff)
        assert result[:1] == OpCode.OP_PUSHDATA2
        assert len(result) == 3
    
    def test_pushdata_code_pushdata4_min(self):
        """Test pushdata code for min OP_PUSHDATA4 (65536 bytes)."""
        result = get_pushdata_code(0x10000)
        assert result[:1] == OpCode.OP_PUSHDATA4
        assert len(result) == 5
    
    def test_pushdata_code_pushdata4_large(self):
        """Test pushdata code for large PUSHDATA4 value."""
        result = get_pushdata_code(1000000)
        assert result[:1] == OpCode.OP_PUSHDATA4
        assert len(result) == 5
    
    def test_pushdata_code_pushdata4_max(self):
        """Test pushdata code for max OP_PUSHDATA4 (2^32-1 bytes)."""
        result = get_pushdata_code(0xffffffff)
        assert result[:1] == OpCode.OP_PUSHDATA4
        assert len(result) == 5
    
    def test_pushdata_code_too_large_raises(self):
        """Test that data too large raises ValueError."""
        with pytest.raises(ValueError, match="data too long"):
            get_pushdata_code(2**32)
    
    @pytest.mark.parametrize("byte_length,expected_len", [
        (0, 1),
        (0x4b, 1),     # max direct
        (0x4c, 2),     # min PUSHDATA1
        (0xff, 2),     # max PUSHDATA1
        (0x100, 3),    # min PUSHDATA2
        (0xffff, 3),   # max PUSHDATA2
        (0x10000, 5),  # min PUSHDATA4
    ])
    def test_pushdata_code_lengths(self, byte_length, expected_len):
        """Test pushdata code returns correct length."""
        result = get_pushdata_code(byte_length)
        assert len(result) == expected_len


class TestEncodePushdata:
    """Test encode_pushdata() function."""
    
    def test_encode_pushdata_empty_minimal(self):
        """Test encoding empty data with minimal push."""
        result = encode_pushdata(b'', minimal_push=True)
        assert result == OpCode.OP_0
    
    def test_encode_pushdata_empty_non_minimal_raises(self):
        """Test encoding empty data non-minimal raises."""
        with pytest.raises(AssertionError, match="empty pushdata"):
            encode_pushdata(b'', minimal_push=False)
    
    def test_encode_pushdata_single_byte(self):
        """Test encoding single byte."""
        result = encode_pushdata(b'\x42')
        assert len(result) == 2  # length prefix + data
    
    def test_encode_pushdata_op_1_minimal(self):
        """Test encoding 1 uses OP_1 with minimal push."""
        result = encode_pushdata(b'\x01', minimal_push=True)
        assert result == bytes([OpCode.OP_1[0]])
    
    def test_encode_pushdata_op_2_minimal(self):
        """Test encoding 2 uses OP_2 with minimal push."""
        result = encode_pushdata(b'\x02', minimal_push=True)
        assert result == bytes([OpCode.OP_1[0] + 1])
    
    def test_encode_pushdata_op_16_minimal(self):
        """Test encoding 16 uses OP_16 with minimal push."""
        result = encode_pushdata(b'\x10', minimal_push=True)
        assert result == bytes([OpCode.OP_1[0] + 15])
    
    def test_encode_pushdata_op_1negate_minimal(self):
        """Test encoding 0x81 uses OP_1NEGATE with minimal push."""
        result = encode_pushdata(b'\x81', minimal_push=True)
        assert result == OpCode.OP_1NEGATE
    
    def test_encode_pushdata_op_1_non_minimal(self):
        """Test encoding 1 without minimal push."""
        result = encode_pushdata(b'\x01', minimal_push=False)
        # Should be: length_byte + data
        assert len(result) == 2
        assert result[1:] == b'\x01'
    
    def test_encode_pushdata_small_data(self):
        """Test encoding small data."""
        data = b'Hello'
        result = encode_pushdata(data)
        assert result[0] == len(data)
        assert result[1:] == data
    
    def test_encode_pushdata_75_bytes(self):
        """Test encoding max direct push (75 bytes)."""
        data = b'x' * 75
        result = encode_pushdata(data)
        assert result[0] == 75
        assert result[1:] == data
    
    def test_encode_pushdata_76_bytes(self):
        """Test encoding 76 bytes uses OP_PUSHDATA1."""
        data = b'x' * 76
        result = encode_pushdata(data)
        assert result[0:1] == OpCode.OP_PUSHDATA1
        assert result[1] == 76
        assert result[2:] == data
    
    def test_encode_pushdata_256_bytes(self):
        """Test encoding 256 bytes uses OP_PUSHDATA2."""
        data = b'x' * 256
        result = encode_pushdata(data)
        assert result[0:1] == OpCode.OP_PUSHDATA2
        assert len(result) == 256 + 3  # data + opcode + 2-byte length
    
    def test_encode_pushdata_large_data(self):
        """Test encoding large data."""
        data = b'x' * 1000
        result = encode_pushdata(data)
        assert len(result) > len(data)
        assert data in result


class TestEncodeInt:
    """Test encode_int() function."""
    
    def test_encode_int_zero(self):
        """Test encoding zero."""
        result = encode_int(0)
        assert result == OpCode.OP_0
    
    def test_encode_int_positive_one(self):
        """Test encoding positive one."""
        result = encode_int(1)
        # Should be minimal: OP_1
        assert result == bytes([OpCode.OP_1[0]])
    
    def test_encode_int_positive_small(self):
        """Test encoding small positive integer."""
        result = encode_int(5)
        # Should use OP_1 + 4 = OP_5
        assert result == bytes([OpCode.OP_1[0] + 4])
    
    def test_encode_int_positive_16(self):
        """Test encoding 16."""
        result = encode_int(16)
        # Should use OP_16
        assert result == bytes([OpCode.OP_1[0] + 15])
    
    def test_encode_int_positive_17(self):
        """Test encoding 17 (beyond OP_16)."""
        result = encode_int(17)
        # Should encode as pushdata
        assert len(result) > 1
    
    def test_encode_int_negative_one(self):
        """Test encoding negative one."""
        result = encode_int(-1)
        # Should be OP_1NEGATE
        assert result == OpCode.OP_1NEGATE
    
    def test_encode_int_negative_two(self):
        """Test encoding negative two."""
        result = encode_int(-2)
        # Should encode as pushdata with high bit set
        assert len(result) > 1
    
    def test_encode_int_large_positive(self):
        """Test encoding large positive integer."""
        result = encode_int(1000)
        assert len(result) > 1
        # Check it's encoded as pushdata
        assert result[0] in range(1, 76) or result[0:1] == OpCode.OP_PUSHDATA1
    
    def test_encode_int_large_negative(self):
        """Test encoding large negative integer."""
        result = encode_int(-1000)
        assert len(result) > 1
    
    def test_encode_int_max_positive(self):
        """Test encoding large positive number."""
        result = encode_int(2**31 - 1)
        assert isinstance(result, bytes)
        assert len(result) > 1
    
    def test_encode_int_max_negative(self):
        """Test encoding large negative number."""
        result = encode_int(-(2**31))
        assert isinstance(result, bytes)
        assert len(result) > 1
    
    @pytest.mark.parametrize("num", [
        0, 1, 2, 5, 16,  # Special opcodes
        17, 100, 255, 256,  # Regular positive
        -1, -2, -100, -255,  # Negative
    ])
    def test_encode_int_various_values(self, num):
        """Test encoding various integer values."""
        result = encode_int(num)
        assert isinstance(result, bytes)
        assert len(result) > 0
    
    def test_encode_int_requires_padding_byte(self):
        """Test encoding value that requires padding byte."""
        # Value where high bit is set, needs padding
        result = encode_int(0x80)
        # Should have padding byte to prevent sign misinterpretation
        assert len(result) > 2


class TestTextDigest:
    """Test text_digest() function."""
    
    def test_text_digest_simple(self):
        """Test generating text digest."""
        result = text_digest("Hello")
        assert isinstance(result, bytes)
        # Should contain Bitcoin Signed Message header
        assert b'Bitcoin Signed Message:\n' in result
        assert b'Hello' in result
    
    def test_text_digest_empty(self):
        """Test generating digest for empty text."""
        result = text_digest("")
        assert isinstance(result, bytes)
        assert b'Bitcoin Signed Message:\n' in result
    
    def test_text_digest_structure(self):
        """Test text digest structure."""
        result = text_digest("Test")
        # Should have varint length prefix for message and text
        assert len(result) > 10
        assert b'Bitcoin Signed Message:\n' in result
        assert b'Test' in result
    
    def test_text_digest_unicode(self):
        """Test text digest with unicode."""
        text = "世界"
        result = text_digest(text)
        assert isinstance(result, bytes)
        assert text.encode('utf-8') in result
    
    def test_text_digest_long_text(self):
        """Test text digest with long text."""
        text = "x" * 10000
        result = text_digest(text)
        assert len(result) > 10000
        assert text.encode('utf-8') in result
    
    @pytest.mark.parametrize("text", [
        "",
        "a",
        "Hello World",
        "Test\nMultiple\nLines",
        "Unicode: 你好",
        "Numbers: 12345",
        "Special: !@#$%^&*()",
    ])
    def test_text_digest_various_inputs(self, text):
        """Test text digest with various inputs."""
        result = text_digest(text)
        assert isinstance(result, bytes)
        assert len(result) > 0
        if text:  # Non-empty text should appear in digest
            assert text.encode('utf-8') in result

