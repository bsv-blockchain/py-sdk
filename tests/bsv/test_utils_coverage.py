"""
Additional tests to improve coverage for utility modules.
"""

import pytest
import base64
from bsv.utils import Reader, Writer
from bsv.utils.script import get_pushdata_code, encode_pushdata, encode_int
from bsv.utils.encoding import BytesList, BytesHex, Bytes32Base64, Bytes33Hex, StringBase64, Signature
from bsv.constants import OpCode


class TestUtilsCoverage:
    """Test utility functions for better coverage."""

    def test_reader_operations(self):
        """Test Reader class operations."""
        data = b"Hello, World! This is test data for Reader."
        reader = Reader(data)

        # Test reading bytes
        assert reader.read_bytes(5) == b"Hello"
        assert reader.read_bytes(7) == b", World"

        # Test reading uints
        reader_small = Reader(b"\x01\x00\xFF\xFE")
        assert reader_small.read_uint8() == 1
        assert reader_small.read_uint8() == 0
        assert reader_small.read_uint16_le() == 0xFEFF  # Little endian

        # Test reading varints
        reader_varint = Reader(b"\x01")  # 1
        assert reader_varint.read_var_int_num() == 1

        # Test all integer reading methods
        test_data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
        reader_all = Reader(test_data)

        # Test signed/unsigned variants
        assert reader_all.read_int8() == 1
        assert reader_all.read_uint8() == 2

        # Test 16-bit big endian
        reader_16be = Reader(b"\x01\x02")
        assert reader_16be.read_uint16_be() == 0x0102
        reader_16be_int = Reader(b"\x01\x02")
        assert reader_16be_int.read_int16_be() == 0x0102

        # Test 16-bit little endian
        reader_16le = Reader(b"\x01\x02")
        assert reader_16le.read_uint16_le() == 0x0201
        reader_16le_int = Reader(b"\x01\x02")
        assert reader_16le_int.read_int16_le() == 0x0201

        # Test 32-bit variants
        reader_32_be = Reader(b"\x01\x02\x03\x04")
        assert reader_32_be.read_uint32_be() == 0x01020304
        reader_32_be_int = Reader(b"\x01\x02\x03\x04")
        assert reader_32_be_int.read_int32_be() == 0x01020304
        reader_32_le = Reader(b"\x01\x02\x03\x04")
        assert reader_32_le.read_uint32_le() == 0x04030201
        reader_32_le_int = Reader(b"\x01\x02\x03\x04")
        assert reader_32_le_int.read_int32_le() == 0x04030201

        # Test 64-bit variants
        reader_64_be = Reader(b"\x01\x02\x03\x04\x05\x06\x07\x08")
        assert reader_64_be.read_uint64_be() == 0x0102030405060708
        reader_64_le = Reader(b"\x01\x02\x03\x04\x05\x06\x07\x08")
        assert reader_64_le.read_uint64_le() == 0x0807060504030201

        # Test read_int method
        reader_int_big = Reader(b"\x01\x02\x03\x04")
        assert reader_int_big.read_int(4, 'big') == 0x01020304
        reader_int_little = Reader(b"\x01\x02\x03\x04")
        assert reader_int_little.read_int(4, 'little') == 0x04030201

        # Test read_reverse
        reader_rev = Reader(b"\x01\x02\x03\x04")
        assert reader_rev.read_reverse(4) == b"\x04\x03\x02\x01"

        # Test eof
        reader_eof = Reader(b"\x01")
        assert not reader_eof.eof()
        reader_eof.read(1)
        assert reader_eof.eof()

        # Test varint edge cases
        reader_varint_large = Reader(b"\xfd\x01\x00")  # 253 + 2 bytes
        assert reader_varint_large.read_var_int_num() == 1

        reader_varint_huge = Reader(b"\xff\x01\x00\x00\x00\x00\x00\x00\x00")  # 255 + 8 bytes
        assert reader_varint_huge.read_var_int_num() == 1

        # Test read_var_int (returns bytes)
        reader_varint_bytes = Reader(b"\xfd\x01\x00")
        result = reader_varint_bytes.read_var_int()
        assert result == b"\xfd\x01\x00"

    def test_writer_operations(self):
        """Test Writer class operations."""
        writer = Writer()

        # Test writing bytes
        writer.write(b"Hello")
        writer.write(b", World")

        # Test writing uints
        writer.write_uint8(42)
        writer.write_uint16_le(0x1234)

        # Test writing varints
        writer.write_var_int_num(1)
        writer.write_var_int_num(1000)

        result = writer.to_bytes()
        assert len(result) > 0

        # Verify we can read back what we wrote
        reader = Reader(result)
        assert reader.read_bytes(5) == b"Hello"
        assert reader.read_bytes(7) == b", World"

        # Test all integer writing methods
        writer_all = Writer()

        # Test signed/unsigned variants
        writer_all.write_int8(-1)
        writer_all.write_uint8(255)

        # Test 16-bit variants
        writer_all.write_uint16_be(0x0102)
        writer_all.write_int16_be(-0x0102)
        writer_all.write_uint16_le(0x0102)
        writer_all.write_int16_le(-0x0102)

        # Test 32-bit variants
        writer_all.write_uint32_be(0x01020304)
        writer_all.write_int32_be(-0x01020304)
        writer_all.write_uint32_le(0x01020304)
        writer_all.write_int32_le(-0x01020304)

        # Test 64-bit variants
        writer_all.write_uint64_be(0x0102030405060708)
        writer_all.write_uint64_le(0x0102030405060708)

        # Test write_reverse
        writer_rev = Writer()
        writer_rev.write_reverse(b"\x01\x02\x03\x04")
        assert writer_rev.to_bytes() == b"\x04\x03\x02\x01"

        # Test var_int_num static method
        varint_1 = Writer.var_int_num(1)
        assert varint_1 == b"\x01"

        varint_large = Writer.var_int_num(1000)
        assert len(varint_large) == 3  # Should be \xfd + 2 bytes
        assert varint_large[0] == 0xfd

        # Test method chaining (fluent interface)
        chained = Writer()
        result = chained.write(b"test").write_uint8(1).write_uint16_le(1000)
        assert result is chained  # Should return self

    def test_script_utility_functions(self):
        """Test script utility functions."""
        # Test get_pushdata_code
        assert get_pushdata_code(10) == b"\x0a"  # Just push 10 bytes
        assert get_pushdata_code(100) == OpCode.OP_PUSHDATA1.value + b"\x64"  # PUSHDATA1 + length
        assert get_pushdata_code(1000) == OpCode.OP_PUSHDATA2.value + b"\xe8\x03"  # PUSHDATA2 + length

        # Test encode_pushdata
        data = b"Hello, World!"
        encoded = encode_pushdata(data)
        assert isinstance(encoded, bytes)
        assert len(encoded) > len(data)  # Should include length prefix

        # Test encode_int
        assert encode_int(0) == OpCode.OP_0  # Returns OP_0 for zero
        result_1 = encode_int(1)
        assert isinstance(result_1, bytes)
        result_neg1 = encode_int(-1)
        assert isinstance(result_neg1, bytes)


class TestConstantsCoverage:
    """Test constants and enums for coverage."""

    def test_op_values(self):
        """Test that all opcodes have valid values."""
        # Test some key opcodes
        assert OpCode.OP_0.value == b'\x00'
        assert OpCode.OP_1.value == b'\x51'
        assert OpCode.OP_DUP.value == b'\x76'
        assert OpCode.OP_EQUAL.value == b'\x87'
        assert OpCode.OP_CHECKSIG.value == b'\xac'

        # Test that opcodes can be created from bytes
        assert OpCode(b'\x00') == OpCode.OP_0
        assert OpCode(b'\x51') == OpCode.OP_1

    def test_op_names(self):
        """Test opcode name access."""
        # Test that names are accessible
        assert hasattr(OpCode.OP_0, 'name')
        assert hasattr(OpCode.OP_TRUE, 'name')  # OP_1 is aliased to OP_TRUE

        # Test string representation
        assert str(OpCode.OP_0) == "OpCode.OP_0"
        assert str(OpCode.OP_TRUE) == "OpCode.OP_TRUE"

    def test_encoding_classes(self):
        """Test encoding utility classes."""
        # Test BytesList
        data = b"hello"
        bytes_list = BytesList(data)
        json_str = bytes_list.to_json()
        assert json_str == '[104, 101, 108, 108, 111]'
        restored = BytesList.from_json(json_str)
        assert restored == data

        # Test BytesHex
        bytes_hex = BytesHex(data)
        json_str = bytes_hex.to_json()
        assert json_str == '"68656c6c6f"'
        restored = BytesHex.from_json(json_str)
        assert restored == data

        # Test Bytes32Base64
        data_32 = b"a" * 32
        bytes_32 = Bytes32Base64(data_32)
        json_str = bytes_32.to_json()
        expected_b64 = base64.b64encode(data_32).decode('ascii')
        assert json_str == f'"{expected_b64}"'
        restored = Bytes32Base64.from_json(json_str)
        assert restored == data_32

        # Test Bytes32Base64 with wrong length
        with pytest.raises(ValueError):
            Bytes32Base64(b"short")

        # Test Bytes33Hex
        data_33 = b"b" * 33
        bytes_33 = Bytes33Hex(data_33)
        json_str = bytes_33.to_json()
        assert json_str == f'"{data_33.hex()}"'
        restored = Bytes33Hex.from_json(json_str)
        assert restored == data_33

        # Test Bytes33Hex with wrong length
        with pytest.raises(ValueError):
            Bytes33Hex(b"short")

        # Test StringBase64
        test_bytes = b"test data"
        str_b64 = StringBase64.from_array(test_bytes)
        assert str_b64 == base64.b64encode(test_bytes).decode('ascii')
        restored_bytes = str_b64.to_array()
        assert restored_bytes == test_bytes

        # Test Signature
        sig_data = b"signature_bytes"
        sig = Signature(sig_data)
        json_str = sig.to_json()
        assert json_str == '[115, 105, 103, 110, 97, 116, 117, 114, 101, 95, 98, 121, 116, 101, 115]'
        restored = Signature.from_json(json_str)
        assert restored.sig_bytes == sig_data
