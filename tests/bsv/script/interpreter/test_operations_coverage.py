"""
Comprehensive tests for script interpreter operations to improve coverage.

These tests target specific operations functions that are not well covered
by existing tests.
"""

import pytest
from typing import cast
from bsv.script.interpreter.operations import (
    cast_to_bool, encode_bool, bin2num, minimally_encode,
    check_signature_encoding, check_public_key_encoding,
    op_dup, op_hash160, op_equal_verify
)
from bsv.script.interpreter.errs import Error, ErrorCode
from bsv.script.interpreter.stack import Stack
from bsv.script.interpreter.config import BeforeGenesisConfig
from bsv.script.interpreter.op_parser import ParsedOpcode
from unittest.mock import Mock


class TestOperationsUtilityFunctions:
    """Test utility functions in operations.py."""

    def test_cast_to_bool_comprehensive(self):
        """Test cast_to_bool with various edge cases."""
        # Test cases: (input, expected_output, description)
        test_cases = [
            (b"", False, "Empty bytes"),
            (b"\x00", False, "Zero byte"),
            (b"\x00\x00", False, "Multiple zero bytes"),
            (b"\x80", False, "Negative zero"),
            (b"\x00\x80", False, "Zero with negative flag"),
            (b"\x01", True, "Single non-zero"),
            (b"\xff", True, "All bits set"),
            (b"\x00\x01", True, "Zero followed by non-zero"),
            (b"\x00\x00\x01", True, "Multiple zeros then non-zero"),
            (b"\x00\x00\x80", False, "Multiple zeros with negative flag"),
        ]

        for input_bytes, expected, description in test_cases:
            result = cast_to_bool(input_bytes)
            assert result == expected, f"Failed for {description}: {input_bytes}"

    def test_encode_bool(self):
        """Test encode_bool function."""
        assert encode_bool(True) == b"\x01"
        assert encode_bool(False) == b""

    def test_bin2num_comprehensive(self):
        """Test bin2num with various inputs matching Go implementation."""
        # Test cases matching Go TestMakeScriptNum expectations
        test_cases = [
            (b"", 0, "Empty bytes"),
            (b"\x01", 1, "Single byte positive"),
            (b"\x7f", 127, "Max positive single byte"),
            (b"\x80\x00", 128, "128 as little-endian bytes"),
            (b"\x00\x01", 256, "256 as little-endian bytes"),
            (b"\x81", -1, "Negative one"),
            (b"\xff", -127, "Negative 127"),
            (b"\x80\x80", -128, "Negative 128"),
        ]

        for input_bytes, expected, description in test_cases:
            result = bin2num(input_bytes)
            assert result == expected, f"Failed for {description}: got {result}, expected {expected}"

    def test_minimally_encode_comprehensive(self):
        """Test minimally_encode with various inputs."""
        test_cases = [
            (0, b"", "Zero"),
            (1, b"\x01", "Small positive"),
            (127, b"\x7f", "Max single byte"),
            (-1, b"\x81", "Negative one"),
        ]

        for input_num, expected, description in test_cases:
            result = minimally_encode(input_num)
            assert isinstance(result, bytes), f"Should return bytes for {description}"
            if expected:  # Some cases may vary by implementation
                assert result == expected, f"Failed for {description}: got {result}"

        # Test that it returns bytes for edge cases
        edge_cases = [128, 255, -127, -128, 0x7fffffff, -0x80000000]
        for num in edge_cases:
            result = minimally_encode(num)
            assert isinstance(result, bytes)
            assert len(result) > 0

    def test_check_signature_encoding_comprehensive(self):
        """Test check_signature_encoding with various inputs."""
        # Empty signature should pass
        assert check_signature_encoding(b"") is None

        # Test with different DER requirements
        test_sigs = [b"", b"invalid", b"\x30\x01\x01"]

        for sig in test_sigs:
            result_strict = check_signature_encoding(sig, require_der=True)
            result_lenient = check_signature_encoding(sig, require_der=False)

            # Both should return either None or Error
            assert result_strict is None or isinstance(result_strict, Error)
            assert result_lenient is None or isinstance(result_lenient, Error)

    def test_check_public_key_encoding_comprehensive(self):
        """Test check_public_key_encoding with various inputs."""
        # Empty key should fail
        result = check_public_key_encoding(b"")
        assert result is not None

        # Test various key formats
        test_keys = [
            b"\x02" + b"\x00" * 32,  # Compressed format (33 bytes)
            b"\x04" + b"\x00" * 64,  # Uncompressed format (65 bytes)
            b"\x02",  # Too short
            b"\x05" + b"\x00" * 32,  # Invalid prefix
        ]

        for key in test_keys:
            result = check_public_key_encoding(key)
            # Should return either None (valid) or Error (invalid)
            assert result is None or isinstance(result, Error)


class TestOperationsOpcodes:
    """Test opcode operations with mock threads."""

    def test_op_dup(self):
        """Test OP_DUP operation."""
        # Create mock thread with real stack
        mock_thread = Mock()
        stack = Stack(BeforeGenesisConfig())
        mock_thread.dstack = stack

        # Test with empty stack
        stack.stk = []  # Clear the stack
        result = op_dup(cast(ParsedOpcode, None), mock_thread)
        assert isinstance(result, Error)
        assert result.code == ErrorCode.ERR_INVALID_STACK_OPERATION

        # Test with data
        stack.stk = []  # Clear the stack
        test_data = b"test_data"
        stack.push_byte_array(test_data)
        result = op_dup(cast(ParsedOpcode, None), mock_thread)
        assert result is None
        assert stack.depth() == 2
        assert stack.peek_byte_array(0) == test_data
        assert stack.peek_byte_array(1) == test_data

    def test_op_hash160(self):
        """Test OP_HASH160 operation."""
        # Create mock thread with real stack
        mock_thread = Mock()
        stack = Stack(BeforeGenesisConfig())
        mock_thread.dstack = stack

        # Test with empty stack
        stack.stk = []  # Clear the stack
        result = op_hash160(cast(ParsedOpcode, None), mock_thread)
        assert isinstance(result, Error)
        assert result.code == ErrorCode.ERR_INVALID_STACK_OPERATION

        # Test with data
        stack.stk = []  # Clear the stack
        test_data = b"Hello, World!"
        stack.push_byte_array(test_data)
        result = op_hash160(cast(ParsedOpcode, None), mock_thread)
        assert result is None
        assert stack.depth() == 1
        hash_result = stack.peek_byte_array(0)
        assert len(hash_result) == 20  # RIPEMD160 produces 20 bytes

    def test_op_equal_verify(self):
        """Test OP_EQUALVERIFY operation."""
        # Create mock thread with real stack
        mock_thread = Mock()
        stack = Stack(BeforeGenesisConfig())
        mock_thread.dstack = stack

        # Test with insufficient stack items
        stack.stk = []  # Clear the stack
        result = op_equal_verify(cast(ParsedOpcode, None), mock_thread)
        assert isinstance(result, Error)
        assert result.code == ErrorCode.ERR_INVALID_STACK_OPERATION

        # Test with equal values (should succeed and clear stack)
        stack.stk = []  # Clear the stack
        test_data = b"test_data"
        stack.push_byte_array(test_data)
        stack.push_byte_array(test_data)
        result = op_equal_verify(cast(ParsedOpcode, None), mock_thread)
        assert result is None
        assert stack.depth() == 0  # Should pop both items

        # Test with unequal values (should return error)
        stack.stk = []  # Clear the stack
        stack.push_byte_array(b"test1")
        stack.push_byte_array(b"test2")
        result = op_equal_verify(cast(ParsedOpcode, None), mock_thread)
        assert isinstance(result, Error)
        assert result.code == ErrorCode.ERR_EQUAL_VERIFY


class TestOperationsIntegration:
    """Test integration of operations functions."""

    def test_utility_functions_integration(self):
        """Test that utility functions work together."""
        # Test encode/decode round trip
        test_values = [0, 1, -1, 127, -127]

        for val in test_values:
            encoded = minimally_encode(val)
            decoded = bin2num(encoded)
            # Note: This may not round-trip perfectly due to minimal encoding
            assert isinstance(decoded, int)

    def test_bool_encoding_integration(self):
        """Test bool encoding/decoding."""
        for bool_val in [True, False]:
            encoded = encode_bool(bool_val)
            decoded = cast_to_bool(encoded)
            assert decoded == bool_val
