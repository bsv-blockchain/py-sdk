"""
TDD tests for hash opcodes in operations.py.

Following TDD approach: write tests first that demonstrate expected behavior,
then implement the opcodes to make tests pass.

References:
- Go SDK: go-sdk/script/interpreter/operations.go
- TypeScript SDK: ts-sdk/src/script/Spend.ts
"""

import hashlib
import pytest
from bsv.script.interpreter.operations import (
    op_ripemd160, op_sha1, op_sha256, op_hash160, op_hash256
)
from bsv.script.interpreter.op_parser import ParsedOpcode
from bsv.script.interpreter.stack import Stack
from bsv.script.interpreter.config import BeforeGenesisConfig
from bsv.script.interpreter.errs import Error, ErrorCode
from bsv.constants import OpCode


class MockThread:
    """Mock Thread for testing opcodes without full engine setup."""

    def __init__(self):
        self.dstack = Stack(BeforeGenesisConfig())
        self.astack = Stack(BeforeGenesisConfig())


class TestHashOpcodes:
    """TDD tests for hash opcodes."""

    def setup_method(self):
        """Set up fresh thread for each test."""
        self.thread = MockThread()

    def test_op_ripemd160_success(self):
        """Test OP_RIPEMD160."""
        # Setup: push some data
        test_data = b"hello world"
        self.thread.dstack.push_byte_array(test_data)

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_RIPEMD160, b"")
        err = op_ripemd160(pop, self.thread)

        # Verify: should push RIPEMD160 hash
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_byte_array()
        expected = hashlib.new('ripemd160', test_data).digest()
        assert result == expected

    def test_op_ripemd160_stack_underflow(self):
        """Test OP_RIPEMD160 with empty stack."""
        assert self.thread.dstack.depth() == 0

        pop = ParsedOpcode(OpCode.OP_RIPEMD160, b"")
        err = op_ripemd160(pop, self.thread)

        assert err is not None
        assert err.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_sha1_success(self):
        """Test OP_SHA1."""
        # Setup: push some data
        test_data = b"hello world"
        self.thread.dstack.push_byte_array(test_data)

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_SHA1, b"")
        err = op_sha1(pop, self.thread)

        # Verify: should push SHA1 hash
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_byte_array()
        # noqa: S324 - SHA1 is required by Bitcoin Script OP_SHA1 opcode, not for security
        expected = hashlib.sha1(test_data).digest()  # noqa: S324
        assert result == expected

    def test_op_sha256_success(self):
        """Test OP_SHA256."""
        # Setup: push some data
        test_data = b"hello world"
        self.thread.dstack.push_byte_array(test_data)

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_SHA256, b"")
        err = op_sha256(pop, self.thread)

        # Verify: should push SHA256 hash
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_byte_array()
        expected = hashlib.sha256(test_data).digest()
        assert result == expected

    def test_op_hash160_success(self):
        """Test OP_HASH160 - RIPEMD160(SHA256(data))."""
        # Setup: push some data
        test_data = b"hello world"
        self.thread.dstack.push_byte_array(test_data)

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_HASH160, b"")
        err = op_hash160(pop, self.thread)

        # Verify: should push HASH160 (RIPEMD160 of SHA256)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_byte_array()
        sha256_hash = hashlib.sha256(test_data).digest()
        expected = hashlib.new('ripemd160', sha256_hash).digest()
        assert result == expected

    def test_op_hash256_success(self):
        """Test OP_HASH256 - SHA256(SHA256(data))."""
        # Setup: push some data
        test_data = b"hello world"
        self.thread.dstack.push_byte_array(test_data)

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_HASH256, b"")
        err = op_hash256(pop, self.thread)

        # Verify: should push HASH256 (double SHA256)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_byte_array()
        expected = hashlib.sha256(hashlib.sha256(test_data).digest()).digest()
        assert result == expected

    def test_op_hash160_empty_data(self):
        """Test OP_HASH160 with empty data."""
        # Setup: push empty data
        test_data = b""
        self.thread.dstack.push_byte_array(test_data)

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_HASH160, b"")
        err = op_hash160(pop, self.thread)

        # Verify: should push hash of empty data
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_byte_array()
        sha256_hash = hashlib.sha256(test_data).digest()
        expected = hashlib.new('ripemd160', sha256_hash).digest()
        assert result == expected
        # HASH160 of empty should be: RIPEMD160(SHA256(""))
        assert len(result) == 20  # RIPEMD160 produces 20 bytes
