"""
TDD tests for stack manipulation opcodes in operations.py.

Following TDD approach: write tests first that demonstrate expected behavior,
then implement the opcodes to make tests pass.

References:
- Go SDK: go-sdk/script/interpreter/operations.go
- TypeScript SDK: ts-sdk/src/script/Spend.ts
"""

import pytest
from bsv.script.interpreter.operations import (
    opcode_drop, opcode_dup, opcode_nip, opcode_over,
    opcode_pick, opcode_roll, opcode_rot, opcode_swap,
    opcode_tuck, opcode_2drop, opcode_2dup, opcode_3dup,
    opcode_2over, opcode_2rot, opcode_2swap, opcode_ifdup,
    opcode_depth, opcode_size
)
from bsv.script.interpreter.opcode_parser import ParsedOpcode
from bsv.script.interpreter.stack import Stack
from bsv.script.interpreter.config import BeforeGenesisConfig
from bsv.script.interpreter.errs import Error, ErrorCode
from bsv.constants import OpCode


class MockThread:
    """Mock Thread for testing opcodes without full engine setup."""

    def __init__(self):
        self.dstack = Stack(BeforeGenesisConfig())
        self.astack = Stack(BeforeGenesisConfig())


class TestStackManipulationOpcodes:
    """TDD tests for stack manipulation opcodes."""

    def setup_method(self):
        """Set up fresh thread for each test."""
        self.thread = MockThread()

    def test_opcode_drop_success(self):
        """Test OP_DROP - removes top stack item."""
        # Setup: push an item
        self.thread.dstack.push_byte_array(b"test_data")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_DROP, b"")
        err = opcode_drop(pop, self.thread)

        # Verify: stack should be empty, no error
        assert err is None
        assert self.thread.dstack.depth() == 0

    def test_opcode_drop_stack_underflow(self):
        """Test OP_DROP with empty stack - should fail."""
        # Setup: empty stack
        assert self.thread.dstack.depth() == 0

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_DROP, b"")
        err = opcode_drop(pop, self.thread)

        # Verify: should return error
        assert err is not None
        assert err.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_opcode_dup_success(self):
        """Test OP_DUP - duplicates top stack item."""
        # Setup: push an item
        test_data = b"duplicate_me"
        self.thread.dstack.push_byte_array(test_data)

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_DUP, b"")
        err = opcode_dup(pop, self.thread)

        # Verify: should have two identical items, no error
        assert err is None
        assert self.thread.dstack.depth() == 2
        assert self.thread.dstack.pop_byte_array() == test_data
        assert self.thread.dstack.pop_byte_array() == test_data

    def test_opcode_dup_stack_underflow(self):
        """Test OP_DUP with empty stack - should fail."""
        # Setup: empty stack
        assert self.thread.dstack.depth() == 0

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_DUP, b"")
        err = opcode_dup(pop, self.thread)

        # Verify: should return error
        assert err is not None
        assert err.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_opcode_nip_success(self):
        """Test OP_NIP - removes second-to-top stack item."""
        # Setup: push two items
        self.thread.dstack.push_byte_array(b"bottom")
        self.thread.dstack.push_byte_array(b"top")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_NIP, b"")
        err = opcode_nip(pop, self.thread)

        # Verify: only top item should remain
        assert err is None
        assert self.thread.dstack.depth() == 1
        assert self.thread.dstack.pop_byte_array() == b"top"

    def test_opcode_nip_stack_underflow(self):
        """Test OP_NIP with insufficient stack items."""
        # Setup: push only one item
        self.thread.dstack.push_byte_array(b"only_item")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_NIP, b"")
        err = opcode_nip(pop, self.thread)

        # Verify: should return error
        assert err is not None
        assert err.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_opcode_over_success(self):
        """Test OP_OVER - copies second-to-top item to top."""
        # Setup: push two items
        self.thread.dstack.push_byte_array(b"bottom")
        self.thread.dstack.push_byte_array(b"top")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_OVER, b"")
        err = opcode_over(pop, self.thread)

        # Verify: should have three items, with bottom copied to top
        assert err is None
        assert self.thread.dstack.depth() == 3
        assert self.thread.dstack.pop_byte_array() == b"bottom"  # copied
        assert self.thread.dstack.pop_byte_array() == b"top"     # original top
        assert self.thread.dstack.pop_byte_array() == b"bottom"  # original bottom

    def test_opcode_swap_success(self):
        """Test OP_SWAP - swaps top two stack items."""
        # Setup: push two items
        self.thread.dstack.push_byte_array(b"first")
        self.thread.dstack.push_byte_array(b"second")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_SWAP, b"")
        err = opcode_swap(pop, self.thread)

        # Verify: items should be swapped
        assert err is None
        assert self.thread.dstack.depth() == 2
        assert self.thread.dstack.pop_byte_array() == b"first"   # was second
        assert self.thread.dstack.pop_byte_array() == b"second"  # was first

    def test_opcode_rot_success(self):
        """Test OP_ROT - rotates top three stack items."""
        # Setup: push three items (bottom to top: a, b, c)
        self.thread.dstack.push_byte_array(b"a")
        self.thread.dstack.push_byte_array(b"b")
        self.thread.dstack.push_byte_array(b"c")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_ROT, b"")
        err = opcode_rot(pop, self.thread)

        # Verify: should be rotated (a, c, b)
        assert err is None
        assert self.thread.dstack.depth() == 3
        assert self.thread.dstack.pop_byte_array() == b"b"  # was top
        assert self.thread.dstack.pop_byte_array() == b"c"  # was middle
        assert self.thread.dstack.pop_byte_array() == b"a"  # was bottom

    def test_opcode_tuck_success(self):
        """Test OP_TUCK - copies top item to position 2."""
        # Setup: push two items
        self.thread.dstack.push_byte_array(b"bottom")
        self.thread.dstack.push_byte_array(b"top")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_TUCK, b"")
        err = opcode_tuck(pop, self.thread)

        # Verify: should be (bottom, top, top) - top item copied to position 2
        assert err is None
        assert self.thread.dstack.depth() == 3
        assert self.thread.dstack.pop_byte_array() == b"top"     # copied top
        assert self.thread.dstack.pop_byte_array() == b"top"     # original top
        assert self.thread.dstack.pop_byte_array() == b"bottom"  # original bottom

    def test_opcode_2drop_success(self):
        """Test OP_2DROP - removes top two stack items."""
        # Setup: push three items
        self.thread.dstack.push_byte_array(b"a")
        self.thread.dstack.push_byte_array(b"b")
        self.thread.dstack.push_byte_array(b"c")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_2DROP, b"")
        err = opcode_2drop(pop, self.thread)

        # Verify: only bottom item should remain
        assert err is None
        assert self.thread.dstack.depth() == 1
        assert self.thread.dstack.pop_byte_array() == b"a"

    def test_opcode_2dup_success(self):
        """Test OP_2DUP - duplicates top two stack items."""
        # Setup: push two items
        self.thread.dstack.push_byte_array(b"bottom")
        self.thread.dstack.push_byte_array(b"top")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_2DUP, b"")
        err = opcode_2dup(pop, self.thread)

        # Verify: should be (bottom, top, bottom, top)
        assert err is None
        assert self.thread.dstack.depth() == 4
        assert self.thread.dstack.pop_byte_array() == b"top"
        assert self.thread.dstack.pop_byte_array() == b"bottom"
        assert self.thread.dstack.pop_byte_array() == b"top"
        assert self.thread.dstack.pop_byte_array() == b"bottom"

    def test_opcode_ifdup_true(self):
        """Test OP_IFDUP when top item is truthy."""
        # Setup: push truthy value (non-zero)
        self.thread.dstack.push_byte_array(b"\x01")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_IFDUP, b"")
        err = opcode_ifdup(pop, self.thread)

        # Verify: should duplicate
        assert err is None
        assert self.thread.dstack.depth() == 2
        assert self.thread.dstack.pop_byte_array() == b"\x01"
        assert self.thread.dstack.pop_byte_array() == b"\x01"

    def test_opcode_ifdup_false(self):
        """Test OP_IFDUP when top item is falsy."""
        # Setup: push falsy value (zero)
        self.thread.dstack.push_byte_array(b"")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_IFDUP, b"")
        err = opcode_ifdup(pop, self.thread)

        # Verify: should not duplicate
        assert err is None
        assert self.thread.dstack.depth() == 1
        assert self.thread.dstack.pop_byte_array() == b""

    def test_opcode_depth_success(self):
        """Test OP_DEPTH - pushes stack depth."""
        # Setup: push some items
        self.thread.dstack.push_byte_array(b"a")
        self.thread.dstack.push_byte_array(b"b")
        self.thread.dstack.push_byte_array(b"c")

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_DEPTH, b"")
        err = opcode_depth(pop, self.thread)

        # Verify: should push depth (originally 3)
        assert err is None
        assert self.thread.dstack.depth() == 4
        depth_value = self.thread.dstack.pop_byte_array()
        # Depth should be 3 (minimal encoding of number 3)
        assert depth_value == b"\x03"

    def test_opcode_size_success(self):
        """Test OP_SIZE - pushes size of top stack item."""
        # Setup: push an item
        test_data = b"hello_world"
        self.thread.dstack.push_byte_array(test_data)

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_SIZE, b"")
        err = opcode_size(pop, self.thread)

        # Verify: should push size of the data
        assert err is None
        assert self.thread.dstack.depth() == 2
        size_value = self.thread.dstack.pop_byte_array()
        assert size_value == b"\x0b"  # 11 in minimal encoding
        assert self.thread.dstack.pop_byte_array() == test_data

    # Additional tests for more complex opcodes
    def test_opcode_pick_success(self):
        """Test OP_PICK - copies nth item to top."""
        # Setup: push items 0, 1, 2 (bottom to top)
        self.thread.dstack.push_byte_array(b"item0")
        self.thread.dstack.push_byte_array(b"item1")
        self.thread.dstack.push_byte_array(b"item2")
        self.thread.dstack.push_byte_array(b"\x01")  # index 1 (0-based from top)

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_PICK, b"")
        err = opcode_pick(pop, self.thread)

        # Verify: should copy item at index 1 (item1) to top
        assert err is None
        assert self.thread.dstack.depth() == 4
        assert self.thread.dstack.pop_byte_array() == b"item1"  # copied item
        assert self.thread.dstack.pop_byte_array() == b"item2"  # original top
        assert self.thread.dstack.pop_byte_array() == b"item1"  # middle
        assert self.thread.dstack.pop_byte_array() == b"item0"  # bottom

    def test_opcode_roll_success(self):
        """Test OP_ROLL - moves nth item to top."""
        # Setup: push items 0, 1, 2 (bottom to top)
        self.thread.dstack.push_byte_array(b"item0")
        self.thread.dstack.push_byte_array(b"item1")
        self.thread.dstack.push_byte_array(b"item2")
        self.thread.dstack.push_byte_array(b"\x01")  # roll index 1

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_ROLL, b"")
        err = opcode_roll(pop, self.thread)

        # Verify: item1 should be moved to top
        assert err is None
        assert self.thread.dstack.depth() == 3
        assert self.thread.dstack.pop_byte_array() == b"item1"  # rolled to top
        assert self.thread.dstack.pop_byte_array() == b"item2"
        assert self.thread.dstack.pop_byte_array() == b"item0"
