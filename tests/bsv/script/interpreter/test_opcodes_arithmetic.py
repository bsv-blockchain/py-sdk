"""
TDD tests for arithmetic opcodes in operations.py.

Following TDD approach: write tests first that demonstrate expected behavior,
then implement the opcodes to make tests pass.

References:
- Go SDK: go-sdk/script/interpreter/operations.go
- TypeScript SDK: ts-sdk/src/script/Spend.ts
"""

from bsv.script.interpreter.operations import (
    op_1add, op_1sub, op_negate, op_abs, op_not,
    op_0notequal, op_add, op_sub,
    op_booland, op_boolor, op_numequal,
    op_lessthan, op_greaterthan,
    op_min, op_max, op_within
)
from bsv.script.interpreter.op_parser import ParsedOpcode
from bsv.script.interpreter.stack import Stack
from bsv.script.interpreter.config import BeforeGenesisConfig
from bsv.script.interpreter.number import ScriptNumber
from bsv.script.interpreter.errs import ErrorCode
from bsv.constants import OpCode


class MockThread:
    """Mock Thread for testing opcodes without full engine setup."""

    def __init__(self):
        self.dstack = Stack(BeforeGenesisConfig())
        self.astack = Stack(BeforeGenesisConfig())


class TestArithmeticOpcodes:
    """TDD tests for arithmetic opcodes."""

    def setup_method(self):
        """Set up fresh thread for each test."""
        self.thread = MockThread()

    def test_op_1add_success(self):
        """Test OP_1ADD - adds 1 to top stack item."""
        # Setup: push 5
        self.thread.dstack.push_int(ScriptNumber(5))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_1ADD, b"")
        err = op_1add(pop, self.thread)

        # Verify: should be 6
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 6

    def test_op_1add_stack_underflow(self):
        """Test OP_1ADD with empty stack."""
        assert self.thread.dstack.depth() == 0

        pop = ParsedOpcode(OpCode.OP_1ADD, b"")
        err = op_1add(pop, self.thread)

        assert err is not None
        assert err.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_1sub_success(self):
        """Test OP_1SUB - subtracts 1 from top stack item."""
        # Setup: push 5
        self.thread.dstack.push_int(ScriptNumber(5))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_1SUB, b"")
        err = op_1sub(pop, self.thread)

        # Verify: should be 4
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 4

    def test_op_negate_success(self):
        """Test OP_NEGATE - negates top stack item."""
        # Setup: push 5
        self.thread.dstack.push_int(ScriptNumber(5))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_NEGATE, b"")
        err = op_negate(pop, self.thread)

        # Verify: should be -5
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == -5

    def test_op_negate_zero(self):
        """Test OP_NEGATE with zero."""
        # Setup: push 0
        self.thread.dstack.push_int(ScriptNumber(0))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_NEGATE, b"")
        err = op_negate(pop, self.thread)

        # Verify: should still be 0
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 0

    def test_op_abs_success_positive(self):
        """Test OP_ABS with positive number."""
        # Setup: push 5
        self.thread.dstack.push_int(ScriptNumber(5))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_ABS, b"")
        err = op_abs(pop, self.thread)

        # Verify: should still be 5
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 5

    def test_op_abs_success_negative(self):
        """Test OP_ABS with negative number."""
        # Setup: push -5
        self.thread.dstack.push_int(ScriptNumber(-5))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_ABS, b"")
        err = op_abs(pop, self.thread)

        # Verify: should be 5
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 5

    def test_op_not_success_zero(self):
        """Test OP_NOT with zero (false)."""
        # Setup: push 0 (false)
        self.thread.dstack.push_int(ScriptNumber(0))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_NOT, b"")
        err = op_not(pop, self.thread)

        # Verify: should be 1 (true)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 1

    def test_op_not_success_nonzero(self):
        """Test OP_NOT with non-zero (true)."""
        # Setup: push 5 (true)
        self.thread.dstack.push_int(ScriptNumber(5))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_NOT, b"")
        err = op_not(pop, self.thread)

        # Verify: should be 0 (false)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 0

    def test_op_0notequal_success_zero(self):
        """Test OP_0NOTEQUAL with zero."""
        # Setup: push 0
        self.thread.dstack.push_int(ScriptNumber(0))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_0NOTEQUAL, b"")
        err = op_0notequal(pop, self.thread)

        # Verify: should be 0 (false)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 0

    def test_op_0notequal_success_nonzero(self):
        """Test OP_0NOTEQUAL with non-zero."""
        # Setup: push 5
        self.thread.dstack.push_int(ScriptNumber(5))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_0NOTEQUAL, b"")
        err = op_0notequal(pop, self.thread)

        # Verify: should be 1 (true)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 1

    def test_op_add_success(self):
        """Test OP_ADD - adds top two stack items."""
        # Setup: push 3 and 7
        self.thread.dstack.push_int(ScriptNumber(3))
        self.thread.dstack.push_int(ScriptNumber(7))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_ADD, b"")
        err = op_add(pop, self.thread)

        # Verify: should be 10
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 10

    def test_op_add_stack_underflow(self):
        """Test OP_ADD with insufficient stack items."""
        # Setup: push only one item
        self.thread.dstack.push_int(ScriptNumber(5))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_ADD, b"")
        err = op_add(pop, self.thread)

        # Verify: should return error
        assert err is not None
        assert err.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_sub_success(self):
        """Test OP_SUB - subtracts top item from second item."""
        # Setup: push 10 and 3 (10 - 3 = 7)
        self.thread.dstack.push_int(ScriptNumber(10))
        self.thread.dstack.push_int(ScriptNumber(3))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_SUB, b"")
        err = op_sub(pop, self.thread)

        # Verify: should be 7 (10 - 3)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 7

    def test_op_booland_success(self):
        """Test OP_BOOLAND - boolean AND of top two items."""
        # Setup: push two truthy values
        self.thread.dstack.push_int(ScriptNumber(5))
        self.thread.dstack.push_int(ScriptNumber(7))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_BOOLAND, b"")
        err = op_booland(pop, self.thread)

        # Verify: should be 1 (true)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 1

    def test_op_booland_false(self):
        """Test OP_BOOLAND with one false value."""
        # Setup: push false and true
        self.thread.dstack.push_int(ScriptNumber(0))
        self.thread.dstack.push_int(ScriptNumber(7))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_BOOLAND, b"")
        err = op_booland(pop, self.thread)

        # Verify: should be 0 (false)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 0

    def test_op_boolor_success(self):
        """Test OP_BOOLOR - boolean OR of top two items."""
        # Setup: push false and true
        self.thread.dstack.push_int(ScriptNumber(0))
        self.thread.dstack.push_int(ScriptNumber(7))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_BOOLOR, b"")
        err = op_boolor(pop, self.thread)

        # Verify: should be 1 (true)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 1

    def test_op_boolor_both_false(self):
        """Test OP_BOOLOR with both false."""
        # Setup: push two false values
        self.thread.dstack.push_int(ScriptNumber(0))
        self.thread.dstack.push_int(ScriptNumber(0))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_BOOLOR, b"")
        err = op_boolor(pop, self.thread)

        # Verify: should be 0 (false)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 0

    def test_op_numequal_success_equal(self):
        """Test OP_NUMEQUAL with equal numbers."""
        # Setup: push two equal numbers
        self.thread.dstack.push_int(ScriptNumber(42))
        self.thread.dstack.push_int(ScriptNumber(42))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_NUMEQUAL, b"")
        err = op_numequal(pop, self.thread)

        # Verify: should be 1 (true)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 1

    def test_op_numequal_success_not_equal(self):
        """Test OP_NUMEQUAL with unequal numbers."""
        # Setup: push two different numbers
        self.thread.dstack.push_int(ScriptNumber(42))
        self.thread.dstack.push_int(ScriptNumber(43))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_NUMEQUAL, b"")
        err = op_numequal(pop, self.thread)

        # Verify: should be 0 (false)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 0

    def test_op_lessthan_success(self):
        """Test OP_LESSTHAN."""
        # Setup: push 5 and 10 (5 < 10 = true)
        self.thread.dstack.push_int(ScriptNumber(5))
        self.thread.dstack.push_int(ScriptNumber(10))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_LESSTHAN, b"")
        err = op_lessthan(pop, self.thread)

        # Verify: should be 1 (true)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 1

    def test_op_greaterthan_success(self):
        """Test OP_GREATERTHAN."""
        # Setup: push 10 and 5 (10 > 5 = true)
        self.thread.dstack.push_int(ScriptNumber(10))
        self.thread.dstack.push_int(ScriptNumber(5))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_GREATERTHAN, b"")
        err = op_greaterthan(pop, self.thread)

        # Verify: should be 1 (true)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 1

    def test_op_min_success(self):
        """Test OP_MIN."""
        # Setup: push 10 and 5
        self.thread.dstack.push_int(ScriptNumber(10))
        self.thread.dstack.push_int(ScriptNumber(5))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_MIN, b"")
        err = op_min(pop, self.thread)

        # Verify: should be 5
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 5

    def test_op_max_success(self):
        """Test OP_MAX."""
        # Setup: push 10 and 5
        self.thread.dstack.push_int(ScriptNumber(10))
        self.thread.dstack.push_int(ScriptNumber(5))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_MAX, b"")
        err = op_max(pop, self.thread)

        # Verify: should be 10
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 10

    def test_op_within_success_inside(self):
        """Test OP_WITHIN with value inside range."""
        # Setup: push value=10, min=5, max=15
        self.thread.dstack.push_int(ScriptNumber(10))
        self.thread.dstack.push_int(ScriptNumber(5))
        self.thread.dstack.push_int(ScriptNumber(15))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_WITHIN, b"")
        err = op_within(pop, self.thread)

        # Verify: should be 1 (true)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 1

    def test_op_within_success_outside(self):
        """Test OP_WITHIN with value outside range."""
        # Setup: push min=5, max=15, value=20
        self.thread.dstack.push_int(ScriptNumber(5))
        self.thread.dstack.push_int(ScriptNumber(15))
        self.thread.dstack.push_int(ScriptNumber(20))

        # Execute opcode
        pop = ParsedOpcode(OpCode.OP_WITHIN, b"")
        err = op_within(pop, self.thread)

        # Verify: should be 0 (false)
        assert err is None
        assert self.thread.dstack.depth() == 1
        result = self.thread.dstack.pop_int()
        assert result.value == 0
