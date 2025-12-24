"""
Edge case tests for script interpreter operations
"""
from bsv.script.interpreter.operations import (
    op_dup, op_drop, op_swap, op_over, op_pick, op_roll, op_rot,
    op_add, op_sub, op_mul, op_div, op_mod,
    op_equal, op_equal_verify,
    op_hash160, op_hash256, op_sha256,
    op_checksig, op_checkmultisig,
    op_if, op_notif, op_else, op_endif,
    op_depth, op_size,
    op_1add, op_1sub, op_negate, op_abs,
    op_numequal, op_lessthan, op_greaterthan,
    op_min, op_max, op_within,
    op_cat, op_split, op_num2bin, op_bin2num,
    op_invert, op_and, op_or, op_xor,
    op_lshift, op_rshift
)
from bsv.script.interpreter.errs import Error, ErrorCode
from bsv.script.interpreter.stack import Stack
from bsv.script.interpreter.config import BeforeGenesisConfig
from bsv.script.interpreter.op_parser import ParsedOpcode


class MockThread:
    """Mock Thread for testing operations without full engine setup."""

    def __init__(self):
        self.dstack = Stack(BeforeGenesisConfig())
        self.astack = Stack(BeforeGenesisConfig())

    def is_branch_executing(self):
        """Mock branch execution check."""
        return True

    def should_exec(self, opcode=None):
        """Mock execution check - always execute for these tests."""
        return True


class TestOperationsEdgeCases:
    """Test edge cases for script operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.thread = MockThread()

    def create_parsed_opcode(self, opcode_value: int) -> ParsedOpcode:
        """Create a parsed opcode for testing."""
        return ParsedOpcode(opcode_value, b"")

    # Stack manipulation edge cases

    def test_op_dup_stack_underflow(self):
        """Test OP_DUP with empty stack."""
        pop = self.create_parsed_opcode(0x76)  # OP_DUP
        error = op_dup(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_drop_stack_underflow(self):
        """Test OP_DROP with empty stack."""
        pop = self.create_parsed_opcode(0x75)  # OP_DROP
        error = op_drop(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_swap_stack_underflow(self):
        """Test OP_SWAP with insufficient stack items."""
        # Test with 0 items
        pop = self.create_parsed_opcode(0x7c)  # OP_SWAP
        error = op_swap(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

        # Test with 1 item
        self.thread.dstack.push(b"item1")
        error = op_swap(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_over_stack_underflow(self):
        """Test OP_OVER with insufficient stack items."""
        # Test with 0 items
        pop = self.create_parsed_opcode(0x78)  # OP_OVER
        error = op_over(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

        # Test with 1 item
        self.thread.dstack.push(b"item1")
        error = op_over(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_pick_stack_underflow(self):
        """Test OP_PICK with insufficient stack items."""
        pop = self.create_parsed_opcode(0x79)  # OP_PICK
        error = op_pick(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_pick_invalid_index(self):
        """Test OP_PICK with invalid index."""
        self.thread.dstack.push(b"item1")
        self.thread.dstack.push(b"\x05")  # Index 5, but only 1 item available

        pop = self.create_parsed_opcode(0x79)  # OP_PICK
        error = op_pick(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_roll_stack_underflow(self):
        """Test OP_ROLL with insufficient stack items."""
        pop = self.create_parsed_opcode(0x7a)  # OP_ROLL
        error = op_roll(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_roll_invalid_index(self):
        """Test OP_ROLL with invalid index."""
        self.thread.dstack.push(b"item1")
        self.thread.dstack.push(b"\x05")  # Index 5, but only 1 item available

        pop = self.create_parsed_opcode(0x7a)  # OP_ROLL
        error = op_roll(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_rot_stack_underflow(self):
        """Test OP_ROT with insufficient stack items."""
        pop = self.create_parsed_opcode(0x7b)  # OP_ROT
        error = op_rot(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    # Arithmetic operation edge cases

    def test_op_add_stack_underflow(self):
        """Test OP_ADD with insufficient stack items."""
        pop = self.create_parsed_opcode(0x93)  # OP_ADD
        error = op_add(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_add_invalid_numbers(self):
        """Test OP_ADD with invalid number encodings."""
        self.thread.dstack.push(b"not_a_number")
        self.thread.dstack.push(b"also_not_a_number")

        pop = self.create_parsed_opcode(0x93)  # OP_ADD
        error = op_add(pop, self.thread)
        # Should handle gracefully or raise appropriate error

    def test_op_sub_stack_underflow(self):
        """Test OP_SUB with insufficient stack items."""
        pop = self.create_parsed_opcode(0x94)  # OP_SUB
        error = op_sub(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_mul_stack_underflow(self):
        """Test OP_MUL with insufficient stack items."""
        pop = self.create_parsed_opcode(0x95)  # OP_MUL
        error = op_mul(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_div_stack_underflow(self):
        """Test OP_DIV with insufficient stack items."""
        pop = self.create_parsed_opcode(0x96)  # OP_DIV
        error = op_div(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_div_by_zero(self):
        """Test OP_DIV with division by zero."""
        self.thread.dstack.push(b"\x05")  # dividend
        self.thread.dstack.push(b"")      # divisor (top, empty = 0) - this gets checked for zero

        pop = self.create_parsed_opcode(0x96)  # OP_DIV
        error = op_div(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_DIVIDE_BY_ZERO

    def test_op_mod_stack_underflow(self):
        """Test OP_MOD with insufficient stack items."""
        pop = self.create_parsed_opcode(0x97)  # OP_MOD
        error = op_mod(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_mod_by_zero(self):
        """Test OP_MOD with modulus by zero."""
        self.thread.dstack.push(b"\x05")  # dividend
        self.thread.dstack.push(b"")      # modulus (top, empty = 0) - this gets checked for zero

        pop = self.create_parsed_opcode(0x97)  # OP_MOD
        error = op_mod(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_DIVIDE_BY_ZERO

    # Comparison operation edge cases

    def test_op_equal_stack_underflow(self):
        """Test OP_EQUAL with insufficient stack items."""
        pop = self.create_parsed_opcode(0x87)  # OP_EQUAL
        error = op_equal(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_equal_verify_false(self):
        """Test OP_EQUAL_VERIFY when equal fails."""
        self.thread.dstack.push(b"item1")
        self.thread.dstack.push(b"item2")

        pop = self.create_parsed_opcode(0x88)  # OP_EQUAL_VERIFY
        error = op_equal_verify(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_EQUAL_VERIFY

    # Unary arithmetic operations

    def test_op_1add_stack_underflow(self):
        """Test OP_1ADD with empty stack."""
        pop = self.create_parsed_opcode(0x8b)  # OP_1ADD
        error = op_1add(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_1sub_stack_underflow(self):
        """Test OP_1SUB with empty stack."""
        pop = self.create_parsed_opcode(0x8c)  # OP_1SUB
        error = op_1sub(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_negate_stack_underflow(self):
        """Test OP_NEGATE with empty stack."""
        pop = self.create_parsed_opcode(0x8f)  # OP_NEGATE
        error = op_negate(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_abs_stack_underflow(self):
        """Test OP_ABS with empty stack."""
        pop = self.create_parsed_opcode(0x90)  # OP_ABS
        error = op_abs(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    # Hash operation edge cases

    def test_op_hash160_stack_underflow(self):
        """Test OP_HASH160 with empty stack."""
        pop = self.create_parsed_opcode(0xa9)  # OP_HASH160
        error = op_hash160(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_hash256_stack_underflow(self):
        """Test OP_HASH256 with empty stack."""
        pop = self.create_parsed_opcode(0xaa)  # OP_HASH256
        error = op_hash256(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_sha256_stack_underflow(self):
        """Test OP_SHA256 with empty stack."""
        pop = self.create_parsed_opcode(0xa8)  # OP_SHA256
        error = op_sha256(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    # Numeric comparison operations

    def test_op_numequal_stack_underflow(self):
        """Test OP_NUMEQUAL with insufficient stack items."""
        pop = self.create_parsed_opcode(0x9c)  # OP_NUMEQUAL
        error = op_numequal(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_lessthan_stack_underflow(self):
        """Test OP_LESSTHAN with insufficient stack items."""
        pop = self.create_parsed_opcode(0x9f)  # OP_LESSTHAN
        error = op_lessthan(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_greaterthan_stack_underflow(self):
        """Test OP_GREATERTHAN with insufficient stack items."""
        pop = self.create_parsed_opcode(0xa0)  # OP_GREATERTHAN
        error = op_greaterthan(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    # Min/Max operations

    def test_op_min_stack_underflow(self):
        """Test OP_MIN with insufficient stack items."""
        pop = self.create_parsed_opcode(0xa3)  # OP_MIN
        error = op_min(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_max_stack_underflow(self):
        """Test OP_MAX with insufficient stack items."""
        pop = self.create_parsed_opcode(0xa4)  # OP_MAX
        error = op_max(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_within_stack_underflow(self):
        """Test OP_WITHIN with insufficient stack items."""
        pop = self.create_parsed_opcode(0xa5)  # OP_WITHIN
        error = op_within(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    # Cryptographic operations

    def test_op_checksig_stack_underflow(self):
        """Test OP_CHECKSIG with insufficient stack items."""
        pop = self.create_parsed_opcode(0xac)  # OP_CHECKSIG
        error = op_checksig(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_checkmultisig_stack_underflow(self):
        """Test OP_CHECKMULTISIG with insufficient stack items."""
        pop = self.create_parsed_opcode(0xae)  # OP_CHECKMULTISIG
        error = op_checkmultisig(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    # Control flow operations

    def test_op_if_stack_underflow(self):
        """Test OP_IF with empty stack."""
        pop = self.create_parsed_opcode(0x63)  # OP_IF
        error = op_if(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_notif_stack_underflow(self):
        """Test OP_NOTIF with empty stack."""
        pop = self.create_parsed_opcode(0x64)  # OP_NOTIF
        error = op_notif(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    # Stack information operations

    def test_op_depth_normal_operation(self):
        """Test OP_DEPTH normal operation."""
        # Add some items to stack
        self.thread.dstack.push(b"item1")
        self.thread.dstack.push(b"item2")
        self.thread.dstack.push(b"item3")

        pop = self.create_parsed_opcode(0x74)  # OP_DEPTH
        error = op_depth(pop, self.thread)
        assert error is None

        # Should have pushed the depth (3) onto the stack
        depth_value = self.thread.dstack.pop_byte_array()
        assert depth_value == b"\x03"

    def test_op_size_stack_underflow(self):
        """Test OP_SIZE with empty stack."""
        pop = self.create_parsed_opcode(0x82)  # OP_SIZE
        error = op_size(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_size_normal_operation(self):
        """Test OP_SIZE normal operation."""
        test_data = b"hello world"
        self.thread.dstack.push(test_data)

        pop = self.create_parsed_opcode(0x82)  # OP_SIZE
        error = op_size(pop, self.thread)
        assert error is None

        # Should have pushed the size onto the stack
        size_value = self.thread.dstack.pop_byte_array()
        assert size_value == b"\x0b"  # 11 bytes

    # String operations

    def test_op_cat_stack_underflow(self):
        """Test OP_CAT with insufficient stack items."""
        pop = self.create_parsed_opcode(0x7e)  # OP_CAT
        error = op_cat(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_split_stack_underflow(self):
        """Test OP_SPLIT with insufficient stack items."""
        pop = self.create_parsed_opcode(0x7f)  # OP_SPLIT
        error = op_split(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_num2bin_stack_underflow(self):
        """Test OP_NUM2BIN with insufficient stack items."""
        pop = self.create_parsed_opcode(0x80)  # OP_NUM2BIN
        error = op_num2bin(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_bin2num_stack_underflow(self):
        """Test OP_BIN2NUM with empty stack."""
        pop = self.create_parsed_opcode(0x81)  # OP_BIN2NUM
        error = op_bin2num(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    # Bitwise operations

    def test_op_invert_stack_underflow(self):
        """Test OP_INVERT with empty stack."""
        pop = self.create_parsed_opcode(0x83)  # OP_INVERT
        error = op_invert(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_and_stack_underflow(self):
        """Test OP_AND with insufficient stack items."""
        pop = self.create_parsed_opcode(0x84)  # OP_AND
        error = op_and(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_or_stack_underflow(self):
        """Test OP_OR with insufficient stack items."""
        pop = self.create_parsed_opcode(0x85)  # OP_OR
        error = op_or(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_xor_stack_underflow(self):
        """Test OP_XOR with insufficient stack items."""
        pop = self.create_parsed_opcode(0x86)  # OP_XOR
        error = op_xor(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_lshift_stack_underflow(self):
        """Test OP_LSHIFT with insufficient stack items."""
        pop = self.create_parsed_opcode(0x98)  # OP_LSHIFT
        error = op_lshift(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    def test_op_rshift_stack_underflow(self):
        """Test OP_RSHIFT with insufficient stack items."""
        pop = self.create_parsed_opcode(0x99)  # OP_RSHIFT
        error = op_rshift(pop, self.thread)
        assert error is not None
        assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION

    # Large number handling

    def test_op_add_large_numbers(self):
        """Test OP_ADD with large numbers that might overflow."""
        # Push maximum values
        self.thread.dstack.push(b"\xff\xff\xff\x7f")  # Large positive
        self.thread.dstack.push(b"\xff\xff\xff\x7f")  # Large positive

        pop = self.create_parsed_opcode(0x93)  # OP_ADD
        error = op_add(pop, self.thread)
        # Should handle large numbers appropriately

    def test_op_mul_large_numbers(self):
        """Test OP_MUL with numbers that might cause overflow."""
        self.thread.dstack.push(b"\xff\xff")  # Large number
        self.thread.dstack.push(b"\xff\xff")  # Large number

        pop = self.create_parsed_opcode(0x95)  # OP_MUL
        error = op_mul(pop, self.thread)
        # Should handle multiplication appropriately

    # Edge cases with specific number encodings

    def test_operations_with_negative_zero(self):
        """Test operations with negative zero encoding."""
        # Negative zero in Bitcoin script: 0x80
        self.thread.dstack.push(b"\x80")  # Negative zero
        self.thread.dstack.push(b"\x01")  # Positive one

        pop = self.create_parsed_opcode(0x93)  # OP_ADD
        error = op_add(pop, self.thread)
        # Should handle negative zero correctly

    def test_operations_with_minimal_encoding(self):
        """Test operations with minimally encoded numbers."""
        # Test various minimal encodings
        test_cases = [
            b"",      # 0
            b"\x01",  # 1
            b"\x7f",  # 127
            b"\x80",  # -0 (negative zero)
            b"\x81",  # -1
            b"\xff",  # -127
        ]

        for num_encoding in test_cases:
            # Clear stack
            while self.thread.dstack.depth() > 0:
                self.thread.dstack.pop_byte_array()

            self.thread.dstack.push(num_encoding)
            self.thread.dstack.push(b"\x01")

            pop = self.create_parsed_opcode(0x93)  # OP_ADD
            error = op_add(pop, self.thread)
            # Should handle various encodings
