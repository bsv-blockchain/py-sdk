"""
Comprehensive tests for bsv/script/interpreter/stack.py

Tests stack operations for the script interpreter.
"""

import pytest
from bsv.script.interpreter.stack import (
    Stack,
    as_bool,
    from_bool,
    NopDebugger,
    NopStateHandler,
)
from bsv.script.interpreter.config import AfterGenesisConfig
from bsv.script.interpreter.number import ScriptNumber


class TestAsBool:
    """Test as_bool function."""
    
    def test_empty_bytes_is_false(self):
        """Test that empty bytes is false."""
        assert as_bool(b"") is False
    
    def test_zero_is_false(self):
        """Test that zero is false."""
        assert as_bool(b"\x00") is False
    
    def test_negative_zero_is_false(self):
        """Test that negative zero (0x80) is false."""
        assert as_bool(b"\x80") is False
    
    def test_non_zero_is_true(self):
        """Test that non-zero values are true."""
        assert as_bool(b"\x01") is True
        assert as_bool(b"\x02") is True
        assert as_bool(b"\xFF") is True
    
    def test_multiple_bytes_with_nonzero(self):
        """Test multi-byte values with non-zero bytes."""
        assert as_bool(b"\x00\x01") is True
        assert as_bool(b"\x01\x00") is True
    
    def test_all_zeros_is_false(self):
        """Test that all zeros is false."""
        assert as_bool(b"\x00\x00\x00") is False
    
    def test_negative_zero_multi_byte_is_false(self):
        """Test multi-byte negative zero is false."""
        assert as_bool(b"\x00\x00\x80") is False


class TestFromBool:
    """Test from_bool function."""
    
    def test_true_to_bytes(self):
        """Test converting true to bytes."""
        assert from_bool(True) == b"\x01"
    
    def test_false_to_bytes(self):
        """Test converting false to bytes."""
        assert from_bool(False) == b""


class TestNopDebugger:
    """Test NopDebugger class."""
    
    def test_before_stack_push(self):
        """Test before_stack_push does nothing."""
        debugger = NopDebugger()
        debugger.before_stack_push(b"data")  # Should not raise
    
    def test_after_stack_push(self):
        """Test after_stack_push does nothing."""
        debugger = NopDebugger()
        debugger.after_stack_push(b"data")  # Should not raise
    
    def test_before_stack_pop(self):
        """Test before_stack_pop does nothing."""
        debugger = NopDebugger()
        debugger.before_stack_pop()  # Should not raise
    
    def test_after_stack_pop(self):
        """Test after_stack_pop does nothing."""
        debugger = NopDebugger()
        debugger.after_stack_pop(b"data")  # Should not raise


class TestNopStateHandler:
    """Test NopStateHandler class."""
    
    def test_state_returns_empty_dict(self):
        """Test state returns empty dict."""
        handler = NopStateHandler()
        assert handler.state() == {}
    
    def test_set_state_does_nothing(self):
        """Test set_state does nothing."""
        handler = NopStateHandler()
        handler.set_state({"key": "value"})  # Should not raise


class TestStackInit:
    """Test Stack initialization."""
    
    def test_init_with_config(self):
        """Test initializing stack with config."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        assert stack.depth() == 0
        assert isinstance(stack.debug, NopDebugger)
        assert isinstance(stack.sh, NopStateHandler)
    
    def test_init_with_debugger(self):
        """Test initializing with custom debugger."""
        cfg = AfterGenesisConfig()
        debugger = NopDebugger()
        stack = Stack(cfg, debug=debugger)
        assert stack.debug is debugger
    
    def test_init_with_state_handler(self):
        """Test initializing with custom state handler."""
        cfg = AfterGenesisConfig()
        handler = NopStateHandler()
        stack = Stack(cfg, state_handler=handler)
        assert stack.sh is handler
    
    def test_init_verify_minimal_data(self):
        """Test initializing with verify_minimal_data flag."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg, verify_minimal_data=False)
        assert stack.verify_minimal_data is False


class TestStackBasicOperations:
    """Test basic stack operations."""
    
    def test_depth_empty_stack(self):
        """Test depth of empty stack."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        assert stack.depth() == 0
    
    def test_push_byte_array(self):
        """Test pushing byte array."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"test")
        assert stack.depth() == 1
    
    def test_push_multiple_items(self):
        """Test pushing multiple items."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"item1")
        stack.push_byte_array(b"item2")
        stack.push_byte_array(b"item3")
        assert stack.depth() == 3
    
    def test_pop_byte_array(self):
        """Test popping byte array."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"test")
        data = stack.pop_byte_array()
        assert data == b"test"
        assert stack.depth() == 0
    
    def test_pop_empty_stack_raises(self):
        """Test popping from empty stack raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        with pytest.raises(ValueError, match="stack is empty"):
            stack.pop_byte_array()
    
    def test_push_pop_order(self):
        """Test LIFO order of push/pop."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"first")
        stack.push_byte_array(b"second")
        stack.push_byte_array(b"third")
        
        assert stack.pop_byte_array() == b"third"
        assert stack.pop_byte_array() == b"second"
        assert stack.pop_byte_array() == b"first"


class TestStackIntOperations:
    """Test integer operations on stack."""
    
    def test_push_int(self):
        """Test pushing integer."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        num = ScriptNumber(42)
        stack.push_int(num)
        assert stack.depth() == 1
    
    def test_pop_int(self):
        """Test popping integer."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_int(ScriptNumber(42))
        num = stack.pop_int()
        assert num.value == 42
    
    def test_push_pop_negative_int(self):
        """Test push/pop with negative integer."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_int(ScriptNumber(-100))
        num = stack.pop_int()
        assert num.value == -100
    
    def test_push_pop_zero(self):
        """Test push/pop with zero."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_int(ScriptNumber(0))
        num = stack.pop_int()
        assert num.value == 0


class TestStackBoolOperations:
    """Test boolean operations on stack."""
    
    def test_push_bool_true(self):
        """Test pushing true."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_bool(True)
        assert stack.depth() == 1
    
    def test_push_bool_false(self):
        """Test pushing false."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_bool(False)
        assert stack.depth() == 1
    
    def test_pop_bool_true(self):
        """Test popping true."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_bool(True)
        val = stack.pop_bool()
        assert val is True
    
    def test_pop_bool_false(self):
        """Test popping false."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_bool(False)
        val = stack.pop_bool()
        assert val is False


class TestStackPeekOperations:
    """Test peek operations on stack."""
    
    def test_peek_byte_array_top(self):
        """Test peeking at top of stack."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"bottom")
        stack.push_byte_array(b"top")
        
        assert stack.peek_byte_array(0) == b"top"
        assert stack.depth() == 2  # Depth unchanged
    
    def test_peek_byte_array_offset(self):
        """Test peeking at offset."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"first")
        stack.push_byte_array(b"second")
        stack.push_byte_array(b"third")
        
        assert stack.peek_byte_array(0) == b"third"
        assert stack.peek_byte_array(1) == b"second"
        assert stack.peek_byte_array(2) == b"first"
    
    def test_peek_invalid_index_negative(self):
        """Test peeking with negative index raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"data")
        
        with pytest.raises(ValueError, match="invalid stack index"):
            stack.peek_byte_array(-1)
    
    def test_peek_invalid_index_too_large(self):
        """Test peeking with too large index raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"data")
        
        with pytest.raises(ValueError, match="invalid stack index"):
            stack.peek_byte_array(1)
    
    def test_peek_int(self):
        """Test peeking at integer."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_int(ScriptNumber(99))
        
        num = stack.peek_int(0)
        assert num.value == 99
        assert stack.depth() == 1
    
    def test_peek_bool(self):
        """Test peeking at boolean."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_bool(True)
        
        val = stack.peek_bool(0)
        assert val is True
        assert stack.depth() == 1


class TestStackNipNop:
    """Test nip_n and nop_n operations."""
    
    def test_nip_n_removes_item(self):
        """Test nip_n removes and returns item."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"first")
        stack.push_byte_array(b"second")
        stack.push_byte_array(b"third")
        
        removed = stack.nip_n(1)  # Remove second from top
        assert removed == b"second"
        assert stack.depth() == 2
    
    def test_nip_n_invalid_index(self):
        """Test nip_n with invalid index raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"data")
        
        with pytest.raises(ValueError, match="invalid stack index"):
            stack.nip_n(5)
    
    def test_nop_n_gets_without_removing(self):
        """Test nop_n gets item without removing."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"first")
        stack.push_byte_array(b"second")
        
        item = stack.nop_n(0)
        assert item == b"second"
        assert stack.depth() == 2  # Not removed


class TestStackDropN:
    """Test drop_n operation."""
    
    def test_drop_n_one(self):
        """Test dropping one item."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        stack.push_byte_array(b"b")
        
        stack.drop_n(1)
        assert stack.depth() == 1
        assert stack.peek_byte_array(0) == b"a"
    
    def test_drop_n_multiple(self):
        """Test dropping multiple items."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        for i in range(5):
            stack.push_byte_array(f"item{i}".encode())
        
        stack.drop_n(3)
        assert stack.depth() == 2
    
    def test_drop_n_all(self):
        """Test dropping all items."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        stack.push_byte_array(b"b")
        
        stack.drop_n(2)
        assert stack.depth() == 0
    
    def test_drop_n_negative_raises(self):
        """Test drop_n with negative count raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        
        with pytest.raises(ValueError, match="invalid drop count"):
            stack.drop_n(-1)
    
    def test_drop_n_too_many_raises(self):
        """Test drop_n with too many items raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        
        with pytest.raises(ValueError, match="invalid drop count"):
            stack.drop_n(2)


class TestStackDupN:
    """Test dup_n operation."""
    
    def test_dup_n_one(self):
        """Test duplicating one item."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"data")
        
        stack.dup_n(1)
        assert stack.depth() == 2
        assert stack.peek_byte_array(0) == b"data"
        assert stack.peek_byte_array(1) == b"data"
    
    def test_dup_n_multiple(self):
        """Test duplicating multiple items."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        stack.push_byte_array(b"b")
        stack.push_byte_array(b"c")
        
        stack.dup_n(2)
        assert stack.depth() == 5
        assert stack.peek_byte_array(0) == b"c"
        assert stack.peek_byte_array(1) == b"b"
    
    def test_dup_n_invalid_count_raises(self):
        """Test dup_n with invalid count raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        
        with pytest.raises(ValueError):
            stack.dup_n(2)  # Not enough items


class TestStackSwapN:
    """Test swap_n operation."""
    
    def test_swap_n_one(self):
        """Test swapping one item."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        stack.push_byte_array(b"b")
        
        initial_depth = stack.depth()
        stack.swap_n(1)
        assert stack.depth() == initial_depth  # Depth unchanged
    
    def test_swap_n_multiple(self):
        """Test swapping multiple items."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        stack.push_byte_array(b"b")
        stack.push_byte_array(b"c")
        stack.push_byte_array(b"d")
        
        initial_depth = stack.depth()
        stack.swap_n(2)
        assert stack.depth() == initial_depth  # Depth unchanged
    
    def test_swap_n_invalid_raises(self):
        """Test swap_n with invalid count raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        
        with pytest.raises(ValueError, match="invalid swap count"):
            stack.swap_n(1)  # Need at least 2 items


class TestStackRotN:
    """Test rot_n operation."""
    
    def test_rot_n_one(self):
        """Test rotating one item."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        stack.push_byte_array(b"b")
        stack.push_byte_array(b"c")
        
        stack.rot_n(1)
        assert stack.peek_byte_array(0) == b"b"
        assert stack.peek_byte_array(1) == b"c"
        assert stack.peek_byte_array(2) == b"a"
    
    def test_rot_n_invalid_raises(self):
        """Test rot_n with invalid count raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        
        with pytest.raises(ValueError, match="invalid rot count"):
            stack.rot_n(1)  # Need at least 3 items


class TestStackOverN:
    """Test over_n operation."""
    
    def test_over_n_one(self):
        """Test over one item."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        stack.push_byte_array(b"b")
        stack.push_byte_array(b"c")
        
        initial_depth = stack.depth()
        stack.over_n(1)
        assert stack.depth() == initial_depth + 1  # Added 1 item
    
    def test_over_n_invalid_raises(self):
        """Test over_n with invalid count raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        
        with pytest.raises(ValueError, match="invalid over count"):
            stack.over_n(1)  # Need at least 2 items


class TestStackPickN:
    """Test pick_n operation."""
    
    def test_pick_n_one(self):
        """Test picking one item."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        stack.push_byte_array(b"b")
        
        stack.pick_n(1)
        assert stack.depth() == 3
        assert stack.peek_byte_array(0) == b"a"
    
    def test_pick_n_invalid_raises(self):
        """Test pick_n with invalid count raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        
        with pytest.raises(ValueError, match="invalid pick count"):
            stack.pick_n(5)


class TestStackRollN:
    """Test roll_n operation."""
    
    def test_roll_n_one(self):
        """Test rolling one item."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        stack.push_byte_array(b"a")
        stack.push_byte_array(b"b")
        
        stack.roll_n(1)
        assert stack.depth() == 2
        assert stack.peek_byte_array(0) == b"a"
        assert stack.peek_byte_array(1) == b"b"
    
    def test_roll_n_invalid_raises(self):
        """Test roll_n with invalid count raises error."""
        cfg = AfterGenesisConfig()
        stack = Stack(cfg)
        
        with pytest.raises(ValueError, match="invalid roll count"):
            stack.roll_n(5)

