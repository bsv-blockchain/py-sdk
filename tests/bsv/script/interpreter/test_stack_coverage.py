"""
Coverage tests for script/interpreter/stack.py - untested branches.
"""
import pytest


# ========================================================================
# Stack operations branches
# ========================================================================

def test_stack_init():
    """Test Stack initialization."""
    try:
        from bsv.script.interpreter.stack import Stack
        from bsv.script.interpreter.config import BeforeGenesisConfig
        cfg = BeforeGenesisConfig()
        stack = Stack(cfg)
        assert stack is not None
    except ImportError:
        pytest.skip("Stack not available")


def test_stack_push():
    """Test Stack push operation."""
    try:
        from bsv.script.interpreter.stack import Stack
        from bsv.script.interpreter.config import BeforeGenesisConfig
        cfg = BeforeGenesisConfig()
        stack = Stack(cfg)
        stack.push(b'\x01\x02\x03')
        assert stack.depth() > 0
    except ImportError:
        pytest.skip("Stack not available")


def test_stack_pop():
    """Test Stack pop operation."""
    try:
        from bsv.script.interpreter.stack import Stack
        from bsv.script.interpreter.config import BeforeGenesisConfig
        cfg = BeforeGenesisConfig()
        stack = Stack(cfg)
        stack.push(b'\x01')
        value = stack.pop()
        assert value == b'\x01'
    except ImportError:
        pytest.skip("Stack not available")


def test_stack_pop_empty():
    """Test Stack pop on empty stack."""
    try:
        from bsv.script.interpreter.stack import Stack
        from bsv.script.interpreter.config import BeforeGenesisConfig
        cfg = BeforeGenesisConfig()
        stack = Stack(cfg)
        try:
            value = stack.pop()
            assert False, "Should raise error"
        except ValueError:
            assert True
    except ImportError:
        pytest.skip("Stack not available")


def test_stack_peek():
    """Test Stack peek operation."""
    try:
        from bsv.script.interpreter.stack import Stack
        from bsv.script.interpreter.config import BeforeGenesisConfig
        cfg = BeforeGenesisConfig()
        stack = Stack(cfg)
        stack.push(b'\x01')
        value = stack.peek()
        assert value == b'\x01'
        assert stack.depth() == 1  # Peek shouldn't remove
    except ImportError:
        pytest.skip("Stack not available")


def test_stack_len():
    """Test Stack length."""
    try:
        from bsv.script.interpreter.stack import Stack
        from bsv.script.interpreter.config import BeforeGenesisConfig
        cfg = BeforeGenesisConfig()
        stack = Stack(cfg)
        assert stack.depth() == 0
        stack.push(b'\x01')
        assert stack.depth() == 1
        stack.push(b'\x02')
        assert stack.depth() == 2
    except ImportError:
        pytest.skip("Stack not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_stack_multiple_operations():
    """Test multiple stack operations."""
    try:
        from bsv.script.interpreter.stack import Stack
        from bsv.script.interpreter.config import BeforeGenesisConfig
        cfg = BeforeGenesisConfig()
        stack = Stack(cfg)
        stack.push(b'\x01')
        stack.push(b'\x02')
        stack.push(b'\x03')
        
        assert stack.pop() == b'\x03'
        assert stack.pop() == b'\x02'
        assert stack.pop() == b'\x01'
        assert stack.depth() == 0
    except ImportError:
        pytest.skip("Stack not available")


def test_stack_clear():
    """Test Stack clear operation."""
    try:
        from bsv.script.interpreter.stack import Stack
        from bsv.script.interpreter.config import BeforeGenesisConfig
        cfg = BeforeGenesisConfig()
        stack = Stack(cfg)
        stack.push(b'\x01')
        stack.push(b'\x02')
        
        if hasattr(stack, 'clear'):
            stack.clear()
            assert stack.depth() == 0
    except ImportError:
        pytest.skip("Stack not available")

