"""
Stack operations for script interpreter.

Ported from go-sdk/script/interpreter/stack.go
"""

from typing import List, Optional, Protocol

from .config import Config
from .number import ScriptNumber


class Debugger(Protocol):
    """Debugger interface for stack operations."""

    def before_stack_push(self, data: bytes) -> None:
        """Called before pushing data to stack."""
        ...

    def after_stack_push(self, data: bytes) -> None:
        """Called after pushing data to stack."""
        ...

    def before_stack_pop(self) -> None:
        """Called before popping from stack."""
        ...

    def after_stack_pop(self, data: bytes) -> None:
        """Called after popping from stack."""
        ...


class StateHandler(Protocol):
    """State handler interface."""

    def state(self) -> dict:
        """Get current state."""
        ...

    def set_state(self, state: dict) -> None:
        """Set state."""
        ...


class NopDebugger:
    """No-op debugger implementation."""

    def before_stack_push(self, data: bytes) -> None:
        """No-op: intentionally empty for performance when debugging is disabled."""
        pass

    def after_stack_push(self, data: bytes) -> None:
        """No-op: intentionally empty for performance when debugging is disabled."""
        pass

    def before_stack_pop(self) -> None:
        """No-op: intentionally empty for performance when debugging is disabled."""
        pass

    def after_stack_pop(self, data: bytes) -> None:
        """No-op: intentionally empty for performance when debugging is disabled."""
        pass


class NopStateHandler:
    """No-op state handler implementation."""

    def state(self) -> dict:
        return {}

    def set_state(self, state: dict) -> None:
        """Intentionally empty: null object pattern."""
        pass  # NOSONAR


def as_bool(data: bytes) -> bool:
    """Get the boolean value of the byte array."""
    if len(data) == 0:
        return False
    
    for i, byte_val in enumerate(data):
        if byte_val != 0:
            # Negative 0 is also considered false
            if i == len(data) - 1 and byte_val == 0x80:
                return False
            return True
    
    return False


def from_bool(value: bool) -> bytes:
    """Convert a boolean into the appropriate byte array."""
    return b"\x01" if value else b""


class Stack:
    """Stack represents a stack of immutable objects for Bitcoin scripts."""

    def __init__(
        self,
        cfg: Config,
        verify_minimal_data: bool = True,
        debug: Optional[Debugger] = None,
        state_handler: Optional[StateHandler] = None,
    ):
        """Initialize a new stack."""
        self.stk: List[bytes] = []
        self.max_num_length = cfg.max_script_number_length()
        self.after_genesis = cfg.after_genesis()
        self.verify_minimal_data = verify_minimal_data
        self.debug = debug or NopDebugger()
        self.sh = state_handler or NopStateHandler()

    def depth(self) -> int:
        """Return the number of items on the stack."""
        return len(self.stk)

    def push_byte_array(self, data: bytes) -> None:
        """Add the given byte array to the top of the stack."""
        self.debug.before_stack_push(data)
        self.stk.append(data)
        self.debug.after_stack_push(data)

    def push_int(self, n: ScriptNumber) -> None:
        """Push a ScriptNumber onto the stack."""
        self.push_byte_array(n.bytes(self.verify_minimal_data))

    def push_bool(self, val: bool) -> None:
        """Push a boolean onto the stack."""
        self.push_byte_array(from_bool(val))

    def pop_byte_array(self) -> bytes:
        """Pop the value off the top of the stack and return it."""
        self.debug.before_stack_pop()
        if len(self.stk) == 0:
            raise ValueError("stack is empty")
        data = self.stk.pop()
        self.debug.after_stack_pop(data)
        return data

    def pop_int(self, require_minimal: bool = True) -> ScriptNumber:
        """Pop a ScriptNumber off the stack."""
        data = self.pop_byte_array()
        return ScriptNumber.from_bytes(data, self.max_num_length, require_minimal)

    def pop_bool(self) -> bool:
        """Pop a boolean off the stack."""
        data = self.pop_byte_array()
        return as_bool(data)

    def peek_byte_array(self, idx: int) -> bytes:
        """Peek at the value at the given index (0 = top)."""
        if idx < 0 or idx >= len(self.stk):
            raise ValueError(f"invalid stack index: {idx}")
        return self.stk[-(idx + 1)]

    def peek_int(self, idx: int, require_minimal: bool = True) -> ScriptNumber:
        """Peek at a ScriptNumber at the given index."""
        data = self.peek_byte_array(idx)
        return ScriptNumber.from_bytes(data, self.max_num_length, require_minimal)

    def peek_bool(self, idx: int) -> bool:
        """Peek at a boolean at the given index."""
        data = self.peek_byte_array(idx)
        return as_bool(data)

    def nip_n(self, idx: int) -> bytes:
        """Remove the item at the given index and return it."""
        if idx < 0 or idx >= len(self.stk):
            raise ValueError(f"invalid stack index: {idx}")
        return self.stk.pop(-(idx + 1))

    def nop_n(self, idx: int) -> bytes:
        """Get the item at the given index without removing it."""
        return self.peek_byte_array(idx)

    def drop_n(self, n: int) -> None:
        """Remove the top n items from the stack."""
        if n < 0 or n > len(self.stk):
            raise ValueError(f"invalid drop count: {n}")
        for _ in range(n):
            self.pop_byte_array()

    def dup_n(self, n: int) -> None:
        """Duplicate the top n items."""
        if n < 0 or n > len(self.stk):
            raise ValueError(f"invalid dup count: {n}")
        if len(self.stk) < n:
            raise ValueError("not enough items on stack")
        items = [self.stk[-(i + 1)] for i in range(n)]
        for item in reversed(items):
            self.push_byte_array(item)

    def swap_n(self, n: int) -> None:
        """Swap the top n items with the next n items."""
        if n < 0 or n * 2 > len(self.stk):
            raise ValueError(f"invalid swap count: {n}")
        top_n = [self.pop_byte_array() for _ in range(n)]
        next_n = [self.pop_byte_array() for _ in range(n)]
        for item in reversed(next_n):
            self.push_byte_array(item)
        for item in reversed(top_n):
            self.push_byte_array(item)

    def rot_n(self, n: int) -> None:
        """Rotate the top 3n items, moving the top n to the bottom."""
        if n < 0 or n * 3 > len(self.stk):
            raise ValueError(f"invalid rot count: {n}")
        top_n = [self.pop_byte_array() for _ in range(n)]
        mid_n = [self.pop_byte_array() for _ in range(n)]
        bot_n = [self.pop_byte_array() for _ in range(n)]
        for item in reversed(bot_n):
            self.push_byte_array(item)
        for item in reversed(top_n):
            self.push_byte_array(item)
        for item in reversed(mid_n):
            self.push_byte_array(item)

    def over_n(self, n: int) -> None:
        """Copy the n items starting at position 2n to the top."""
        if n < 0 or n * 2 > len(self.stk):
            raise ValueError(f"invalid over count: {n}")
        items = [self.stk[-(2 * n + i + 1)] for i in range(n)]
        for item in reversed(items):
            self.push_byte_array(item)

    def pick_n(self, n: int) -> None:
        """Copy the n items starting at position n to the top."""
        if n < 0 or n > len(self.stk):
            raise ValueError(f"invalid pick count: {n}")
        items = [self.stk[-(n + i + 1)] for i in range(n)]
        for item in reversed(items):
            self.push_byte_array(item)

    def roll_n(self, n: int) -> None:
        """Move the n items starting at position n to the top."""
        if n < 0 or n > len(self.stk):
            raise ValueError(f"invalid roll count: {n}")
        items = [self.stk.pop(-(n + i + 1)) for i in range(n)]
        for item in reversed(items):
            self.push_byte_array(item)
    
    # Convenience methods for common operations
    def push(self, data: bytes) -> None:
        """Alias for push_byte_array."""
        self.push_byte_array(data)
    
    def pop(self) -> bytes:
        """Alias for pop_byte_array."""
        return self.pop_byte_array()
    
    def peek(self, idx: int = 0) -> bytes:
        """Alias for peek_byte_array."""
        return self.peek_byte_array(idx)
    
    def dup(self) -> None:
        """Duplicate the top item on the stack."""
        self.dup_n(1)
    
    def swap(self) -> None:
        """Swap the top two items on the stack."""
        if len(self.stk) < 2:
            raise ValueError("not enough items on stack to swap")
        # Pop the top two items
        top = self.pop_byte_array()
        second = self.pop_byte_array()
        # Push them back in swapped order
        self.push_byte_array(top)
        self.push_byte_array(second)

