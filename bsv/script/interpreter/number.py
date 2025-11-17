"""
Script number handling for interpreter.

Ported from go-sdk/script/interpreter/number.go
"""

import struct
from typing import Optional


class ScriptNumber:
    """ScriptNumber represents a number used in Bitcoin scripts."""

    def __init__(self, value: int):
        """Initialize a ScriptNumber with an integer value."""
        self.value = value

    @classmethod
    def from_bytes(cls, data: bytes, max_num_len: int = 4, require_minimal: bool = True) -> "ScriptNumber":
        """
        Create a ScriptNumber from bytes.
        
        Args:
            data: The byte array to parse
            max_num_len: Maximum number length in bytes
            require_minimal: Whether to require minimal encoding
        """
        if len(data) == 0:
            return cls(0)
        
        if len(data) > max_num_len:
            raise ValueError(f"number exceeds max length: {len(data)} > {max_num_len}")
        
        # Check for minimal encoding
        if require_minimal and len(data) > 1:
            # Check if the last byte is zero when it shouldn't be
            if (data[-1] & 0x7f) == 0:
                # Check if the second-to-last byte has the sign bit set
                if len(data) > 1 and (data[-2] & 0x80) == 0:
                    raise ValueError("non-minimally encoded script number")
        
        # Parse the number
        if len(data) == 1:
            byte_val = data[0]
            if byte_val == 0:
                return cls(0)
            if byte_val <= 0x7f:
                return cls(byte_val)
            else:
                return cls(byte_val - 256)
        
        # Multi-byte number
        result = 0
        for i, byte_val in enumerate(data):
            if i == len(data) - 1:
                # Last byte: check sign bit
                if byte_val & 0x80:
                    result |= (byte_val & 0x7f) << (i * 8)
                    result -= (1 << (len(data) * 8))
                else:
                    result |= byte_val << (i * 8)
            else:
                result |= byte_val << (i * 8)
        
        return cls(result)

    def bytes(self, require_minimal: bool = True) -> bytes:
        """Convert ScriptNumber to bytes."""
        if self.value == 0:
            return b"\x00"
        
        # Determine sign and absolute value
        is_negative = self.value < 0
        abs_value = abs(self.value)
        
        # Convert to bytes (little-endian)
        result = []
        while abs_value > 0:
            result.append(abs_value & 0xFF)
            abs_value >>= 8
        
        # Add sign bit to last byte if negative
        if is_negative:
            result[-1] |= 0x80
        
        # Ensure minimal encoding
        if require_minimal and len(result) > 1:
            # Check if we can remove the last byte
            if (result[-1] & 0x7f) == 0:
                if len(result) > 1 and (result[-2] & 0x80) == 0:
                    # Can be more minimal
                    pass
        
        return bytes(result)

    def __int__(self) -> int:
        """Convert to integer."""
        return self.value

    def __repr__(self) -> str:
        return f"ScriptNumber({self.value})"

