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
            # Check if we have unnecessary leading zeros
            if data[-1] == 0x00 and (data[-2] & 0x80) == 0:
                raise ValueError("non-minimally encoded script number")
            # Check if we have 0x80 followed by zeros (would be -0)
            if data[-1] == 0x80 and len(data) > 1 and all(b == 0 for b in data[:-1]):
                raise ValueError("non-minimally encoded script number")
        
        # Parse the number
        if len(data) == 1:
            byte_val = data[0]
            if byte_val == 0:
                return cls(0)
            if (byte_val & 0x80) == 0:
                # Positive number
                return cls(byte_val)
            else:
                # Negative number
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

        # For negative numbers, use two's complement
        if self.value < 0:
            # Calculate two's complement
            abs_value = abs(self.value)
            # Find the minimum number of bytes needed
            if abs_value <= 0x80:
                # Can fit in one byte
                complement = (256 - abs_value) & 0xFF
                return bytes([complement])
            else:
                # Multi-byte two's complement
                result = []
                temp = (1 << (abs_value.bit_length() + 1)) - abs_value
                while temp > 0 or len(result) == 0:
                    result.append(temp & 0xFF)
                    temp >>= 8
                return bytes(result)

        # For positive numbers
        abs_value = self.value
        result = []
        while abs_value > 0:
            result.append(abs_value & 0xFF)
            abs_value >>= 8

        # Ensure the highest byte doesn't have the sign bit set
        if len(result) > 0 and (result[-1] & 0x80) != 0:
            result.append(0x00)

        # Minimal encoding
        if require_minimal and len(result) > 1:
            while len(result) > 1 and result[-1] == 0 and (result[-2] & 0x80) == 0:
                result.pop()

        return bytes(result)

    def __int__(self) -> int:
        """Convert to integer."""
        return self.value

    def __repr__(self) -> str:
        return f"ScriptNumber({self.value})"

