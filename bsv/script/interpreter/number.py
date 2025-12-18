"""
Script number handling for interpreter.

Ported from go-sdk/script/interpreter/number.go
"""

from typing import Optional


# Constants
ERROR_NON_MINIMAL_ENCODING = "non-minimally encoded script number"


class ScriptNumber:
    """ScriptNumber represents a number used in Bitcoin scripts."""

    def __init__(self, value: int):  # NOSONAR - Complexity (18), requires refactoring
        """Initialize a ScriptNumber with an integer value."""
        self.value = value

    @classmethod
    def _validate_minimal_encoding(cls, data: bytes) -> None:
        """Validate that the byte encoding is minimal."""
        # Port of go-sdk minimal encoding rules:
        # - If the most significant byte is 0x00 or 0x80, it is only allowed when needed
        #   to prevent a sign bit conflict with the next-most-significant byte.
        # - This rejects non-minimal encodings such as {0x00} for 0, and {0x80} for -0.
        if len(data) == 0:
            return
        if (data[-1] & 0x7F) == 0 and (len(data) == 1 or (data[-2] & 0x80) == 0):
            raise ValueError(ERROR_NON_MINIMAL_ENCODING)

    @classmethod
    def _decode_little_endian(cls, data: bytes) -> int:
        """Decode bytes as little-endian integer with sign bit handling."""
        result = 0
        for i, byte_val in enumerate(data):
            result |= byte_val << (i * 8)
        
        # Handle sign bit
        if data[-1] & 0x80:
            sign_bit_mask = 0x80 << (8 * (len(data) - 1))
            result &= ~sign_bit_mask
            result = -result
        
        return result

    @classmethod
    def from_bytes(cls, data: bytes, max_num_len: int = 4, require_minimal: bool = True) -> "ScriptNumber":
        """
        Create a ScriptNumber from bytes using Bitcoin script number encoding.
        
        Args:
            data: The byte array to parse
            max_num_len: Maximum number length in bytes
            require_minimal: Whether to require minimal encoding
        """
        # Zero is encoded as empty byte slice
        if len(data) == 0:
            return cls(0)
        
        if len(data) > max_num_len:
            raise ValueError(f"number exceeds max length: {len(data)} > {max_num_len}")
        
        # Check for minimal encoding
        if require_minimal:
            cls._validate_minimal_encoding(data)
        
        # Decode from little endian with sign handling
        result = cls._decode_little_endian(data)
        
        return cls(result)

    def bytes(self, require_minimal: bool = True) -> bytes:
        """Convert ScriptNumber to bytes using Bitcoin script number encoding.
        
        Bitcoin uses sign-magnitude representation where the high bit of the
        last byte indicates the sign.
        """
        # Zero encodes as empty byte slice
        if self.value == 0:
            return b""
        
        # Take absolute value and track if negative
        is_negative = self.value < 0
        abs_value = abs(self.value)
        
        # Encode absolute value in little-endian
        result = []
        while abs_value > 0:
            result.append(abs_value & 0xFF)
            abs_value >>= 8
        
        # When the most significant byte already has the high bit set (0x80),
        # an additional high byte is required to indicate whether the number
        # is negative or positive. The additional byte is removed when converting
        # back to an integral and its high bit is used to denote the sign.
        #
        # Otherwise, when the most significant byte does not already have the
        # high bit set, use it to indicate the value is negative, if needed.
        if result[-1] & 0x80:
            # Need extra byte
            if is_negative:
                result.append(0x80)
            else:
                result.append(0x00)
        elif is_negative:
            # Set the sign bit on the last byte
            result[-1] |= 0x80
        
        return bytes(result)
    
    def to_bytes(self, require_minimal: bool = True) -> bytes:
        """Alias for bytes() method for compatibility."""
        return self.bytes(require_minimal)

    def __int__(self) -> int:
        """Convert to integer."""
        return self.value

    def __repr__(self) -> str:
        return f"ScriptNumber({self.value})"

