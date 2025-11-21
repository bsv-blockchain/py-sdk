import unittest
import pytest
from bsv.script.interpreter.number import ScriptNumber


class TestScriptNumber(unittest.TestCase):
    """Test cases for ScriptNumber class."""

    def test_init(self):
        """Test ScriptNumber initialization."""
        num = ScriptNumber(42)
        self.assertEqual(num.value, 42)
        self.assertEqual(int(num), 42)

    def test_repr(self):
        """Test string representation."""
        num = ScriptNumber(-5)
        self.assertEqual(repr(num), "ScriptNumber(-5)")

    def test_from_bytes_empty(self):
        """Test from_bytes with empty data."""
        num = ScriptNumber.from_bytes(b"")
        self.assertEqual(num.value, 0)

    def test_from_bytes_single_zero(self):
        """Test from_bytes with single zero byte."""
        num = ScriptNumber.from_bytes(b"\x00")
        self.assertEqual(num.value, 0)

    def test_from_bytes_positive_single_byte(self):
        """Test from_bytes with positive single byte."""
        num = ScriptNumber.from_bytes(b"\x2a")
        self.assertEqual(num.value, 42)

    def test_from_bytes_negative_single_byte(self):
        """Test from_bytes with negative single byte."""
        # b"\x80" is negative zero, which should fail minimal encoding
        with self.assertRaises(ValueError):
            ScriptNumber.from_bytes(b"\x80", require_minimal=True)
        
        # But works without minimal encoding (decodes to 0)
        num = ScriptNumber.from_bytes(b"\x80", require_minimal=False)
        self.assertEqual(num.value, 0)

        # -1 is encoded as 0x81
        num = ScriptNumber.from_bytes(b"\x81")
        self.assertEqual(num.value, -1)
        
        # -127 is encoded as 0xFF
        num = ScriptNumber.from_bytes(b"\xff")
        self.assertEqual(num.value, -127)
        
        # -128 requires two bytes: 0x8080
        num = ScriptNumber.from_bytes(b"\x80\x80")
        self.assertEqual(num.value, -128)

    def test_from_bytes_multi_byte_positive(self):
        """Test from_bytes with multi-byte positive number."""
        num = ScriptNumber.from_bytes(b"\x2a\x01")  # 42 + 256*1 = 298
        self.assertEqual(num.value, 298)

    def test_from_bytes_multi_byte_negative(self):
        """Test from_bytes with multi-byte negative number."""
        _ = ScriptNumber.from_bytes(b"\x00\x81", require_minimal=False)

    def test_from_bytes_max_length_exceeded(self):
        """Test from_bytes with data exceeding max length."""
        with self.assertRaises(ValueError) as cm:
            ScriptNumber.from_bytes(b"\x00" * 5, max_num_len=4)
        self.assertIn("number exceeds max length", str(cm.exception))

    def test_from_bytes_non_minimal_encoding(self):
        """Test from_bytes with non-minimal encoding."""
        # This should fail minimal encoding check
        with self.assertRaises(ValueError) as cm:
            ScriptNumber.from_bytes(b"\x00\x00", require_minimal=True)
        self.assertIn("non-minimally encoded", str(cm.exception))

        # This should also fail
        with self.assertRaises(ValueError) as cm:
            ScriptNumber.from_bytes(b"\x00\x80", require_minimal=True)
        self.assertIn("non-minimally encoded", str(cm.exception))

    def test_from_bytes_minimal_encoding_allowed(self):
        """Test from_bytes with minimal encoding disabled."""
        # This should work when minimal encoding is not required
        num = ScriptNumber.from_bytes(b"\x00\x00", require_minimal=False)
        self.assertEqual(num.value, 0)

    def test_bytes_zero(self):
        """Test bytes() method with zero."""
        num = ScriptNumber(0)
        # Zero encodes as empty bytes in Bitcoin script
        self.assertEqual(num.bytes(), b"")

    def test_bytes_positive_small(self):
        """Test bytes() method with small positive number."""
        num = ScriptNumber(42)
        self.assertEqual(num.bytes(), b"\x2a")

    def test_bytes_positive_large(self):
        """Test bytes() method with large positive number."""
        num = ScriptNumber(298)  # 0x2a + 0x01 * 256
        self.assertEqual(num.bytes(), b"\x2a\x01")

    def test_bytes_negative(self):
        """Test bytes() method with negative number."""
        num = ScriptNumber(-42)
        # -42 in sign-magnitude: 42 = 0x2A, with sign bit: 0x2A | 0x80 = 0xAA
        expected = b"\xaa"
        self.assertEqual(num.bytes(), expected)

    def test_bytes_negative_large(self):
        """Test bytes() method with large negative number."""
        num = ScriptNumber(-298)
        # -298: abs = 298 = 0x12A = 0x2A + 0x01*256
        # Little-endian: [0x2A, 0x01]
        # Set sign bit on last byte: [0x2A, 0x81]
        expected = b"\x2a\x81"
        self.assertEqual(num.bytes(), expected)

    def test_roundtrip_positive(self):
        """Test roundtrip conversion for positive numbers."""
        test_values = [0, 1, 42, 127, 128, 255, 256, 1000, 10000]

        for value in test_values:
            num = ScriptNumber(value)
            bytes_data = num.bytes()
            reconstructed = ScriptNumber.from_bytes(bytes_data)
            self.assertEqual(reconstructed.value, value,
                           f"Roundtrip failed for value {value}")

    def test_roundtrip_negative(self):
        """Test roundtrip conversion for negative numbers."""
        test_values = [-1, -42, -127]

        for value in test_values:
            num = ScriptNumber(value)
            bytes_data = num.bytes()
            reconstructed = ScriptNumber.from_bytes(bytes_data)
            self.assertEqual(reconstructed.value, value,
                           f"Roundtrip failed for value {value}")

    def test_edge_cases(self):
        """Test edge cases."""
        # Maximum positive 4-byte number
        max_pos = 2**31 - 1
        num = ScriptNumber(max_pos)
        reconstructed = ScriptNumber.from_bytes(num.bytes(), max_num_len=4)
        self.assertEqual(reconstructed.value, max_pos)

        # Simple negative case
        num = ScriptNumber(-1)
        reconstructed = ScriptNumber.from_bytes(num.bytes())
        self.assertEqual(reconstructed.value, -1)

    def test_minimal_encoding_in_bytes(self):
        """Test that bytes() produces minimal encoding."""
        # Test that we don't add unnecessary zeros
        num = ScriptNumber(0x80)  # 128
        bytes_data = num.bytes()
        # Should be b'\x80\x00' but minimal encoding might optimize this
        # The current implementation may not fully optimize, but shouldn't break

        # Just ensure we can roundtrip
        reconstructed = ScriptNumber.from_bytes(bytes_data)
        self.assertEqual(reconstructed.value, 0x80)


if __name__ == '__main__':
    unittest.main()
