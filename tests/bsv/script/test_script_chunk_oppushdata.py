import pytest
from bsv.script.script import Script
from bsv.constants import OpCode


def test_script_build_chunks_pushdata_opcodes():
    """
    Test that the Script._build_chunks method correctly handles PUSHDATA opcodes
    when changing the reading method from byte-by-int to unit-based reading.
    """

    # Test PUSHDATA1 with a length value that would be negative if incorrectly interpreted as signed
    # 0xff = 255 bytes of data
    pushdata1_high_length = b'\x4c\xff' + b'\x42' * 255
    script_pushdata1 = Script(pushdata1_high_length)
    assert len(script_pushdata1.chunks) == 1
    assert script_pushdata1.chunks[0].op == OpCode.OP_PUSHDATA1
    assert script_pushdata1.chunks[0].data == b'\x42' * 255
    assert len(script_pushdata1.chunks[0].data) == 255

    # Test with smaller data sizes to ensure consistent behavior
    pushdata1_75 = b'\x4c\xff' + b'\x42' * 75
    script_pushdata1_75 = Script(pushdata1_75)
    assert len(script_pushdata1_75.chunks) == 1
    assert script_pushdata1_75.chunks[0].op == OpCode.OP_PUSHDATA1
    assert script_pushdata1_75.chunks[0].data == b'\x42' * 75

    pushdata1_76 = b'\x4c\xff' + b'\x42' * 76
    script_pushdata1_76 = Script(pushdata1_76)
    assert len(script_pushdata1_76.chunks) == 1
    assert script_pushdata1_76.chunks[0].op == OpCode.OP_PUSHDATA1
    assert script_pushdata1_76.chunks[0].data == b'\x42' * 76

    # Test PUSHDATA2 with a length value that would be negative if incorrectly interpreted as signed
    # 0xffff = 65535 bytes of data
    pushdata2_high_length = b'\x4d\xff\xff' + b'\x42' * 65535
    script_pushdata2 = Script(pushdata2_high_length)
    assert len(script_pushdata2.chunks) == 1
    assert script_pushdata2.chunks[0].op == OpCode.OP_PUSHDATA2
    assert script_pushdata2.chunks[0].data == b'\x42' * 65535
    assert len(script_pushdata2.chunks[0].data) == 65535

    # Test with smaller data sizes for PUSHDATA2
    pushdata2_255 = b'\x4d\xff\xff' + b'\x42' * 255
    script_pushdata2_255 = Script(pushdata2_255)
    assert len(script_pushdata2_255.chunks) == 1
    assert script_pushdata2_255.chunks[0].op == OpCode.OP_PUSHDATA2
    assert script_pushdata2_255.chunks[0].data == b'\x42' * 255

    pushdata2_256 = b'\x4d\xff\xff' + b'\x42' * 256
    script_pushdata2_256 = Script(pushdata2_256)
    assert len(script_pushdata2_256.chunks) == 1
    assert script_pushdata2_256.chunks[0].op == OpCode.OP_PUSHDATA2
    assert script_pushdata2_256.chunks[0].data == b'\x42' * 256

    # Test PUSHDATA4 with values that would be negative if interpreted as signed integers
    # Test with very large value - 0x80000001 = 2,147,483,649 (would be -2,147,483,647 as signed int32)
    # Note: This test may require significant memory
    pushdata4_large_value = b'\x4e\x01\x00\x00\x80' + b'\x42' * 2147483649
    script_pushdata4_large = Script(pushdata4_large_value)
    assert len(script_pushdata4_large.chunks) == 1
    assert script_pushdata4_large.chunks[0].op == OpCode.OP_PUSHDATA4
    assert len(script_pushdata4_large.chunks[0].data) == 2147483649

    # Test with smaller data sizes for PUSHDATA4
    pushdata4_upper_half = b'\x4e\x00\x00\x00\xC0' + b'\x43' * 65535
    script_pushdata4_upper_half = Script(pushdata4_upper_half)
    assert len(script_pushdata4_upper_half.chunks) == 1
    assert script_pushdata4_upper_half.chunks[0].op == OpCode.OP_PUSHDATA4
    assert len(script_pushdata4_upper_half.chunks[0].data) == 65535

    # Test with slightly larger data size
    pushdata4_upper_half_2 = b'\x4e\x00\x00\x00\xC0' + b'\x43' * 65536
    script_pushdata4_upper_half_2 = Script(pushdata4_upper_half_2)
    assert len(script_pushdata4_upper_half_2.chunks) == 1
    assert script_pushdata4_upper_half_2.chunks[0].op == OpCode.OP_PUSHDATA4
    assert len(script_pushdata4_upper_half_2.chunks[0].data) == 65536

    # Test boundary cases where the length is exactly at important thresholds
    # PUSHDATA1 with length 0
    pushdata1_zero = b'\x4c\x00'
    script_pushdata1_zero = Script(pushdata1_zero)
    assert len(script_pushdata1_zero.chunks) == 1
    assert script_pushdata1_zero.chunks[0].op == OpCode.OP_PUSHDATA1
    assert script_pushdata1_zero.chunks[0].data == b''
    assert len(script_pushdata1_zero.chunks[0].data) == 0

    # Edge case: PUSHDATA with incomplete length specification
    incomplete_pushdata1 = b'\x4c'  # PUSHDATA1 without length byte
    script_incomplete1 = Script(incomplete_pushdata1)
    assert len(script_incomplete1.chunks) == 1
    assert script_incomplete1.chunks[0].op == OpCode.OP_PUSHDATA1
    assert script_incomplete1.chunks[0].data is None

    incomplete_pushdata2 = b'\x4d\xff'  # PUSHDATA2 with incomplete length (only one byte)
    script_incomplete2 = Script(incomplete_pushdata2)
    assert len(script_incomplete2.chunks) == 1
    assert script_incomplete2.chunks[0].op == OpCode.OP_PUSHDATA2
    assert script_incomplete2.chunks[0].data == b''

    # Edge case: PUSHDATA with specified length but insufficient data
    insufficient_data1 = b'\x4c\x0A\x01\x02\x03'  # PUSHDATA1 expecting 10 bytes but only 3 are provided
    script_insufficient1 = Script(insufficient_data1)
    assert len(script_insufficient1.chunks) == 1
    assert script_insufficient1.chunks[0].op == OpCode.OP_PUSHDATA1
    assert script_insufficient1.chunks[0].data == b'\x01\x02\x03'  # Should get the available data

    # Multiple PUSHDATA opcodes in sequence to test parsing continuity
    mixed_pushdata = (
        b'\x4c\x03\x01\x02\x03'  # PUSHDATA1 with 3 bytes
        b'\x4d\x04\x00\x04\x05\x06\x07'  # PUSHDATA2 with 4 bytes
        b'\x02\x08\x09'  # Direct push of 2 bytes
    )
    script_mixed = Script(mixed_pushdata)
    assert len(script_mixed.chunks) == 3
    assert script_mixed.chunks[0].op == OpCode.OP_PUSHDATA1
    assert script_mixed.chunks[0].data == b'\x01\x02\x03'
    assert script_mixed.chunks[1].op == OpCode.OP_PUSHDATA2
    assert script_mixed.chunks[1].data == b'\x04\x05\x06\x07'
    assert script_mixed.chunks[2].op == b'\x02'
    assert script_mixed.chunks[2].data == b'\x08\x09'


def test_script_serialization_with_pushdata():
    """
    Test that serialization and deserialization of scripts with PUSHDATA opcodes work correctly.

    This test verifies that scripts containing PUSHDATA opcodes can be:
    1. Serialized back to their original binary form
    2. Deserialized from binary to produce identical Script objects with properly parsed chunks

    This ensures the round-trip integrity of Script objects with various PUSHDATA operations.
    """
    # Create a script with various PUSHDATA opcodes and direct push data
    original_script = (
        b'\x4c\x03\x01\x02\x03'  # PUSHDATA1 with 3 bytes
        b'\x4d\x04\x00\x04\x05\x06\x07'  # PUSHDATA2 with 4 bytes
        b'\x02\x08\x09'  # Direct push of 2 bytes
    )

    script = Script(original_script)

    # Serialize and deserialize the script
    serialized = script.serialize()
    deserialized = Script(serialized)

    # Verify the scripts are equivalent
    assert serialized == original_script
    assert deserialized.serialize() == original_script

    # Check that the chunks are correctly parsed
    assert len(deserialized.chunks) == 3
    assert deserialized.chunks[0].op == OpCode.OP_PUSHDATA1
    assert deserialized.chunks[0].data == b'\x01\x02\x03'
    assert deserialized.chunks[1].op == OpCode.OP_PUSHDATA2
    assert deserialized.chunks[1].data == b'\x04\x05\x06\x07'
    assert deserialized.chunks[2].op == b'\x02'
    assert deserialized.chunks[2].data == b'\x08\x09'


if __name__ == "__main__":
    test_script_build_chunks_pushdata_opcodes()
    test_script_serialization_with_pushdata()
    print("All tests passed!")
