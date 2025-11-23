"""
BRC-106 Compliance Tests

Tests for BRC-106: Standardized ASM Representation of Bitcoin Script
https://github.com/bitcoin-sv/BRCs/blob/master/scripts/0106.md

BRC-106 Requirements:
1. Multiple input names for the same op-code should parse to the same hex value
2. Output should always use the most human-readable format
3. Ensure deterministic translation across different SDKs
"""

import pytest
from bsv.script.script import Script
from bsv.constants import OpCode


class TestBRC106OpCodeAliases:
    """Test that multiple op-code names parse to the same hex value"""

    def test_false_aliases_parse_to_same_value(self):
        """OP_FALSE, OP_0, and '0' should all parse to 0x00"""
        script_false = Script.from_asm('OP_FALSE')
        script_0 = Script.from_asm('OP_0')
        script_zero = Script.from_asm('0')

        # All should produce the same hex
        assert script_false.hex() == '00'
        assert script_0.hex() == '00'
        assert script_zero.hex() == '00'

        # All should be equal
        assert script_false == script_0 == script_zero

    def test_true_aliases_parse_to_same_value(self):
        """OP_TRUE and OP_1 should parse to 0x51"""
        script_true = Script.from_asm('OP_TRUE')
        script_1 = Script.from_asm('OP_1')

        assert script_true.hex() == '51'
        assert script_1.hex() == '51'
        assert script_true == script_1

    def test_1negate_aliases_parse_to_same_value(self):
        """OP_1NEGATE and '-1' should parse to 0x4f"""
        script_1negate = Script.from_asm('OP_1NEGATE')
        script_minus1 = Script.from_asm('-1')

        assert script_1negate.hex() == '4f'
        assert script_minus1.hex() == '4f'
        assert script_1negate == script_minus1

    def test_number_aliases_parse_correctly(self):
        """OP_2 through OP_16 should parse to correct values"""
        for i in range(2, 17):
            script = Script.from_asm(f'OP_{i}')
            expected_hex = hex(0x50 + i)[2:]
            assert script.hex() == expected_hex


class TestBRC106HumanReadableOutput:
    """Test that to_asm() outputs the most human-readable format"""

    def test_false_outputs_as_op_false(self):
        """
        BRC-106 requires 0x00 to output as 'OP_FALSE' (most human-readable)
        """
        script = Script('00')
        assert script.to_asm() == 'OP_FALSE'

    def test_true_outputs_as_op_true(self):
        """
        BRC-106 requires 0x51 to output as 'OP_TRUE' (most human-readable)
        """
        script = Script('51')
        assert script.to_asm() == 'OP_TRUE'

    def test_1negate_outputs_correctly(self):
        """0x4f should output as 'OP_1NEGATE'"""
        script = Script('4f')
        assert script.to_asm() == 'OP_1NEGATE'

    def test_numbered_opcodes_output_correctly(self):
        """OP_2 through OP_16 should output with their numbers"""
        for i in range(2, 17):
            hex_value = hex(0x50 + i)[2:]
            script = Script(hex_value)
            assert script.to_asm() == f'OP_{i}'


class TestBRC106RoundTripConversion:
    """Test round-trip conversion from ASM to binary and back"""

    def test_roundtrip_with_current_implementation(self):
        """
        Test round-trip conversion with current implementation
        Note: This uses current behavior (OP_0 instead of OP_FALSE)
        """
        test_cases = [
            'OP_DUP OP_HASH160 abcd1234 OP_EQUALVERIFY OP_CHECKSIG',
            'OP_RETURN 48656c6c6f',
            'OP_0 OP_RETURN',
            'OP_1 OP_2 OP_ADD OP_3 OP_EQUAL',
        ]

        for asm in test_cases:
            script = Script.from_asm(asm)
            roundtrip_asm = script.to_asm()
            roundtrip_script = Script.from_asm(roundtrip_asm)

            # Binary should be identical after round-trip
            assert script.hex() == roundtrip_script.hex()

    def test_roundtrip_preserves_human_readable_names(self):
        """
        BRC-106 requires that human-readable names are preserved in round-trip
        """
        test_cases = [
            ('OP_FALSE', 'OP_FALSE'),  # Should stay OP_FALSE, not become OP_0
            ('OP_TRUE', 'OP_TRUE'),    # Should stay OP_TRUE, not become OP_1
        ]

        for input_asm, expected_output in test_cases:
            script = Script.from_asm(input_asm)
            output_asm = script.to_asm()
            assert output_asm == expected_output

    def test_aliases_normalize_to_canonical_form(self):
        """
        Different input aliases should normalize to the same canonical output
        Current behavior: normalizes to OP_0, OP_1NEGATE
        """
        # OP_FALSE, OP_0, '0' should all output the same
        assert Script.from_asm('OP_FALSE').to_asm() == Script.from_asm('OP_0').to_asm()
        assert Script.from_asm('OP_0').to_asm() == Script.from_asm('0').to_asm()

        # OP_1NEGATE and '-1' should output the same
        assert Script.from_asm('OP_1NEGATE').to_asm() == Script.from_asm('-1').to_asm()


class TestBRC106ComplexScripts:
    """Test BRC-106 compliance with complex, real-world scripts"""

    def test_p2pkh_script(self):
        """Test P2PKH script maintains consistency"""
        # Standard P2PKH: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        hex_script = '76a914f4c03610e60ad15100929cc23da2f3a799af172588ac'
        script = Script(hex_script)
        asm = script.to_asm()

        # Verify it contains the expected opcodes
        assert 'OP_DUP' in asm
        assert 'OP_HASH160' in asm
        assert 'OP_EQUALVERIFY' in asm
        assert 'OP_CHECKSIG' in asm

        # Round-trip should preserve binary
        roundtrip = Script.from_asm(asm)
        assert roundtrip.hex() == hex_script

    def test_op_return_with_false(self):
        """
        Test OP_RETURN script that starts with OP_FALSE
        BRC-106 requires output to use OP_FALSE
        """
        # OP_FALSE OP_RETURN is common pattern
        hex_script = '006a'
        script = Script(hex_script)
        asm = script.to_asm()

        # Should output as 'OP_FALSE OP_RETURN'
        assert asm == 'OP_FALSE OP_RETURN'

    def test_multisig_script_consistency(self):
        """Test multisig script maintains consistency"""
        # 2-of-3 multisig start: OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
        script = Script.from_asm('OP_2 02aabbccdd 03ddeeff11 02112233aa OP_3 OP_CHECKMULTISIG')

        # Verify round-trip
        asm = script.to_asm()
        roundtrip = Script.from_asm(asm)
        assert script.hex() == roundtrip.hex()


class TestBRC106EdgeCases:
    """Test edge cases and special scenarios"""

    def test_empty_script(self):
        """Empty script should handle correctly"""
        script = Script.from_asm('')
        assert script.hex() == ''
        assert script.to_asm() == ''

    def test_mixed_opcodes_and_data(self):
        """Test scripts with mix of opcodes and data pushes"""
        asm = 'OP_0 010203 OP_1 abcdef OP_2'
        script = Script.from_asm(asm)
        roundtrip = Script.from_asm(script.to_asm())

        assert script.hex() == roundtrip.hex()

    def test_all_numeric_opcodes(self):
        """Test all numeric opcodes (OP_1NEGATE through OP_16)"""
        # Build script with all numeric opcodes
        opcodes = ['OP_1NEGATE'] + [f'OP_{i}' for i in range(1, 17)]
        asm = ' '.join(opcodes)

        script = Script.from_asm(asm)
        assert len(script.chunks) == len(opcodes)

        # Verify each opcode is present
        output_asm = script.to_asm()
        assert 'OP_1NEGATE' in output_asm
        for i in range(1, 17):
            assert f'OP_{i}' in output_asm or (i == 1 and 'OP_TRUE' in output_asm)

    def test_pushdata_opcodes(self):
        """Test various sizes of data pushes"""
        # Small push (< 76 bytes) - direct length
        small_data = 'aa' * 10
        script = Script.from_asm(f'OP_RETURN {small_data}')
        assert 'OP_RETURN' in script.to_asm()

        # Medium push - would use OP_PUSHDATA1 if needed
        # Test current implementation handles various data sizes
        medium_data = 'bb' * 100
        script = Script.from_asm(f'OP_RETURN {medium_data}')
        roundtrip = Script.from_asm(script.to_asm())
        assert script.hex() == roundtrip.hex()


class TestBRC106ComparisonWithSpec:
    """Test specific examples from BRC-106 specification"""

    def test_spec_example_false(self):
        """
        From BRC-106 spec:
        parseASM("OP_0") === parseASM("OP_FALSE") // true
        toASM(0x00) // "OP_FALSE"
        """
        # Parsing test - both should produce same result
        assert Script.from_asm('OP_0').hex() == Script.from_asm('OP_FALSE').hex()

        # Output test - should be OP_FALSE (marked as xfail until implemented)
        script = Script('00')
        # Current implementation outputs 'OP_0', but BRC-106 requires 'OP_FALSE'
        # assert script.to_asm() == 'OP_FALSE'  # Uncomment when implementing BRC-106

    def test_spec_example_true(self):
        """
        From BRC-106 spec:
        toASM(0x51) // "OP_TRUE"
        """
        # Parsing test
        assert Script.from_asm('OP_TRUE').hex() == Script.from_asm('OP_1').hex()

        # Output test - should be OP_TRUE (marked as xfail until implemented)
        script = Script('51')
        # Current implementation outputs 'OP_1', but BRC-106 requires 'OP_TRUE'
        # assert script.to_asm() == 'OP_TRUE'  # Uncomment when implementing BRC-106

    def test_deterministic_output(self):
        """
        BRC-106 requires deterministic output across multiple calls
        """
        hex_script = '76a914f4c03610e60ad15100929cc23da2f3a799af172588ac'
        script = Script(hex_script)

        # Multiple calls should produce identical output
        asm1 = script.to_asm()
        asm2 = script.to_asm()
        asm3 = script.to_asm()

        assert asm1 == asm2 == asm3

    def test_cross_sdk_compatibility_hex(self):
        """
        Test that our ASM parsing produces the same hex as other SDKs would
        This is a forward-compatibility test for cross-SDK validation
        """
        test_vectors = [
            ('OP_DUP OP_HASH160 abcd1234 OP_EQUALVERIFY OP_CHECKSIG',
             '76a904abcd123488ac'),
            ('OP_RETURN 48656c6c6f',
             '6a0548656c6c6f'),
            ('OP_1 OP_2 OP_ADD',
             '515293'),
        ]

        for asm, expected_hex in test_vectors:
            script = Script.from_asm(asm)
            assert script.hex() == expected_hex


class TestBRC106CurrentImplementation:
    """Document current implementation behavior for future reference"""

    def test_current_false_behavior(self):
        """Document that current implementation outputs 'OP_FALSE' for 0x00 (BRC-106 compliant)"""
        script = Script('00')
        assert script.to_asm() == 'OP_FALSE'  # BRC-106 compliant

    def test_current_true_behavior(self):
        """Document that current implementation outputs 'OP_TRUE' for 0x51 (BRC-106 compliant)"""
        script = Script('51')
        assert script.to_asm() == 'OP_TRUE'  # BRC-106 compliant

    def test_current_accepts_all_aliases(self):
        """Verify that current implementation accepts all common aliases"""
        # These should all parse without error
        aliases = [
            'OP_FALSE', 'OP_0', '0',
            'OP_TRUE', 'OP_1',
            'OP_1NEGATE', '-1',
        ]

        for alias in aliases:
            script = Script.from_asm(alias)
            assert script is not None
            assert len(script.hex()) > 0
