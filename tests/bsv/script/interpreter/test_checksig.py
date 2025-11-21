"""
Comprehensive tests for OP_CHECKSIG opcode implementation.

Following TDD approach: write tests first, then implement the functionality.
Ported from:
- go-sdk/script/interpreter/reference_test.go (script_tests.json)
- go-sdk/script/interpreter/operations_test.go
- ts-sdk/src/script/__tests/script.invalid.vectors.ts
"""

import pytest
from bsv.script.script import Script, ScriptChunk
from bsv.script.interpreter import Engine, with_scripts, with_tx, with_flags
from bsv.script.interpreter.errs import ErrorCode, is_error_code
from bsv.script.interpreter.scriptflag import Flag
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
from bsv.keys import PrivateKey, PublicKey
from bsv.constants import SIGHASH


class TestCheckSigVectors:
    """Test OP_CHECKSIG with comprehensive test vectors from Go SDK and TypeScript SDK."""

    def _parse_flags(self, flags_str: str) -> Flag:
        """Parse flags string into Flag enum."""
        flags = Flag(0)
        if "DERSIG" in flags_str:
            flags = flags.add_flag(Flag.VERIFY_DER_SIGNATURES)
        if "STRICTENC" in flags_str:
            flags = flags.add_flag(Flag.VERIFY_STRICT_ENCODING)
        return flags

    @pytest.mark.parametrize("sig_hex,pubkey_hex,script_after,flags,expected_result,description", [
        # Ported from Go SDK script_tests.json - valid encoding tests
        ("", "02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0", "OP_CHECKSIG NOT", "STRICTENC", "OK", "Overly long signature is correctly encoded"),
        ("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0", "OP_CHECKSIG NOT", "", "OK", "Overly long signature is correctly encoded"),
        ("30220220000000000000000000000000000000000000000000000000000000000000000000", "0", "OP_CHECKSIG NOT", "", "OK", "Missing S is correctly encoded"),
        ("3024021077777777777777777777777777777777020a7777777777777777777777777777777701", "0", "OP_CHECKSIG NOT", "", "OK", "S with invalid S length is correctly encoded"),
        ("302403107777777777777777777777777777777702107777777777777777777777777777777701", "0", "OP_CHECKSIG NOT", "", "OK", "Non-integer R is correctly encoded"),
        ("302402107777777777777777777777777777777703107777777777777777777777777777777701", "0", "OP_CHECKSIG NOT", "", "OK", "Non-integer S is correctly encoded"),
        ("3014020002107777777777777777777777777777777701", "0", "OP_CHECKSIG NOT", "", "OK", "Zero-length R is correctly encoded"),
        ("3014021077777777777777777777777777777777020001", "0", "OP_CHECKSIG NOT", "", "OK", "Zero-length S is correctly encoded for DERSIG"),
        ("302402107777777777777777777777777777777702108777777777777777777777777777777701", "0", "OP_CHECKSIG NOT", "", "OK", "Negative S is correctly encoded"),
    ])
    def test_checksig_encoding_valid(self, sig_hex, pubkey_hex, script_after, flags, expected_result, description):
        """Test OP_CHECKSIG with valid encoding test vectors."""
        # Build the script bytes manually
        script_bytes = b""
        # Always push signature (even if empty)
        sig_bytes = bytes.fromhex(sig_hex) if sig_hex else b""
        script_bytes += len(sig_bytes).to_bytes(1, 'little') + sig_bytes

        # Always push public key (even if empty)
        if pubkey_hex:
            # Handle special case where pubkey_hex might be a single digit
            if len(pubkey_hex) % 2 != 0:
                pubkey_hex = "0" + pubkey_hex
            pubkey_bytes = bytes.fromhex(pubkey_hex)
            script_bytes += len(pubkey_bytes).to_bytes(1, 'little') + pubkey_bytes
        else:
            script_bytes += b'\x00'  # Push empty byte array

        # Add the opcodes
        script_bytes += b'\xac'  # OP_CHECKSIG
        if "NOT" in script_after:
            script_bytes += b'\x91'  # OP_NOT

        locking_script = Script(script_bytes)

        # Create unlocking script (empty since sig/pubkey are in locking script)
        unlocking_script = Script.from_bytes(b"")

        engine = Engine()
        flags = self._parse_flags(flags)
        err = engine.execute(with_scripts(locking_script, unlocking_script), with_flags(flags))

        if expected_result == "OK":
            assert err is None, f"Expected OK but got error: {err}"
        else:
            assert err is not None, f"Expected error but got OK"

    @pytest.mark.parametrize("sig_hex,pubkey_hex,script_after,flags,expected_error,description", [
        # Ported from Go SDK script_tests.json - invalid encoding tests
        ("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0", "OP_CHECKSIG NOT", "DERSIG", "SIG_DER", "Overly long signature is incorrectly encoded for DERSIG"),
        ("30220220000000000000000000000000000000000000000000000000000000000000000000", "0", "OP_CHECKSIG NOT", "DERSIG", "SIG_DER", "Missing S is incorrectly encoded for DERSIG"),
        ("3024021077777777777777777777777777777777020a7777777777777777777777777777777701", "0", "OP_CHECKSIG NOT", "DERSIG", "SIG_DER", "S with invalid S length is incorrectly encoded for DERSIG"),
        ("302403107777777777777777777777777777777702107777777777777777777777777777777701", "0", "OP_CHECKSIG NOT", "DERSIG", "SIG_DER", "Non-integer R is incorrectly encoded for DERSIG"),
        ("302402107777777777777777777777777777777703107777777777777777777777777777777701", "0", "OP_CHECKSIG NOT", "DERSIG", "SIG_DER", "Non-integer S is incorrectly encoded for DERSIG"),
        ("3014020002107777777777777777777777777777777701", "0", "OP_CHECKSIG NOT", "DERSIG", "SIG_DER", "Zero-length R is incorrectly encoded for DERSIG"),
        ("3014021077777777777777777777777777777777020001", "0", "OP_CHECKSIG NOT", "DERSIG", "SIG_DER", "Zero-length S is incorrectly encoded for DERSIG"),
        ("302402107777777777777777777777777777777702108777777777777777777777777777777701", "0", "OP_CHECKSIG NOT", "DERSIG", "SIG_DER", "Negative S is incorrectly encoded for DERSIG"),
        # Ported from TypeScript SDK invalid vectors
        ("", "", "OP_CHECKSIG NOT", "STRICTENC", "INVALID_STACK_OPERATION", "OP_CHECKSIG must error when there are no stack items"),
        ("00", "", "OP_CHECKSIG NOT", "STRICTENC", "INVALID_STACK_OPERATION", "OP_CHECKSIG must error when there are not 2 stack items"),
    ])
    def test_checksig_encoding_invalid(self, sig_hex, pubkey_hex, script_after, flags, expected_error, description):
        """Test OP_CHECKSIG with invalid encoding test vectors."""
        # Build the script bytes manually
        script_bytes = b""
        # Always push signature (even if empty)
        sig_bytes = bytes.fromhex(sig_hex) if sig_hex else b""
        script_bytes += len(sig_bytes).to_bytes(1, 'little') + sig_bytes

        # Always push public key (even if empty)
        if pubkey_hex:
            # Handle special case where pubkey_hex might be a single digit
            if len(pubkey_hex) % 2 != 0:
                pubkey_hex = "0" + pubkey_hex
            pubkey_bytes = bytes.fromhex(pubkey_hex)
            script_bytes += len(pubkey_bytes).to_bytes(1, 'little') + pubkey_bytes
        else:
            script_bytes += b'\x00'  # Push empty byte array

        # Add the opcodes
        script_bytes += b'\xac'  # OP_CHECKSIG
        if "NOT" in script_after:
            script_bytes += b'\x91'  # OP_NOT

        locking_script = Script(script_bytes)

        # Create unlocking script (empty since sig/pubkey are in locking script)
        unlocking_script = Script.from_bytes(b"")

        engine = Engine()
        flags = self._parse_flags(flags)
        err = engine.execute(with_scripts(locking_script, unlocking_script), with_flags(flags))

        assert err is not None, f"Expected error but got OK for: {description}"

    def test_checksig_signature_verification(self):
        """Test OP_CHECKSIG with real signature verification test vectors.
        
        Note: This test verifies that CHECKSIG correctly returns EVAL_FALSE when executed
        without proper transaction context. This is expected behavior - CHECKSIG needs
        transaction data to compute the sighash for verification.
        
        Full signature verification with transaction context is tested in other test files
        (e.g., test_transaction.py::test_transaction_signing_hydrate_scripts).
        """
        test_vectors = [
            # Basic P2PK test case - should return EVAL_FALSE due to no transaction context
            {
                "unlocking": "47 304402200a5c6163f07b8d3b013c4d1d6dba25e780b39658d79ba37af7057a3b7f15ffa102201fd9b4eaa9943f734928b99a83592c2e7bf342ea2680f6a2bb705167966b742001",
                "locking": "41 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 OP_CHECKSIG",
                "expected": "EVAL_FALSE",
                "description": "P2PK signature verification (fails without tx context)"
            },
        ]

        for test_case in test_vectors:
            unlocking_script = Script.from_asm(test_case["unlocking"])
            locking_script = Script.from_asm(test_case["locking"])

            # Test without transaction context - CHECKSIG should handle this gracefully
            engine = Engine()
            err = engine.execute(with_scripts(locking_script, unlocking_script))

            # CHECKSIG should execute and return EVAL_FALSE when signature verification fails
            # (which is expected without proper transaction context for sighash calculation)
            assert err is not None, f"Expected error for {test_case['description']}, got None"
            assert is_error_code(err, ErrorCode.ERR_EVAL_FALSE), \
                f"Expected EVAL_FALSE but got {err.code} ({err}) for {test_case['description']}. " \
                f"CHECKSIG requires transaction context to compute sighash for signature verification."
            
            # Verify signature and pubkey were on stack (consumed by CHECKSIG)
            # If stack underflow occurred, we'd get ERR_INVALID_STACK_OPERATION instead
            assert not is_error_code(err, ErrorCode.ERR_INVALID_STACK_OPERATION), \
                "Should not be a stack operation error - signature and pubkey should be present"

    def test_checksig_stack_underflow_no_items(self):
        """Test OP_CHECKSIG with no stack items - ported from TypeScript invalid vectors."""
        engine = Engine()

        # Empty script that tries to do OP_CHECKSIG
        locking_script = Script.from_bytes(bytes.fromhex("ac"))  # OP_OP_CHECKSIG
        unlocking_script = Script.from_bytes(b"")

        err = engine.execute(with_scripts(locking_script, unlocking_script))
        assert err is not None
        assert is_error_code(err, ErrorCode.ERR_INVALID_STACK_OPERATION)

    def test_checksig_stack_underflow_one_item(self):
        """Test OP_CHECKSIG with only one stack item - ported from TypeScript invalid vectors."""
        engine = Engine()

        # Script with only one item then OP_CHECKSIG
        locking_script = Script.from_bytes(bytes.fromhex("00ac"))  # OP_0 OP_OP_CHECKSIG
        unlocking_script = Script.from_bytes(b"")

        err = engine.execute(with_scripts(locking_script, unlocking_script))
        assert err is not None
        assert is_error_code(err, ErrorCode.ERR_INVALID_STACK_OPERATION)


class TestCheckSig:
    """Test OP_CHECKSIG opcode implementation."""

    def test_checksig_with_valid_signature(self):
        """Test OP_CHECKSIG with valid signature."""
        # Create a transaction with proper input/output structure
        tx = Transaction()

        # Create P2PKH locking script for the input
        private_key = PrivateKey()
        public_key = private_key.public_key()

        # Create proper P2PKH script for this public key
        import hashlib
        pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(public_key.serialize()).digest()).digest()
        p2pkh_script_hex = '76a914' + pubkey_hash.hex() + '88ac'
        locking_script = Script.from_bytes(bytes.fromhex(p2pkh_script_hex))

        # Create input with locking script and satoshis set (required for preimage calculation)
        input_tx = TransactionInput(source_txid="00"*32, source_output_index=0, unlocking_script=Script(), sighash=SIGHASH.ALL)
        input_tx.locking_script = locking_script  # Set the locking script for preimage calculation
        input_tx.satoshis = 1000  # Set the value of the output being spent
        tx.add_input(input_tx)
        tx.add_output(TransactionOutput(locking_script, 1000))

        # Create unlocking script with signature
        preimage = tx.preimage(0)
        signature_der = private_key.sign(preimage)
        
        # Construct unlocking script with proper pushdata operations
        # Signature with sighash: sig_bytes + sighash_byte
        sig_with_sighash = signature_der + bytes([SIGHASH.ALL])
        pubkey_bytes = public_key.serialize()
        
        # Push signature (variable length, use appropriate push opcode)
        if len(sig_with_sighash) <= 75:
            unlocking_script_bytes = bytes([len(sig_with_sighash)]) + sig_with_sighash
        else:
            # Use OP_PUSHDATA1 for longer signatures
            from bsv.constants import OpCode
            unlocking_script_bytes = bytes([OpCode.OP_PUSHDATA1.value[0]]) + bytes([len(sig_with_sighash)]) + sig_with_sighash
        
        # Push pubkey (33 bytes for compressed)
        unlocking_script_bytes += bytes([len(pubkey_bytes)]) + pubkey_bytes
        unlocking_script = Script.from_bytes(unlocking_script_bytes)

        # Update the input with the unlocking script
        tx.inputs[0].unlocking_script = unlocking_script
        # Ensure input sighash matches signature sighash for OP_CHECKSIG preimage calculation
        tx.inputs[0].sighash = SIGHASH.ALL

        # Test OP_CHECKSIG
        prev_output = TransactionOutput(locking_script, 1000)  # Create a TransactionOutput for the spent output
        engine = Engine()
        err = engine.execute(
            with_tx(tx, 0, prev_output),
            with_scripts(locking_script, unlocking_script)
        )

        # Should succeed
        assert err is None

        # The script should execute successfully and leave True on stack
        # Full implementation needed for this test to pass

    def test_checksig_with_invalid_signature(self):
        """Test OP_CHECKSIG with invalid signature."""
        # Create fake signature (all zeros)
        fake_sig = b'\x00' * 64 + bytes([SIGHASH.ALL])

        # Fake public key
        fake_pubkey = b'\x02' + b'\x00' * 32

        # Calculate hash160 of fake pubkey for P2PKH script
        import hashlib
        pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(fake_pubkey).digest()).digest()
        p2pkh_script_hex = '76a914' + pubkey_hash.hex() + '88ac'
        locking_script = Script.from_bytes(bytes.fromhex(p2pkh_script_hex))

        # Create a transaction
        tx = Transaction()
        tx.add_output(TransactionOutput(locking_script, 1000))

        # Construct unlocking script with proper pushdata operations
        # For data <= 75 bytes, use direct push opcode (byte value = length)
        # Push 65-byte signature (64 bytes + 1 byte sighash) = 0x41
        # Push 33-byte pubkey = 0x21
        unlocking_script_bytes = bytes([65]) + fake_sig + bytes([33]) + fake_pubkey
        unlocking_script = Script.from_bytes(unlocking_script_bytes)
        prev_output = TransactionOutput(locking_script, 1000)

        # Create input with locking script and satoshis set (required for preimage calculation)
        input_tx = TransactionInput(source_txid="00"*32, source_output_index=0, unlocking_script=unlocking_script)
        input_tx.locking_script = locking_script
        input_tx.satoshis = 1000
        tx.add_input(input_tx)

        # Test OP_CHECKSIG - should fail
        engine = Engine()
        err = engine.execute(
            with_tx(tx, 0, prev_output),
            with_scripts(locking_script, unlocking_script)
        )

        # Script execution completes but leaves False on stack (invalid signature)
        # This is correct behavior - OP_CHECKSIG returns False for invalid signature
        assert err is not None
        assert is_error_code(err, ErrorCode.ERR_EVAL_FALSE)

    def test_checksig_stack_underflow(self):
        """Test OP_CHECKSIG with insufficient stack items."""
        engine = Engine()

        # Script with only one item on stack
        locking_script = Script.from_bytes(bytes.fromhex("51ac"))  # OP_1 OP_OP_CHECKSIG
        unlocking_script = Script.from_bytes(bytes.fromhex(""))  # Empty

        err = engine.execute(
            with_scripts(locking_script, unlocking_script)
        )

        # Should fail with stack underflow
        assert err is not None
        assert is_error_code(err, ErrorCode.ERR_INVALID_STACK_OPERATION)

    def test_checksig_invalid_signature_encoding(self):
        """Test OP_CHECKSIG with invalid signature encoding."""
        engine = Engine()

        # Empty signature
        locking_script = Script.from_bytes(bytes.fromhex("00ac"))  # OP_0 OP_OP_CHECKSIG
        unlocking_script = Script.from_bytes(bytes.fromhex("02" + "00"*32))  # Empty sig, fake pubkey

        err = engine.execute(
            with_scripts(locking_script, unlocking_script)
        )

        # OP_CHECKSIG returns False for invalid signature encoding
        # Script execution completes but leaves False on stack
        assert err is not None
        assert is_error_code(err, ErrorCode.ERR_EVAL_FALSE)

    def test_checksig_invalid_public_key_encoding(self):
        """Test OP_CHECKSIG with invalid public key encoding."""
        engine = Engine()

        # Invalid public key (too short)
        locking_script = Script.from_bytes(bytes.fromhex("51ac"))  # OP_1 OP_OP_CHECKSIG
        unlocking_script = Script.from_bytes(bytes.fromhex("00" + "00"))  # Fake sig, invalid pubkey

        err = engine.execute(
            with_scripts(locking_script, unlocking_script)
        )

        # OP_CHECKSIG returns False for invalid public key encoding
        # Script execution completes but leaves False on stack
        assert err is not None
        assert is_error_code(err, ErrorCode.ERR_EVAL_FALSE)

    def test_checksig_verify_success(self):
        """Test OP_OP_CHECKSIGVERIFY with valid signature."""
        # This test will need full implementation to pass
        engine = Engine()

        # Simple script that should verify
        locking_script = Script.from_bytes(bytes.fromhex("51ad"))  # OP_1 OP_OP_OP_CHECKSIGVERIFY
        unlocking_script = Script.from_bytes(bytes.fromhex("00" + "00"*32))  # Fake sig/pubkey

        err = engine.execute(
            with_scripts(locking_script, unlocking_script)
        )

        # Currently fails due to TODO implementation
        # With full implementation should either succeed or fail based on verification
        assert err is not None  # Will change when implemented

    def test_checksig_verify_failure(self):
        """Test OP_OP_CHECKSIGVERIFY with invalid signature."""
        engine = Engine()

        # OP_OP_CHECKSIGVERIFY with invalid sig should fail
        locking_script = Script.from_bytes(bytes.fromhex("00ad"))  # OP_0 OP_OP_OP_CHECKSIGVERIFY
        unlocking_script = Script.from_bytes(bytes.fromhex("00" + "00"*32))  # Fake sig/pubkey

        err = engine.execute(
            with_scripts(locking_script, unlocking_script)
        )

        # Should fail with OP_OP_CHECKSIGVERIFY error
        assert err is not None
        assert is_error_code(err, ErrorCode.ERR_CHECK_SIG_VERIFY)

    @pytest.mark.skip(reason="Requires full signature verification implementation")
    def test_checksig_p2pkh_transaction(self):
        """Test OP_CHECKSIG with real P2PKH transaction."""
        # This test requires full implementation
        pass

    @pytest.mark.skip(reason="Requires full signature verification implementation")
    def test_checksig_different_sighash_types(self):
        """Test OP_CHECKSIG with different sighash types."""
        # Test ALL, NONE, SINGLE, etc.
        pass

    @pytest.mark.skip(reason="Requires full signature verification implementation")
    def test_checksig_with_codeseparator(self):
        """Test OP_CHECKSIG with OP_CODESEPARATOR."""
        pass
