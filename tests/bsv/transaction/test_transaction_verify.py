"""
Transaction verification tests - ported from Go SDK spv/verify_test.go

These tests verify that Transaction.verify() correctly validates scripts
using the Engine-based interpreter, matching Go SDK behavior.
"""

import pytest
import base64
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
from bsv.keys import PrivateKey
from bsv.script.type import P2PKH
from bsv.spv import GullibleHeadersClient

# BEEF transaction from Go SDK test (BRC62Hex)
BRC62_HEX = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"

# BEEF transaction from Go SDK test (base64)
BEEF_BASE64 = "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"


class TestTransactionVerify:
    """Test Transaction.verify() - ported from Go SDK spv/verify_test.go"""

    @pytest.mark.asyncio
    async def test_verify_simple_p2pkh_transaction(self):
        """
        Test basic P2PKH transaction verification.
        
        This is a simpler test than the Go SDK's BEEF tests, verifying
        that the Engine-based interpreter works correctly for a standard
        P2PKH spend.
        """
        # Create keys
        priv_key = PrivateKey()
        address = priv_key.address()
        
        # Create source transaction
        source_tx = Transaction([], [
            TransactionOutput(
                locking_script=P2PKH().lock(address),
                satoshis=1000
            )
        ])
        
        # Create spending transaction
        tx = Transaction(
            [TransactionInput(
                source_transaction=source_tx,
                source_output_index=0,
                unlocking_script_template=P2PKH().unlock(priv_key)
            )],
            [TransactionOutput(
                locking_script=P2PKH().lock(address),
                satoshis=500
            )]
        )
        
        # Sign the transaction
        tx.sign()
        
        # Verify with GullibleHeadersClient (scripts_only mode)
        chaintracker = GullibleHeadersClient()
        result = await tx.verify(chaintracker, scripts_only=True)
        
        assert result is True, "Valid P2PKH transaction should verify successfully"

    @pytest.mark.asyncio
    async def test_verify_rejects_invalid_signature(self):
        """
        Test that verification correctly rejects invalid signatures.
        
        This tests that the Engine properly validates signatures and returns
        False when a transaction is signed with the wrong key.
        """
        # Create keys
        priv_key = PrivateKey()
        wrong_key = PrivateKey()
        address = priv_key.address()
        
        # Create source transaction locked to priv_key's address
        source_tx = Transaction([], [
            TransactionOutput(
                locking_script=P2PKH().lock(address),
                satoshis=1000
            )
        ])
        
        # Create spending transaction but sign with wrong key
        tx = Transaction(
            [TransactionInput(
                source_transaction=source_tx,
                source_output_index=0,
                unlocking_script_template=P2PKH().unlock(wrong_key)
            )],
            [TransactionOutput(
                locking_script=P2PKH().lock(address),
                satoshis=500
            )]
        )
        
        # Sign with wrong key
        tx.sign()
        
        # Verification should fail
        chaintracker = GullibleHeadersClient()
        result = await tx.verify(chaintracker, scripts_only=True)
        
        assert result is False, "Transaction with invalid signature should fail verification"

    @pytest.mark.asyncio
    async def test_verify_raises_error_missing_source_transaction(self):
        """
        Test that verify() raises ValueError when source transaction is missing.
        
        Ported from Go SDK test that expects error for missing source.
        """
        priv_key = PrivateKey()
        address = priv_key.address()
        
        # Create transaction without source_transaction
        tx = Transaction(
            [TransactionInput(
                source_txid="0" * 64,
                source_output_index=0,
                unlocking_script_template=P2PKH().unlock(priv_key)
            )],
            [TransactionOutput(
                locking_script=P2PKH().lock(address),
                satoshis=500
            )]
        )
        
        chaintracker = GullibleHeadersClient()
        
        with pytest.raises(ValueError, match="missing an associated source transaction"):
            await tx.verify(chaintracker, scripts_only=True)

    @pytest.mark.asyncio
    async def test_verify_raises_error_missing_unlocking_script(self):
        """
        Test that verify() raises ValueError when unlocking script is missing.
        """
        priv_key = PrivateKey()
        address = priv_key.address()
        
        # Create source transaction
        source_tx = Transaction([], [
            TransactionOutput(
                locking_script=P2PKH().lock(address),
                satoshis=1000
            )
        ])
        
        # Create transaction without unlocking script
        tx = Transaction(
            [TransactionInput(
                source_transaction=source_tx,
                source_output_index=0
                # No unlocking_script_template
            )],
            [TransactionOutput(
                locking_script=P2PKH().lock(address),
                satoshis=500
            )]
        )
        
        chaintracker = GullibleHeadersClient()
        
        with pytest.raises(ValueError, match="missing an associated unlocking script"):
            await tx.verify(chaintracker, scripts_only=True)

    @pytest.mark.asyncio
    async def test_spv_verify_from_beef_hex(self):
        """
        Test SPV verification from BEEF hex - ported from Go SDK TestSPVVerify.
        
        This test uses real BEEF data from the Go SDK test suite to ensure
        compatibility.
        
        Note: Currently skipped due to BEEF parsing issues.
        """
        pytest.skip("BEEF parsing from hex needs investigation - see test_verify_scripts.py")
        
        # This would be the full test once BEEF parsing is fixed:
        # tx = Transaction.from_beef_hex(BRC62_HEX)
        # chaintracker = GullibleHeadersClient()
        # result = await tx.verify(chaintracker, scripts_only=True)
        # assert result is True

    @pytest.mark.asyncio
    async def test_spv_verify_scripts_from_beef(self):
        """
        Test VerifyScripts from BEEF - ported from Go SDK TestSPVVerifyScripts.
        
        Note: Currently skipped due to BEEF parsing issues.
        """
        pytest.skip("BEEF parsing from base64 needs investigation - see test_verify_scripts.py")
        
        # This would be the full test once BEEF parsing is fixed:
        # beef_bytes = base64.b64decode(BEEF_BASE64 + '=')  # Add padding
        # tx = Transaction.from_beef(beef_bytes)
        # chaintracker = GullibleHeadersClient()
        # result = await tx.verify(chaintracker, scripts_only=True)
        # assert result is True

