"""
Go SDK sighash hardcoded test vectors.

This file replicates the hardcoded test vectors from go-sdk/transaction/signaturehash_test.go
to ensure Python implementation matches Go exactly.

Tests signature hash calculation and preimage generation against the official go-sdk test vectors.
"""

import pytest

from bsv.transaction import Transaction
from bsv.script.script import Script
from bsv.constants import SIGHASH


@pytest.mark.parametrize("test_name,unsigned_tx,index,previous_tx_satoshis,source_tx_script,sig_hash_type,expected_preimage", [
    (
        "1 Input 2 Outputs - SIGHASH_ALL (FORKID)",
        "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000",
        0,
        100000000,
        "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac",
        SIGHASH.ALL_FORKID,
        "010000007ced5b2e5cf3ea407b005d8b18c393b6256ea2429b6ff409983e10adc61d0ae83bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e7066504493a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000001976a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac00e1f50500000000ffffffff87841ab2b7a4133af2c58256edb7c3c9edca765a852ebe2d0dc962604a30f1030000000041000000",
    ),
    (
        "2 Inputs 3 Outputs - SIGHASH_ALL (FORKID) - Index 0",
        "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000",
        0,
        2000000000,
        "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac",
        SIGHASH.ALL_FORKID,
        "01000000eaef7a1b82f72f4097e63b0173906d690cc137221d221fc4150bae88570fa356752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc010000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac0094357700000000ffffffff0cf3246582f4b1b5fd150b942916c7d5c78e80259cbab1a761a9e4ac3a66e0a70000000041000000",
    ),
    (
        "2 Inputs 3 Outputs - SIGHASH_ALL (FORKID) - Index 1",
        "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000",
        1,
        2000000000,
        "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac",
        SIGHASH.ALL_FORKID,
        "01000000eaef7a1b82f72f4097e63b0173906d690cc137221d221fc4150bae88570fa356752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632addebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d849000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac0094357700000000ffffffff0cf3246582f4b1b5fd150b942916c7d5c78e80259cbab1a761a9e4ac3a66e0a70000000041000000",
    ),
])
def test_calc_input_preimage_bip143(test_name: str, unsigned_tx: str, index: int, previous_tx_satoshis: int, source_tx_script: str, sig_hash_type: SIGHASH, expected_preimage: str) -> None:
    """
    Test BIP143/ForkID preimage calculation against go-sdk hardcoded vectors.
    Mirrors TestTx_CalcInputPreimage from go-sdk.
    """
    # Parse transaction
    tx = Transaction.from_hex(unsigned_tx)
    assert tx is not None, f"Failed to parse transaction for test: {test_name}"

    # Set up the input with locking script and satoshis
    prev_script = Script.from_bytes(bytes.fromhex(source_tx_script))
    tx.inputs[index].locking_script = prev_script
    tx.inputs[index].satoshis = previous_tx_satoshis

    # Calculate preimage using BIP143 algorithm
    actual_preimage = tx._calc_input_preimage_bip143(index, int(sig_hash_type), prev_script, previous_tx_satoshis)

    # Compare with expected
    expected_bytes = bytes.fromhex(expected_preimage)
    assert actual_preimage == expected_bytes, (
        f"BIP143 preimage test failed: {test_name}\n"
        f"Expected: {expected_preimage}\n"
        f"Actual:   {actual_preimage.hex()}"
    )


@pytest.mark.parametrize("test_name,unsigned_tx,index,previous_tx_satoshis,source_tx_script,sig_hash_type,expected_sig_hash", [
    (
        "1 Input 2 Outputs - SIGHASH_ALL (FORKID)",
        "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000",
        0,
        100000000,
        "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac",
        SIGHASH.ALL_FORKID,
        "be9a42ef2e2dd7ef02cd631290667292cbbc5018f4e3f6843a8f4c302a2111b1",
    ),
    (
        "2 Inputs 3 Outputs - SIGHASH_ALL (FORKID) - Index 0",
        "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000",
        0,
        2000000000,
        "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac",
        SIGHASH.ALL_FORKID,
        "8b15eecfb6d5e727485e19797b5d1829e0630e8b43c806707685238e28a3194c",
    ),
    (
        "2 Inputs 3 Outputs - SIGHASH_ALL (FORKID) - Index 1",
        "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffffdebe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000",
        1,
        2000000000,
        "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac",
        SIGHASH.ALL_FORKID,
        "7b72c355a2714a5039d97fbd5eee792099b0eab4bf07d2e5bfcfc3309f81badb",
    ),
])
def test_calc_input_signature_hash(test_name: str, unsigned_tx: str, index: int, previous_tx_satoshis: int, source_tx_script: str, sig_hash_type: SIGHASH, expected_sig_hash: str) -> None:
    """
    Test signature hash calculation against go-sdk hardcoded vectors.
    Mirrors TestTx_CalcInputSignatureHash from go-sdk.
    """
    # Parse transaction
    tx = Transaction.from_hex(unsigned_tx)
    assert tx is not None, f"Failed to parse transaction for test: {test_name}"

    # Set up the input with locking script and satoshis
    prev_script = Script.from_bytes(bytes.fromhex(source_tx_script))
    tx.inputs[index].locking_script = prev_script
    tx.inputs[index].satoshis = previous_tx_satoshis

    # Calculate signature hash
    actual_sig_hash = tx.calc_input_signature_hash(index, int(sig_hash_type), prev_script, previous_tx_satoshis)

    # Compare with expected
    expected_bytes = bytes.fromhex(expected_sig_hash)
    assert actual_sig_hash == expected_bytes, (
        f"Signature hash test failed: {test_name}\n"
        f"Expected: {expected_sig_hash}\n"
        f"Actual:   {actual_sig_hash.hex()}"
    )


