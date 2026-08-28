"""Test that Transaction.sign() uses batch preimage computation (O(N) not O(N²))."""

from unittest.mock import patch

import pytest

from bsv.constants import SIGHASH
from bsv.hash import hash256
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.type import P2PKH
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput


def _fund(priv_key: PrivateKey, num_outputs: int = 1) -> Transaction:
    """Create a source transaction with `num_outputs` P2PKH outputs."""
    addr = priv_key.address()
    source_tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_txid="ab" * 32,
                source_output_index=0,
                unlocking_script=Script(b"\x00"),
                sequence=0xFFFFFFFF,
            )
        ],
        tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=100_000) for _ in range(num_outputs)],
    )
    return source_tx


def _build_tx(priv_key: PrivateKey, num_inputs: int) -> Transaction:
    """Build a transaction spending `num_inputs` UTXOs."""
    source_tx = _fund(priv_key, num_inputs)
    addr = priv_key.address()
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=source_tx,
                source_output_index=i,
                unlocking_script_template=P2PKH().unlock(priv_key),
            )
            for i in range(num_inputs)
        ],
        tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=num_inputs * 100_000 - 1000)],
    )
    return tx


class TestBatchPreimage:
    def test_sign_produces_valid_signatures(self):
        """Batch-signed transaction must produce the same signatures as per-input signing."""
        priv_key = PrivateKey()
        num_inputs = 5
        source_tx = _fund(priv_key, num_inputs)
        addr = priv_key.address()

        expected_preimages = []
        for i in range(num_inputs):
            tx = Transaction(
                tx_inputs=[
                    TransactionInput(
                        source_transaction=source_tx,
                        source_output_index=j,
                        unlocking_script_template=P2PKH().unlock(priv_key),
                    )
                    for j in range(num_inputs)
                ],
                tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=num_inputs * 100_000 - 1000)],
            )
            expected_preimages.append(tx.preimage(i))

        tx_batch = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=source_tx,
                    source_output_index=j,
                    unlocking_script_template=P2PKH().unlock(priv_key),
                )
                for j in range(num_inputs)
            ],
            tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=num_inputs * 100_000 - 1000)],
        )
        tx_batch.sign()

        for i in range(num_inputs):
            assert tx_batch._preimage_cache is None
            actual = tx_batch.preimage(i)
            assert actual == expected_preimages[i], f"preimage mismatch at input {i}"

    def test_cache_cleared_after_sign(self):
        priv_key = PrivateKey()
        tx = _build_tx(priv_key, 3)
        tx.sign()
        assert tx._preimage_cache is None

    def test_cache_cleared_on_exception(self):
        priv_key = PrivateKey()
        tx = _build_tx(priv_key, 2)
        tx.inputs[1].unlocking_script_template = None

        with pytest.raises(Exception):
            tx.sign()
        assert tx._preimage_cache is None

    def test_single_input_works(self):
        priv_key = PrivateKey()
        tx = _build_tx(priv_key, 1)
        tx.sign()
        assert tx.inputs[0].unlocking_script is not None
        assert tx._preimage_cache is None

    def test_preimage_cache_used_during_sign(self):
        """Verify that sign() sets up the cache before calling template.sign()."""
        priv_key = PrivateKey()
        tx = _build_tx(priv_key, 3)

        observed_caches = []
        original_sign = tx.inputs[0].unlocking_script_template.sign

        def spy_sign(tx_arg, idx):
            observed_caches.append(tx_arg._preimage_cache is not None)
            return original_sign(tx_arg, idx)

        for inp in tx.inputs:
            inp.unlocking_script_template.sign = spy_sign

        tx.sign()
        assert all(observed_caches), "preimage cache should be set during template.sign() calls"
        assert tx._preimage_cache is None

    def test_tx_preimage_not_called_per_input(self):
        """tx_preimage (singular) should NOT be called when all inputs are BIP143."""
        import sys

        priv_key = PrivateKey()
        tx = _build_tx(priv_key, 4)

        tx_mod = sys.modules["bsv._legacy_transaction"]
        with patch.object(tx_mod, "tx_preimage", wraps=tx_preimage_original) as mock_single:
            tx.sign()
            assert mock_single.call_count == 0, (
                f"tx_preimage was called {mock_single.call_count} times; " "batch path should use tx_preimages instead"
            )


from bsv.transaction_preimage import tx_preimage as tx_preimage_original
