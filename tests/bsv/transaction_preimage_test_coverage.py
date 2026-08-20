"""
Coverage tests for transaction_preimage.py - untested branches.
"""

import subprocess
import sys
import textwrap

import pytest

from bsv.script.script import Script
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput

# ========================================================================
# Transaction preimage branches
# ========================================================================


def test_transaction_preimage_basic():
    """Test generating transaction preimage."""
    tx = Transaction(
        version=1,
        tx_inputs=[
            TransactionInput(
                source_txid="0" * 64, source_output_index=0, unlocking_script=Script(b""), sequence=0xFFFFFFFF
            )
        ],
        tx_outputs=[TransactionOutput(satoshis=1000, locking_script=Script(b""))],
        locktime=0,
    )
    # Set the locking script and satoshis for the input (from the output being spent)
    tx.inputs[0].locking_script = Script(b"")
    tx.inputs[0].satoshis = 1000  # Same as the output satoshis

    if hasattr(tx, "preimage"):
        preimage = tx.preimage(0)
        assert isinstance(preimage, bytes)
        assert len(preimage) > 0


def test_transaction_preimage_multiple_inputs():
    """Test preimage with multiple inputs."""
    tx = Transaction(
        version=1,
        tx_inputs=[
            TransactionInput(
                source_txid="0" * 64, source_output_index=0, unlocking_script=Script(b""), sequence=0xFFFFFFFF
            ),
            TransactionInput(
                source_txid="1" * 64, source_output_index=1, unlocking_script=Script(b""), sequence=0xFFFFFFFF
            ),
        ],
        tx_outputs=[TransactionOutput(satoshis=1000, locking_script=Script(b""))],
        locktime=0,
    )
    # Set the locking script and satoshis for the inputs (from the outputs being spent)
    tx.inputs[0].locking_script = Script(b"")
    tx.inputs[0].satoshis = 500
    tx.inputs[1].locking_script = Script(b"")
    tx.inputs[1].satoshis = 600

    if hasattr(tx, "preimage"):
        preimage0 = tx.preimage(0)
        preimage1 = tx.preimage(1)
        assert preimage0 != preimage1


def test_transaction_preimage_with_sighash():
    """Test preimage with specific sighash type."""
    try:
        from bsv.constants import SIGHASH

        tx = Transaction(
            version=1,
            tx_inputs=[
                TransactionInput(
                    source_txid="0" * 64, source_output_index=0, unlocking_script=Script(b""), sequence=0xFFFFFFFF
                )
            ],
            tx_outputs=[TransactionOutput(satoshis=1000, locking_script=Script(b""))],
            locktime=0,
        )
        # Set the locking script and satoshis for the input (from the output being spent)
        tx.inputs[0].locking_script = Script(b"")
        tx.inputs[0].satoshis = 1000

        if hasattr(tx, "preimage"):
            try:
                preimage = tx.preimage(0, sighash_type=SIGHASH.ALL)
                assert isinstance(preimage, bytes)
            except TypeError:
                # preimage may not accept sighash_type parameter
                pytest.skip("preimage doesn't support sighash_type parameter")
    except ImportError:
        pytest.skip("SIGHASH not available")


# ========================================================================
# Edge cases
# ========================================================================


def test_transaction_preimage_index_bounds():
    """Test preimage with input index at bounds."""
    tx = Transaction(
        version=1,
        tx_inputs=[
            TransactionInput(
                source_txid="0" * 64, source_output_index=0, unlocking_script=Script(b""), sequence=0xFFFFFFFF
            )
        ],
        tx_outputs=[TransactionOutput(satoshis=1000, locking_script=Script(b""))],
        locktime=0,
    )
    # Set the locking script and satoshis for the input (from the output being spent)
    tx.inputs[0].locking_script = Script(b"")
    tx.inputs[0].satoshis = 1000

    if hasattr(tx, "preimage"):
        for index in (-1, 1, 99):
            with pytest.raises(ValueError, match=r"index out of range"):
                _ = tx.preimage(index)


def test_transaction_preimage_index_validation_is_preserved_under_python_optimization():
    code = textwrap.dedent("""\
        from bsv.script.script import Script
        from bsv.transaction import Transaction
        from bsv.transaction_input import TransactionInput
        from bsv.transaction_output import TransactionOutput

        if __debug__:
            raise RuntimeError("subprocess is not running with optimization enabled")

        tx_input = TransactionInput(source_txid="0" * 64)
        tx_input.locking_script = Script()
        tx_input.satoshis = 1000
        tx = Transaction(
            tx_inputs=[tx_input],
            tx_outputs=[TransactionOutput(satoshis=1000, locking_script=Script())],
        )

        for index in (-1, 1, 99):
            try:
                tx.preimage(index)
            except ValueError:
                pass
            else:
                raise AssertionError(f"accepted invalid preimage index: {index}")

        if not tx.preimage(0):
            raise AssertionError("valid preimage index changed under optimization")
        """)

    result = subprocess.run(
        [sys.executable, "-O", "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr


def test_transaction_preimage_deterministic():
    """Test preimage is deterministic."""
    tx = Transaction(
        version=1,
        tx_inputs=[
            TransactionInput(
                source_txid="0" * 64, source_output_index=0, unlocking_script=Script(b""), sequence=0xFFFFFFFF
            )
        ],
        tx_outputs=[TransactionOutput(satoshis=1000, locking_script=Script(b""))],
        locktime=0,
    )
    # Set the locking script and satoshis for the input (from the output being spent)
    tx.inputs[0].locking_script = Script(b"")
    tx.inputs[0].satoshis = 1000

    if hasattr(tx, "preimage"):
        preimage1 = tx.preimage(0)
        preimage2 = tx.preimage(0)
        assert preimage1 == preimage2
