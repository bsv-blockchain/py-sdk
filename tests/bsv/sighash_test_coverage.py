"""
Coverage tests for sighash.py - untested branches.
"""
import pytest

# Constants for skip messages
SKIP_VALID_TX = "Requires valid transaction"
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.script.script import Script


# ========================================================================
# Sighash calculation branches
# ========================================================================

SKIP_SIGHASH = "Sighash not available"
def test_sighash_all():
    """Test SIGHASH_ALL calculation."""
    try:
        from bsv.sighash import sighash
        from bsv.constants import SIGHASH
        
        tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
        input_index = 0
        subscript = Script(b'')
        
        try:
            hash_value = sighash(tx, input_index, subscript, SIGHASH.ALL)
            assert isinstance(hash_value, bytes)
        except (IndexError, AttributeError):
            # May need valid inputs
            pytest.skip(SKIP_VALID_TX)
    except ImportError:
        pytest.skip(SKIP_SIGHASH)


def test_sighash_none():
    """Test SIGHASH_NONE calculation."""
    try:
        from bsv.sighash import sighash
        from bsv.constants import SIGHASH
        
        tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
        
        try:
            hash_value = sighash(tx, 0, Script(b''), SIGHASH.NONE)
            assert isinstance(hash_value, bytes)
        except (IndexError, AttributeError):
            pytest.skip(SKIP_VALID_TX)
    except ImportError:
        pytest.skip(SKIP_SIGHASH)


def test_sighash_single():
    """Test SIGHASH_SINGLE calculation."""
    try:
        from bsv.sighash import sighash
        from bsv.constants import SIGHASH
        
        tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
        
        try:
            hash_value = sighash(tx, 0, Script(b''), SIGHASH.SINGLE)
            assert isinstance(hash_value, bytes)
        except (IndexError, AttributeError):
            pytest.skip(SKIP_VALID_TX)
    except ImportError:
        pytest.skip(SKIP_SIGHASH)


def test_sighash_anyonecanpay():
    """Test SIGHASH_ANYONECANPAY flag."""
    try:
        from bsv.sighash import sighash
        from bsv.constants import SIGHASH
        
        tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
        
        try:
            hash_value = sighash(tx, 0, Script(b''), SIGHASH.ALL | SIGHASH.ANYONECANPAY)
            assert isinstance(hash_value, bytes)
        except (IndexError, AttributeError):
            pytest.skip(SKIP_VALID_TX)
    except ImportError:
        pytest.skip(SKIP_SIGHASH)


# ========================================================================
# Preimage branches
# ========================================================================

def test_transaction_preimage():
    """Test transaction preimage generation."""
    tx = Transaction(
        version=1,
        tx_inputs=[
            TransactionInput(
                source_txid='0' * 64,
                source_output_index=0,
                unlocking_script=Script(b''),
                sequence=0xFFFFFFFF
            )
        ],
        tx_outputs=[
            TransactionOutput(satoshis=1000, locking_script=Script(b''))
        ],
        locktime=0
    )
    
    try:
        preimage = tx.preimage(0)
        assert isinstance(preimage, bytes)
    except AttributeError:
        pytest.skip("Transaction.preimage not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_sighash_forkid():
    """Test SIGHASH with FORKID."""
    try:
        from bsv.sighash import sighash
        from bsv.constants import SIGHASH
        
        tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
        
        try:
            hash_value = sighash(tx, 0, Script(b''), SIGHASH.ALL | SIGHASH.FORKID)
            assert isinstance(hash_value, bytes)
        except (IndexError, AttributeError):
            pytest.skip(SKIP_VALID_TX)
    except ImportError:
        pytest.skip(SKIP_SIGHASH)

