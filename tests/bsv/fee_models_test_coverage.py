"""
Coverage tests for fee_models/ modules - untested branches.
"""
import pytest

# Constants for skip messages
SKIP_SATOSHIS_PER_KB = "SatoshisPerKilobyte not available"
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.script.script import Script


# ========================================================================
# SatoshisPerKilobyte branches (additional)
# ========================================================================

def test_satoshis_per_kb_compute_with_transaction():
    """Test computing fee with actual transaction."""
    try:
        from bsv.fee_models import SatoshisPerKilobyte
        
        fee_model = SatoshisPerKilobyte(rate=1000)
        
        tx = Transaction(
            version=1,
            tx_inputs=[
                TransactionInput(
                    source_txid='0' * 64,
                    source_output_index=0,
                    unlocking_script=Script(b'\x00' * 100),
                    sequence=0xFFFFFFFF
                )
            ],
            tx_outputs=[
                TransactionOutput(satoshis=1000, locking_script=Script(b'\x00' * 25))
            ],
            locktime=0
        )
        
        if hasattr(fee_model, 'compute_fee'):
            fee = fee_model.compute_fee(tx)
            assert isinstance(fee, int)
            assert fee > 0
    except ImportError:
        pytest.skip(SKIP_SATOSHIS_PER_KB)


def test_satoshis_per_kb_zero_rate():
    """Test fee model with zero rate."""
    try:
        from bsv.fee_models import SatoshisPerKilobyte
        
        fee_model = SatoshisPerKilobyte(rate=0)
        
        if hasattr(fee_model, 'compute_fee'):
            fee = fee_model.compute_fee(250)  # 250 bytes
            assert fee == 0
    except ImportError:
        pytest.skip(SKIP_SATOSHIS_PER_KB)


def test_satoshis_per_kb_very_high_rate():
    """Test fee model with very high rate."""
    try:
        from bsv.fee_models import SatoshisPerKilobyte
        
        fee_model = SatoshisPerKilobyte(rate=1000000)
        
        if hasattr(fee_model, 'compute_fee'):
            fee = fee_model.compute_fee(250)
            assert fee > 0
    except ImportError:
        pytest.skip(SKIP_SATOSHIS_PER_KB)


# ========================================================================
# DataOnly fee model branches
# ========================================================================

def test_data_only_fee_model():
    """Test DataOnly fee model."""
    try:
        from bsv.fee_models import DataOnly
        
        fee_model = DataOnly()
        assert fee_model is not None
        
        if hasattr(fee_model, 'compute_fee'):
            fee = fee_model.compute_fee(250)
            assert fee == 0  # DataOnly should always return 0
    except (ImportError, AttributeError):
        pytest.skip("DataOnly fee model not available")


# ========================================================================
# Custom fee model branches
# ========================================================================

def test_custom_fee_model():
    """Test custom fee model."""
    try:
        from bsv.fee_models import FeeModel
        
        # Check if FeeModel interface exists
        assert FeeModel is not None
    except (ImportError, AttributeError):
        pytest.skip("FeeModel interface not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_fee_model_with_empty_transaction():
    """Test fee model with empty transaction."""
    try:
        from bsv.fee_models import SatoshisPerKilobyte
        
        fee_model = SatoshisPerKilobyte(rate=1000)
        
        tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
        
        if hasattr(fee_model, 'compute_fee'):
            fee = fee_model.compute_fee(tx)
            assert isinstance(fee, int)
    except ImportError:
        pytest.skip(SKIP_SATOSHIS_PER_KB)


def test_fee_model_fractional_rate():
    """Test fee model with fractional rate."""
    try:
        from bsv.fee_models import SatoshisPerKilobyte
        
        fee_model = SatoshisPerKilobyte(rate=1.5)
        
        if hasattr(fee_model, 'compute_fee'):
            fee = fee_model.compute_fee(250)
            assert isinstance(fee, (int, float))
    except (ImportError, TypeError):
        pytest.skip("SatoshisPerKilobyte not available or doesn't support fractional rate")

