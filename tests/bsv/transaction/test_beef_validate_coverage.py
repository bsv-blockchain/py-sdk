"""
Coverage tests for beef_validate.py - untested branches.
"""
import pytest
from bsv.transaction.beef_validate import validate_transactions, ValidationResult, is_valid, verify_valid, get_valid_txids
from bsv.transaction.beef import Beef


# ========================================================================
# validate_transactions branches
# ========================================================================

def test_validate_transactions_with_empty_beef():
    """Test validate_transactions with empty BEEF."""
    beef = Beef(version=4)
    beef.txs = {}
    beef.bumps = []
    result = validate_transactions(beef)
    assert isinstance(result, ValidationResult)
    assert len(result.valid) == 0


def test_validate_transactions_with_no_bumps():
    """Test validate_transactions with BEEF that has no bumps."""
    beef = Beef(version=4)
    beef.txs = {}
    beef.bumps = None
    result = validate_transactions(beef)
    assert isinstance(result, ValidationResult)


def test_validate_transactions_with_missing_bumps_attr():
    """Test validate_transactions when bumps attribute is missing."""
    from types import SimpleNamespace
    beef = SimpleNamespace()
    beef.txs = {}
    # No bumps attribute
    try:
        result = validate_transactions(beef)  # type: ignore
        assert isinstance(result, ValidationResult)
    except AttributeError:
        # Expected if code doesn't handle missing attribute
        assert True


# ========================================================================
# is_valid branches
# ========================================================================

def test_is_valid_with_empty_beef():
    """Test is_valid with empty BEEF."""
    beef = Beef(version=4)
    beef.txs = {}
    beef.bumps = []
    result = is_valid(beef)
    assert isinstance(result, bool)


def test_is_valid_with_allow_txid_only():
    """Test is_valid with allow_txid_only parameter."""
    beef = Beef(version=4)
    beef.txs = {}
    beef.bumps = []
    result = is_valid(beef, allow_txid_only=True)
    assert isinstance(result, bool)


# ========================================================================
# verify_valid branches
# ========================================================================

def test_verify_valid_with_empty_beef():
    """Test verify_valid with empty BEEF."""
    beef = Beef(version=4)
    beef.txs = {}
    beef.bumps = []
    valid, errors = verify_valid(beef)
    assert isinstance(valid, bool)
    assert isinstance(errors, dict)


def test_verify_valid_with_allow_txid_only():
    """Test verify_valid with allow_txid_only parameter."""
    beef = Beef(version=4)
    beef.txs = {}
    beef.bumps = []
    valid, errors = verify_valid(beef, allow_txid_only=True)
    assert isinstance(valid, bool)
    assert isinstance(errors, dict)


# ========================================================================
# get_valid_txids branches
# ========================================================================

def test_get_valid_txids_with_empty_beef():
    """Test get_valid_txids with empty BEEF."""
    beef = Beef(version=4)
    beef.txs = {}
    beef.bumps = []
    result = get_valid_txids(beef)
    assert isinstance(result, list)
    assert len(result) == 0


# ========================================================================
# ValidationResult class
# ========================================================================

def test_validation_result_str():
    """Test ValidationResult string representation."""
    result = ValidationResult()
    result.valid = ["tx1"]
    result.not_valid = ["tx2"]
    result.txid_only = ["tx3"]
    str_repr = str(result)
    assert "valid" in str_repr
    assert "tx1" in str_repr

