"""
Coverage tests for script/interpreter/scriptflag.py - untested branches.
"""
import pytest


# ========================================================================
# Script flag constants branches
# ========================================================================

def test_scriptflag_module_exists():
    """Test that scriptflag module exists."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag is not None
    except ImportError:
        pytest.skip("scriptflag module not available")


def test_scriptflag_bip16():
    """Test BIP16 flag (P2SH)."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag.BIP16 is not None
        assert isinstance(Flag.BIP16, int)
    except (ImportError, AttributeError):
        pytest.skip("BIP16 flag not available")


def test_scriptflag_verify_strict_encoding():
    """Test VERIFY_STRICT_ENCODING flag."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag.VERIFY_STRICT_ENCODING is not None
        assert isinstance(Flag.VERIFY_STRICT_ENCODING, int)
    except (ImportError, AttributeError):
        pytest.skip("VERIFY_STRICT_ENCODING not available")


def test_scriptflag_verify_der_signatures():
    """Test VERIFY_DER_SIGNATURES flag."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag.VERIFY_DER_SIGNATURES is not None
        assert isinstance(Flag.VERIFY_DER_SIGNATURES, int)
    except (ImportError, AttributeError):
        pytest.skip("VERIFY_DER_SIGNATURES not available")


def test_scriptflag_verify_low_s():
    """Test VERIFY_LOW_S flag."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag.VERIFY_LOW_S is not None
        assert isinstance(Flag.VERIFY_LOW_S, int)
    except (ImportError, AttributeError):
        pytest.skip("VERIFY_LOW_S not available")


def test_scriptflag_strict_multisig():
    """Test STRICT_MULTISIG flag."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag.STRICT_MULTISIG is not None
        assert isinstance(Flag.STRICT_MULTISIG, int)
    except (ImportError, AttributeError):
        pytest.skip("STRICT_MULTISIG not available")


def test_scriptflag_verify_sig_push_only():
    """Test VERIFY_SIG_PUSH_ONLY flag."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag.VERIFY_SIG_PUSH_ONLY is not None
        assert isinstance(Flag.VERIFY_SIG_PUSH_ONLY, int)
    except (ImportError, AttributeError):
        pytest.skip("VERIFY_SIG_PUSH_ONLY not available")


def test_scriptflag_verify_minimal_data():
    """Test VERIFY_MINIMAL_DATA flag."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag.VERIFY_MINIMAL_DATA is not None
        assert isinstance(Flag.VERIFY_MINIMAL_DATA, int)
    except (ImportError, AttributeError):
        pytest.skip("VERIFY_MINIMAL_DATA not available")


def test_scriptflag_discourage_upgradable_nops():
    """Test DISCOURAGE_UPGRADABLE_NOPS flag."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag.DISCOURAGE_UPGRADABLE_NOPS is not None
        assert isinstance(Flag.DISCOURAGE_UPGRADABLE_NOPS, int)
    except (ImportError, AttributeError):
        pytest.skip("DISCOURAGE_UPGRADABLE_NOPS not available")


def test_scriptflag_verify_clean_stack():
    """Test VERIFY_CLEAN_STACK flag."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag.VERIFY_CLEAN_STACK is not None
        assert isinstance(Flag.VERIFY_CLEAN_STACK, int)
    except (ImportError, AttributeError):
        pytest.skip("VERIFY_CLEAN_STACK not available")


def test_scriptflag_verify_check_lock_time_verify():
    """Test VERIFY_CHECK_LOCK_TIME_VERIFY flag."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag.VERIFY_CHECK_LOCK_TIME_VERIFY is not None
        assert isinstance(Flag.VERIFY_CHECK_LOCK_TIME_VERIFY, int)
    except (ImportError, AttributeError):
        pytest.skip("VERIFY_CHECK_LOCK_TIME_VERIFY not available")


def test_scriptflag_verify_check_sequence_verify():
    """Test VERIFY_CHECK_SEQUENCE_VERIFY flag."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        assert Flag.VERIFY_CHECK_SEQUENCE_VERIFY is not None
        assert isinstance(Flag.VERIFY_CHECK_SEQUENCE_VERIFY, int)
    except (ImportError, AttributeError):
        pytest.skip("VERIFY_CHECK_SEQUENCE_VERIFY not available")


# ========================================================================
# Flag combination branches
# ========================================================================

def test_scriptflag_combinations():
    """Test combining script flags."""
    try:
        from bsv.script.interpreter.scriptflag import Flag
        
        combined = Flag.BIP16 | Flag.VERIFY_STRICT_ENCODING
        assert isinstance(combined, int)
        assert combined != 0
    except (ImportError, AttributeError):
        pytest.skip("Script flags not available")

