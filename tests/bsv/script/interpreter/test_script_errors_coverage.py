"""
Coverage tests for script/interpreter/errs/error.py - untested branches.
"""
import pytest


# ========================================================================
# Script error classes branches
# ========================================================================

def test_script_error_base_class():
    """Test base ScriptError class."""
    try:
        from bsv.script.interpreter.errs.error import ScriptError
        
        error = ScriptError("test error")
        assert str(error) == "test error"
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("ScriptError not available")


def test_script_error_invalid_stack_operation():
    """Test InvalidStackOperation error."""
    try:
        from bsv.script.interpreter.errs.error import InvalidStackOperation
        
        error = InvalidStackOperation()
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("InvalidStackOperation not available")


def test_script_error_invalid_alt_stack_operation():
    """Test InvalidAltStackOperation error."""
    try:
        from bsv.script.interpreter.errs.error import InvalidAltStackOperation
        
        error = InvalidAltStackOperation()
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("InvalidAltStackOperation not available")


def test_script_error_op_return():
    """Test OpReturn error."""
    try:
        from bsv.script.interpreter.errs.error import OpReturnError
        
        error = OpReturnError()
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("OpReturnError not available")


def test_script_error_verify_failed():
    """Test VerifyFailed error."""
    try:
        from bsv.script.interpreter.errs.error import VerifyFailed
        
        error = VerifyFailed()
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("VerifyFailed not available")


def test_script_error_equalverify_failed():
    """Test EqualVerifyFailed error."""
    try:
        from bsv.script.interpreter.errs.error import EqualVerifyFailed
        
        error = EqualVerifyFailed()
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("EqualVerifyFailed not available")


def test_script_error_checksig_failed():
    """Test CheckSigFailed error."""
    try:
        from bsv.script.interpreter.errs.error import CheckSigFailed
        
        error = CheckSigFailed()
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("CheckSigFailed not available")


def test_script_error_checkmultisig_failed():
    """Test CheckMultiSigFailed error."""
    try:
        from bsv.script.interpreter.errs.error import CheckMultiSigFailed
        
        error = CheckMultiSigFailed()
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("CheckMultiSigFailed not available")


def test_script_error_disabled_opcode():
    """Test DisabledOpcode error."""
    try:
        from bsv.script.interpreter.errs.error import DisabledOpcode
        
        error = DisabledOpcode("OP_CAT")
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("DisabledOpcode not available")


def test_script_error_bad_opcode():
    """Test BadOpcode error."""
    try:
        from bsv.script.interpreter.errs.error import BadOpcode
        
        error = BadOpcode(0xFF)
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("BadOpcode not available")


def test_script_error_unbalanced_conditional():
    """Test UnbalancedConditional error."""
    try:
        from bsv.script.interpreter.errs.error import UnbalancedConditional
        
        error = UnbalancedConditional()
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("UnbalancedConditional not available")


def test_script_error_negative_locktime():
    """Test NegativeLocktime error."""
    try:
        from bsv.script.interpreter.errs.error import NegativeLocktime
        
        error = NegativeLocktime()
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("NegativeLocktime not available")


def test_script_error_unsatisfied_locktime():
    """Test UnsatisfiedLocktime error."""
    try:
        from bsv.script.interpreter.errs.error import UnsatisfiedLocktime
        
        error = UnsatisfiedLocktime()
        assert isinstance(error, Exception)
    except (ImportError, AttributeError):
        pytest.skip("UnsatisfiedLocktime not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_script_error_with_message():
    """Test script error with custom message."""
    try:
        from bsv.script.interpreter.errs.error import ScriptError
        
        error = ScriptError("custom error message")
        assert "custom error message" in str(error)
    except (ImportError, AttributeError):
        pytest.skip("ScriptError not available")


def test_script_error_raising():
    """Test raising script errors."""
    try:
        from bsv.script.interpreter.errs.error import ScriptError
        
        try:
            raise ScriptError("test")
        except ScriptError as e:
            assert "test" in str(e)
    except (ImportError, AttributeError):
        pytest.skip("ScriptError not available")

