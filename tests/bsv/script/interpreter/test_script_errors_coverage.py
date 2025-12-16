"""
Coverage tests for script/interpreter/errs/error.py - untested branches.
"""
import pytest


# ========================================================================
# Script error classes branches
# ========================================================================

def test_script_error_base_class():
    """Test base Error class."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_OK, "test error")
    assert str(error) == "ERR_OK: test error"
    assert isinstance(error, Exception)


def test_script_error_invalid_stack_operation():
    """Test InvalidStackOperation error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "invalid stack operation")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_INVALID_STACK_OPERATION


def test_script_error_invalid_alt_stack_operation():
    """Test InvalidAltStackOperation error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_INVALID_ALTSTACK_OPERATION, "invalid alt stack operation")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_INVALID_ALTSTACK_OPERATION


def test_script_error_op_return():
    """Test OpReturn error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_EARLY_RETURN, "op return error")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_EARLY_RETURN


def test_script_error_verify_failed():
    """Test VerifyFailed error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_VERIFY, "verify failed")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_VERIFY


def test_script_error_equalverify_failed():
    """Test EqualVerifyFailed error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_EQUAL_VERIFY, "equal verify failed")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_EQUAL_VERIFY


def test_script_error_checksig_failed():
    """Test CheckSigFailed error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_CHECK_SIG_VERIFY, "checksig failed")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_CHECK_SIG_VERIFY


def test_script_error_checkmultisig_failed():
    """Test CheckMultiSigFailed error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_CHECK_MULTISIG_VERIFY, "checkmultisig failed")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_CHECK_MULTISIG_VERIFY


def test_script_error_disabled_opcode():
    """Test DisabledOpcode error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_DISABLED_OPCODE, "OP_CAT disabled")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_DISABLED_OPCODE


def test_script_error_bad_opcode():
    """Test BadOpcode error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_RESERVED_OPCODE, "bad opcode 0xFF")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_RESERVED_OPCODE


def test_script_error_unbalanced_conditional():
    """Test UnbalancedConditional error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_UNBALANCED_CONDITIONAL, "unbalanced conditional")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_UNBALANCED_CONDITIONAL


def test_script_error_negative_locktime():
    """Test NegativeLocktime error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_UNSATISFIED_LOCKTIME, "negative locktime")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_UNSATISFIED_LOCKTIME


def test_script_error_unsatisfied_locktime():
    """Test UnsatisfiedLocktime error."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_UNSATISFIED_LOCKTIME, "unsatisfied locktime")
    assert isinstance(error, Exception)
    assert error.code == ErrorCode.ERR_UNSATISFIED_LOCKTIME


# ========================================================================
# Edge cases
# ========================================================================

def test_script_error_with_message():
    """Test script error with custom message."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    error = Error(ErrorCode.ERR_OK, "custom error message")
    assert "custom error message" in str(error)


def test_script_error_raising():
    """Test raising script errors."""
    from bsv.script.interpreter.errs.error import Error, ErrorCode

    try:
        raise Error(ErrorCode.ERR_OK, "test")
    except Error as e:
        assert "test" in str(e)

