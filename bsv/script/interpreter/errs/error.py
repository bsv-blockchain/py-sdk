"""
Error definitions for script interpreter.

Ported from go-sdk/script/interpreter/errs/error.go
"""

from enum import IntEnum
from typing import Optional


class ErrorCode(IntEnum):
    """ErrorCode identifies a kind of script error."""

    # ErrInternal is returned if internal consistency checks fail.
    ERR_INTERNAL = 0

    # ErrOK represents successful execution.
    ERR_OK = 1

    # Failures related to improper API usage.
    ERR_INVALID_FLAGS = 2
    ERR_INVALID_INDEX = 3
    ERR_UNSUPPORTED_ADDRESS = 4
    ERR_NOT_MULTISIG_SCRIPT = 5
    ERR_TOO_MANY_REQUIRED_SIGS = 6
    ERR_TOO_MUCH_NULL_DATA = 7
    ERR_INVALID_PARAMS = 8

    # Failures related to final execution state.
    ERR_EARLY_RETURN = 9
    ERR_EMPTY_STACK = 10
    ERR_EVAL_FALSE = 11
    ERR_SCRIPT_UNFINISHED = 12
    ERR_INVALID_PROGRAM_COUNTER = 13

    # Failures related to exceeding maximum allowed limits.
    ERR_SCRIPT_TOO_BIG = 14
    ERR_ELEMENT_TOO_BIG = 15
    ERR_TOO_MANY_OPERATIONS = 16
    ERR_STACK_OVERFLOW = 17
    ERR_INVALID_STACK_OPERATION = 18
    ERR_INVALID_ALTSTACK_OPERATION = 19
    ERR_UNBALANCED_CONDITIONAL = 20

    # Failures related to operators.
    ERR_DISABLED_OPCODE = 21
    ERR_RESERVED_OPCODE = 22
    ERR_MALFORMED_PUSH = 23
    ERR_INVALID_SPLIT_RANGE = 24
    ERR_INVALID_BIT_NUMBER = 25

    # Failures related to CHECKMULTISIG.
    ERR_PUBKEY_COUNT = 29
    ERR_SIG_COUNT = 30
    ERR_PUBKEY_TYPE = 31
    ERR_SIG_TYPE = 32
    ERR_SIG_DER = 33
    ERR_SIG_HIGH_S = 34
    ERR_SIG_NULLFAIL = 35
    ERR_SIG_BADLENGTH = 36
    ERR_SIG_NONSCHNORR = 37

    # Failures related to CHECKSIG.
    ERR_SIG_TOO_SHORT = 38
    ERR_SIG_TOO_LONG = 39
    ERR_SIG_INVALID_SEQ_ID = 40
    ERR_SIG_INVALID_DATA_LEN = 41
    ERR_SIG_MISSING_S_TYPE_ID = 42
    ERR_SIG_MISSING_S_LEN = 43
    ERR_SIG_INVALID_S_LEN = 44
    ERR_SIG_INVALID_R_INT_ID = 45
    ERR_SIG_ZERO_R_LEN = 46
    ERR_SIG_NEGATIVE_R = 47
    ERR_SIG_TOO_MUCH_R_PADDING = 48
    ERR_SIG_INVALID_S_INT_ID = 49
    ERR_SIG_ZERO_S_LEN = 50
    ERR_SIG_NEGATIVE_S = 51
    ERR_SIG_TOO_MUCH_S_PADDING = 52
    ERR_SIG_MUST_HAVE_SIGHASH = 53
    ERR_SIG_HASHTYPE = 54
    ERR_SIG_INVALID = 55

    # Failures related to CHECKLOCKTIMEVERIFY.
    ERR_UNSATISFIED_LOCKTIME = 41

    # Failures related to CHECKSEQUENCEVERIFY.
    ERR_UNSATISFIED_LOCKTIME_SEQUENCE = 42

    # Failures related to number parsing.
    ERR_NUMBER_OVERFLOW = 43
    ERR_MINIMAL_DATA = 44
    ERR_INVALID_NUMBER_RANGE = 45
    ERR_NUMBER_TOO_BIG = 46
    ERR_DIVIDE_BY_ZERO = 47
    
    # Failures related to verification operations.
    ERR_VERIFY = 48
    ERR_EQUAL_VERIFY = 49
    ERR_NUM_EQUAL_VERIFY = 50
    ERR_CHECK_SIG_VERIFY = 51
    ERR_CHECK_MULTISIG_VERIFY = 52
    ERR_CLEAN_STACK = 53

    # Failures related to BIP16.
    # ERR_SIG_PUSHONLY reused from above

    # Failures related to BIP62.
    # (Reuses ERR_SIG_HIGH_S, ERR_SIG_NULLFAIL, ERR_MINIMAL_DATA, ERR_SIG_PUSHONLY)

    # Failures related to BIP143.
    # (Reuses ERR_SIG_MUST_HAVE_SIGHASH, ERR_SIG_HASHTYPE, ERR_SIG_INVALID, ERR_SIG_BADLENGTH, ERR_SIG_NONSCHNORR)

    # Failures related to BIP147.
    # (Reuses ERR_SIG_NULLFAIL)

    # Failures related to BIP341.
    # (Reuses ERR_SIG_MUST_HAVE_SIGHASH, ERR_SIG_HASHTYPE, ERR_SIG_INVALID, ERR_SIG_BADLENGTH, ERR_SIG_NONSCHNORR)


class Error(Exception):
    """Error identifies a script error."""

    def __init__(self, code: ErrorCode, message: str):
        self.code = code
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"{self.code.name}: {self.message}"

    def __repr__(self) -> str:
        return f"Error(code={self.code}, message={self.message!r})"


def new_error(code: ErrorCode, message: str, *args) -> Error:
    """Create a new error with optional formatting."""
    if args:
        message = message % args
    return Error(code, message)


def is_error_code(err: Optional[Exception], code: ErrorCode) -> bool:
    """Check if an error matches a specific error code."""
    if err is None:
        return False
    if isinstance(err, Error):
        return err.code == code
    return False

