"""
Opcode operations for script interpreter.

Ported from go-sdk/script/interpreter/operations.go and py-sdk/bsv/script/spend.py
"""

from typing import Optional, List

from bsv.constants import OpCode, SIGHASH
from bsv.curve import curve
from bsv.hash import sha1, sha256, ripemd160, hash256, hash160
from bsv.keys import PublicKey
from bsv.script.script import Script
from bsv.transaction_input import TransactionInput
from bsv.transaction_preimage import tx_preimage
from bsv.utils import unsigned_to_bytes, deserialize_ecdsa_der

from .errs import Error, ErrorCode
from .number import ScriptNumber
from .op_parser import ParsedOpcode
from .stack import Stack

# Type hint for Thread to avoid circular import
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .thread import Thread


# Helper functions from Spend class
def cast_to_bool(val: bytes) -> bool:
    """Convert bytes to boolean."""
    for i in range(len(val)):
        if val[i] != 0:
            # can be negative zero
            if i == len(val) - 1 and val[i] == 0x80:
                return False
            return True
    return False


def encode_bool(f: bool) -> bytes:
    """Convert boolean to bytes."""
    return b"\x01" if f else b""


def bin2num(octets: bytes) -> int:
    """Convert bytes to number."""
    if len(octets) == 0:
        return 0
    negative = octets[-1] & 0x80
    octets = bytearray(octets)
    octets[-1] &= 0x7F
    n = int.from_bytes(octets, "little")
    return -n if negative else n


def minimally_encode(num: int) -> bytes:
    """Encode number minimally."""
    if num == 0:
        return b""
    negative = num < 0
    octets = bytearray(unsigned_to_bytes(-num if negative else num, "little"))
    if octets and octets[-1] & 0x80:
        octets += b"\x00"
    if negative:
        octets[-1] |= 0x80
    return bytes(octets)


def check_signature_encoding(octets: bytes, require_low_s: bool = True, require_der: bool = True, _: bool = False) -> Optional[Error]:  # NOSONAR - Complexity (26), requires refactoring
    """
    Check signature encoding with detailed DER validation.

    This implements the same validation as the Go SDK's checkSignatureEncoding.
    """
    if octets == b"":
        return None

    if len(octets) < 1:
        # Empty signatures are allowed but result in CHECKSIG returning false
        return None

    sig, sighash_byte = octets[:-1], octets[-1]

    # Check sighash type only if DER validation is required
    if require_der:
        try:
            _ = SIGHASH(sighash_byte)  # Validate _ type
        except (ValueError, TypeError):
            return Error(ErrorCode.ERR_SIG_HASHTYPE, "invalid sighash type")

    # If not requiring DER validation, skip the rest
    if not require_der:
        return None

    # Detailed DER signature validation
    sig_len = len(sig)

    # Constants from Go SDK
    asn1_sequence_id = 0x30
    asn1_integer_id = 0x02
    min_sig_len = 8
    max_sig_len = 72

    # Offsets within signature
    sequence_offset = 0
    data_len_offset = 1
    r_type_offset = 2
    r_len_offset = 3

    # The signature must adhere to the minimum and maximum allowed length.
    if sig_len < min_sig_len:
        return Error(ErrorCode.ERR_SIG_TOO_SHORT, f"malformed signature: too short: {sig_len} < {min_sig_len}")
    if sig_len > max_sig_len:
        return Error(ErrorCode.ERR_SIG_TOO_LONG, f"malformed signature: too long: {sig_len} > {max_sig_len}")

    # The signature must start with the ASN.1 sequence identifier.
    if sig[sequence_offset] != asn1_sequence_id:
        return Error(ErrorCode.ERR_SIG_INVALID_SEQ_ID, f"malformed signature: format has wrong type: {sig[sequence_offset]:#x}")

    # The signature must indicate the correct amount of data for all elements
    # related to R and S.
    if int(sig[data_len_offset]) != sig_len - 2:
        return Error(ErrorCode.ERR_SIG_INVALID_DATA_LEN,
                    f"malformed signature: bad length: {sig[data_len_offset]} != {sig_len - 2}")

    # Calculate the offsets of the elements related to S and ensure S is inside
    # the signature.
    r_len = int(sig[r_len_offset])
    s_type_offset = r_type_offset + r_len + 1  # +1 for r_type byte
    s_len_offset = s_type_offset + 1

    if s_type_offset >= sig_len:
        return Error(ErrorCode.ERR_SIG_MISSING_S_TYPE_ID, "malformed signature: S type indicator missing")
    if s_len_offset >= sig_len:
        return Error(ErrorCode.ERR_SIG_MISSING_S_LEN, "malformed signature: S length missing")

    # The lengths of R and S must match the overall length of the signature.
    s_offset = s_len_offset + 1
    s_len = int(sig[s_len_offset])
    if s_offset + s_len != sig_len:
        return Error(ErrorCode.ERR_SIG_INVALID_S_LEN, "malformed signature: invalid S length")

    # R elements must be ASN.1 integers.
    if sig[r_type_offset] != asn1_integer_id:
        return Error(ErrorCode.ERR_SIG_INVALID_R_INT_ID,
                    f"malformed signature: R integer marker: {sig[r_type_offset]:#x} != {asn1_integer_id:#x}")

    # Zero-length integers are not allowed for R.
    if r_len == 0:
        return Error(ErrorCode.ERR_SIG_ZERO_R_LEN, "malformed signature: R length is zero")

    # R must not be negative.
    r_start = r_len_offset + 1
    if sig[r_start] & 0x80 != 0:
        return Error(ErrorCode.ERR_SIG_NEGATIVE_R, "malformed signature: R is negative")

    # Null bytes at the start of R are not allowed, unless R would otherwise be
    # interpreted as a negative number.
    if r_len > 1 and sig[r_start] == 0x00 and sig[r_start + 1] & 0x80 == 0:
        return Error(ErrorCode.ERR_SIG_TOO_MUCH_R_PADDING, "malformed signature: R value has too much padding")

    # S elements must be ASN.1 integers.
    if sig[s_type_offset] != asn1_integer_id:
        return Error(ErrorCode.ERR_SIG_INVALID_S_INT_ID,
                    f"malformed signature: S integer marker: {sig[s_type_offset]:#x} != {asn1_integer_id:#x}")

    # Zero-length integers are not allowed for S.
    if s_len == 0:
        return Error(ErrorCode.ERR_SIG_ZERO_S_LEN, "malformed signature: S length is zero")

    # S must not be negative.
    if sig[s_offset] & 0x80 != 0:
        return Error(ErrorCode.ERR_SIG_NEGATIVE_S, "malformed signature: S is negative")

    # Null bytes at the start of S are not allowed, unless S would otherwise be
    # interpreted as a negative number.
    if s_len > 1 and sig[s_offset] == 0x00 and sig[s_offset + 1] & 0x80 == 0:
        return Error(ErrorCode.ERR_SIG_TOO_MUCH_S_PADDING, "malformed signature: S value has too much padding")

    # Verify the S value is <= half the order of the curve.
    if require_low_s:
        s_value = int.from_bytes(sig[s_offset:s_offset + s_len], byteorder='big')
        if s_value > curve.n // 2:
            return Error(ErrorCode.ERR_SIG_HIGH_S, "signature is not canonical due to unnecessarily high S value")

    return None


def remove_signature_from_script(script: List[ParsedOpcode], sig: bytes) -> List[ParsedOpcode]:
    """
    Remove all occurrences of the signature from the script.

    This is used for sighash generation when not using FORKID.
    """
    result = []
    for opcode in script:
        if opcode.data != sig:
            result.append(opcode)
    return result


def check_public_key_encoding(octets: bytes) -> Optional[Error]:
    """
    Check public key encoding with detailed validation matching TypeScript SDK.

    Returns None if valid, Error if invalid.
    """
    if len(octets) == 0:
        return Error(ErrorCode.ERR_PUBKEY_TYPE, "Public key is empty")

    if len(octets) < 33:
        return Error(ErrorCode.ERR_PUBKEY_TYPE, "The public key is too short, it must be at least 33 bytes")

    # Check format based on first byte
    if octets[0] == 0x04:  # Uncompressed
        if len(octets) != 65:
            return Error(ErrorCode.ERR_PUBKEY_TYPE, "The non-compressed public key must be 65 bytes")
    elif octets[0] == 0x02 or octets[0] == 0x03:  # Compressed
        if len(octets) != 33:
            return Error(ErrorCode.ERR_PUBKEY_TYPE, "The compressed public key must be 33 bytes")
    else:
        return Error(ErrorCode.ERR_PUBKEY_TYPE, "The public key is in an unknown format")

    # Try to parse the public key
    try:
        PublicKey(octets)
    except Exception:
        return Error(ErrorCode.ERR_PUBKEY_TYPE, "The public key is in an unknown format")

    return None


# Opcode implementations
def op_push_data(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle data push opcodes."""
    if pop.data is None:
        t.dstack.push_byte_array(b"")
    else:
        if len(pop.data) > t.cfg.max_script_element_size():
            return Error(
                ErrorCode.ERR_ELEMENT_TOO_BIG,
                f"element size {len(pop.data)} exceeds max {t.cfg.max_script_element_size()}",
            )
        t.dstack.push_byte_array(pop.data)
    return None


def op_n(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_1 through OP_16."""
    n = int.from_bytes(pop.opcode, "big") - int.from_bytes(OpCode.OP_1, "big") + 1
    t.dstack.push_byte_array(minimally_encode(n))
    return None


def op_1negate(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_1NEGATE."""
    t.dstack.push_byte_array(minimally_encode(-1))
    return None


def op_nop(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NOP."""
    return None


def op_if(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_IF."""
    f = False
    if t.is_branch_executing():
        if t.dstack.depth() < 1:
            return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_IF requires at least one item on stack")
        val = t.dstack.peek_byte_array(0)
        f = cast_to_bool(val)
        t.dstack.pop_byte_array()
    t.cond_stack.append(1 if f else 0)
    return None


def op_notif(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NOTIF."""
    f = False
    if t.is_branch_executing():
        if t.dstack.depth() < 1:
            return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_NOTIF requires at least one item on stack")
        val = t.dstack.peek_byte_array(0)
        f = cast_to_bool(val)
        t.dstack.pop_byte_array()
    t.cond_stack.append(1 if not f else 0)
    return None


def op_else(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ELSE."""
    if len(t.cond_stack) == 0:
        return Error(ErrorCode.ERR_UNBALANCED_CONDITIONAL, "OP_ELSE requires preceding OP_IF")
    t.cond_stack[-1] = 1 - t.cond_stack[-1]
    return None


def op_endif(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ENDIF."""
    if len(t.cond_stack) == 0:
        return Error(ErrorCode.ERR_UNBALANCED_CONDITIONAL, "OP_ENDIF requires preceding OP_IF")
    t.cond_stack.pop()
    return None


def op_verify(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_VERIFY."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_VERIFY requires at least one item on stack")
    val = t.dstack.pop_byte_array()
    if not cast_to_bool(val):
        return Error(ErrorCode.ERR_VERIFY, "OP_VERIFY failed")
    return None


def op_return(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_RETURN."""
    t.early_return_after_genesis = True
    return Error(ErrorCode.ERR_EARLY_RETURN, "OP_RETURN executed")


def op_to_alt_stack(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_TOALTSTACK."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_TOALTSTACK requires at least one item on stack")
    val = t.dstack.pop_byte_array()
    t.astack.push_byte_array(val)
    return None


def op_from_alt_stack(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_FROMALTSTACK."""
    if t.astack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_ALTSTACK_OPERATION, "OP_FROMALTSTACK requires at least one item on alt stack")
    val = t.astack.pop_byte_array()
    t.dstack.push_byte_array(val)
    return None


def op_2drop(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_2DROP."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_2DROP requires at least two items on stack")
    t.dstack.pop_byte_array()
    t.dstack.pop_byte_array()
    return None


def op_2dup(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_2DUP."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_2DUP requires at least two items on stack")
    x1 = t.dstack.peek_byte_array(1)
    x2 = t.dstack.peek_byte_array(0)
    t.dstack.push_byte_array(x1)
    t.dstack.push_byte_array(x2)
    return None


def op_3dup(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_3DUP."""
    if t.dstack.depth() < 3:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_3DUP requires at least three items on stack")
    x1 = t.dstack.peek_byte_array(2)
    x2 = t.dstack.peek_byte_array(1)
    x3 = t.dstack.peek_byte_array(0)
    t.dstack.push_byte_array(x1)
    t.dstack.push_byte_array(x2)
    t.dstack.push_byte_array(x3)
    return None


def op_2over(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_2OVER."""
    if t.dstack.depth() < 4:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_2OVER requires at least four items on stack")
    x1 = t.dstack.peek_byte_array(3)
    x2 = t.dstack.peek_byte_array(2)
    t.dstack.push_byte_array(x1)
    t.dstack.push_byte_array(x2)
    return None


def op_2rot(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_2ROT."""
    if t.dstack.depth() < 6:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_2ROT requires at least six items on stack")
    x1 = t.dstack.nip_n(5)
    x2 = t.dstack.nip_n(4)
    t.dstack.push_byte_array(x1)
    t.dstack.push_byte_array(x2)
    return None


def op_2swap(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_2SWAP."""
    if t.dstack.depth() < 4:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_2SWAP requires at least four items on stack")
    x1 = t.dstack.nip_n(3)
    x2 = t.dstack.nip_n(2)
    t.dstack.push_byte_array(x1)
    t.dstack.push_byte_array(x2)
    return None


def op_ifdup(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_IFDUP."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_IFDUP requires at least one item on stack")
    val = t.dstack.peek_byte_array(0)
    if cast_to_bool(val):
        t.dstack.push_byte_array(val)
    return None


def op_depth(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_DEPTH."""
    depth = t.dstack.depth()
    t.dstack.push_byte_array(minimally_encode(depth))
    return None


def op_drop(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_DROP."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_DROP requires at least one item on stack")
    t.dstack.pop_byte_array()
    return None


def op_dup(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_DUP."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_DUP requires at least one item on stack")
    val = t.dstack.peek_byte_array(0)
    t.dstack.push_byte_array(val)
    return None


def op_nip(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NIP."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_NIP requires at least two items on stack")
    t.dstack.nip_n(1)
    return None


def op_over(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_OVER."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_OVER requires at least two items on stack")
    val = t.dstack.peek_byte_array(1)
    t.dstack.push_byte_array(val)
    return None


def op_pick(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_PICK."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_PICK requires at least two items on stack")
    n = bin2num(t.dstack.pop_byte_array())
    if n < 0 or n >= t.dstack.depth():
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, f"OP_PICK index {n} out of range")
    val = t.dstack.peek_byte_array(n)
    t.dstack.push_byte_array(val)
    return None


def op_roll(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ROLL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_ROLL requires at least two items on stack")
    n = bin2num(t.dstack.pop_byte_array())
    if n < 0 or n >= t.dstack.depth():
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, f"OP_ROLL index {n} out of range")
    val = t.dstack.nip_n(n)
    t.dstack.push_byte_array(val)
    return None


def op_rot(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ROT."""
    if t.dstack.depth() < 3:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_ROT requires at least three items on stack")
    x1 = t.dstack.nip_n(2)
    x2 = t.dstack.nip_n(1)
    x3 = t.dstack.pop_byte_array()
    t.dstack.push_byte_array(x1)
    t.dstack.push_byte_array(x3)
    t.dstack.push_byte_array(x2)
    return None


def op_swap(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_SWAP."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_SWAP requires at least two items on stack")
    x1 = t.dstack.pop_byte_array()
    x2 = t.dstack.pop_byte_array()
    t.dstack.push_byte_array(x1)
    t.dstack.push_byte_array(x2)
    return None


def op_tuck(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_TUCK."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_TUCK requires at least two items on stack")
    # Copy top item to position 2
    top = t.dstack.peek_byte_array(0)
    t.dstack.push_byte_array(top)
    return None


def op_size(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_SIZE."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_SIZE requires at least one item on stack")
    val = t.dstack.peek_byte_array(0)
    size = len(val)
    t.dstack.push_byte_array(minimally_encode(size))
    return None


def op_equal(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_EQUAL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_EQUAL requires at least two items on stack")
    x1 = t.dstack.pop_byte_array()
    x2 = t.dstack.pop_byte_array()
    result = x1 == x2
    t.dstack.push_byte_array(encode_bool(result))
    return None


def op_equal_verify(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_EQUALVERIFY."""
    err = op_equal(pop, t)
    if err:
        return err
    val = t.dstack.pop_byte_array()
    if not cast_to_bool(val):
        return Error(ErrorCode.ERR_EQUAL_VERIFY, "OP_EQUALVERIFY failed")
    return None


def op_1add(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_1ADD."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_1ADD requires at least one item on stack")
    x = bin2num(t.dstack.pop_byte_array())
    result = x + 1
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_1sub(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_1SUB."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_1SUB requires at least one item on stack")
    x = bin2num(t.dstack.pop_byte_array())
    result = x - 1
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_negate(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NEGATE."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_NEGATE requires at least one item on stack")
    x = t.dstack.pop_int()
    result = ScriptNumber(-x.value)
    t.dstack.push_int(result)
    return None


def op_abs(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ABS."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_ABS requires at least one item on stack")
    x = t.dstack.pop_int()
    result = ScriptNumber(abs(x.value))
    t.dstack.push_int(result)
    return None


def op_not(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NOT."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_NOT requires at least one item on stack")
    x = bin2num(t.dstack.pop_byte_array())
    result = 1 if x == 0 else 0
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_0notequal(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_0NOTEQUAL."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_0NOTEQUAL requires at least one item on stack")
    x = bin2num(t.dstack.pop_byte_array())
    result = 1 if x != 0 else 0
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_add(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ADD."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_ADD requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    result = x1 + x2
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_sub(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_SUB."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_SUB requires at least two items on stack")
    x1 = t.dstack.pop_int()
    x2 = t.dstack.pop_int()
    result = ScriptNumber(x2.value - x1.value)
    t.dstack.push_int(result)
    return None


def op_mul(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_MUL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_MUL requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    result = x1 * x2
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_div(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_DIV."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_DIV requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    if x2 == 0:
        return Error(ErrorCode.ERR_DIVIDE_BY_ZERO, "OP_DIV cannot divide by zero")
    result = x1 // x2
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_mod(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_MOD."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_MOD requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    if x2 == 0:
        return Error(ErrorCode.ERR_DIVIDE_BY_ZERO, "OP_MOD cannot divide by zero")
    result = x1 % x2
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_booland(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_BOOLAND."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_BOOLAND requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    result = 1 if (x1 != 0 and x2 != 0) else 0
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_boolor(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_BOOLOR."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_BOOLOR requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    result = 1 if (x1 != 0 or x2 != 0) else 0
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_numequal(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NUMEQUAL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_NUMEQUAL requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    result = 1 if x1 == x2 else 0
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_numequal_verify(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NUMEQUALVERIFY."""
    err = op_numequal(pop, t)
    if err:
        return err
    val = t.dstack.pop_byte_array()
    if not cast_to_bool(val):
        return Error(ErrorCode.ERR_NUM_EQUAL_VERIFY, "OP_NUMEQUALVERIFY failed")
    return None


def op_numnotequal(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NUMNOTEQUAL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_NUMNOTEQUAL requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    result = 1 if x1 != x2 else 0
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_lessthan(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_LESSTHAN."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_LESSTHAN requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    result = 1 if x1 < x2 else 0
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_greaterthan(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_GREATERTHAN."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_GREATERTHAN requires at least two items on stack")
    x1 = t.dstack.pop_int()
    x2 = t.dstack.pop_int()
    result = ScriptNumber(1 if x2.value > x1.value else 0)
    t.dstack.push_int(result)
    return None


def op_lessthanorequal(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_LESSTHANOREQUAL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_LESSTHANOREQUAL requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    result = 1 if x1 <= x2 else 0
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_greaterthanorequal(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_GREATERTHANOREQUAL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_GREATERTHANOREQUAL requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    result = 1 if x1 >= x2 else 0
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_min(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_MIN."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_MIN requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    result = min(x1, x2)
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_max(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_MAX."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_MAX requires at least two items on stack")
    x1 = bin2num(t.dstack.pop_byte_array())
    x2 = bin2num(t.dstack.pop_byte_array())
    result = max(x1, x2)
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_within(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_WITHIN."""
    if t.dstack.depth() < 3:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_WITHIN requires at least three items on stack")
    value = t.dstack.pop_int()
    max_val = t.dstack.pop_int()
    min_val = t.dstack.pop_int()
    result = ScriptNumber(1 if min_val.value <= value.value < max_val.value else 0)
    t.dstack.push_int(result)
    return None


def op_ripemd160(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_RIPEMD160."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_RIPEMD160 requires at least one item on stack")
    val = t.dstack.pop_byte_array()
    result = ripemd160(val)
    t.dstack.push_byte_array(result)
    return None


def op_sha1(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_SHA1."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_SHA1 requires at least one item on stack")
    val = t.dstack.pop_byte_array()
    result = sha1(val)
    t.dstack.push_byte_array(result)
    return None


def op_sha256(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_SHA256."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_SHA256 requires at least one item on stack")
    val = t.dstack.pop_byte_array()
    result = sha256(val)
    t.dstack.push_byte_array(result)
    return None


def op_hash160(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_HASH160."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_HASH160 requires at least one item on stack")
    val = t.dstack.pop_byte_array()
    result = hash160(val)
    t.dstack.push_byte_array(result)
    return None


def op_hash256(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_HASH256."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_HASH256 requires at least one item on stack")
    val = t.dstack.pop_byte_array()
    result = hash256(val)
    t.dstack.push_byte_array(result)
    return None


def op_codeseparator(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_CODESEPARATOR."""
    t.last_code_sep = t.script_off
    return None


def op_checksig(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_CHECKSIG."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_CHECKSIG requires at least two items on stack")
    
    pub_key = t.dstack.pop_byte_array()
    sig = t.dstack.pop_byte_array()
    
    # Validate encodings
    err = _validate_signature_and_pubkey_encoding(t, sig, pub_key)
    if err:
        return err
    
    # Handle empty signature
    if len(sig) < 1:
        t.dstack.push_byte_array(encode_bool(False))
        return None
    
    # Extract and validate sighash
    sighash_flag, sig_bytes, err = _extract_sighash_from_signature(t, sig)
    if err:
        return err
    
    # Compute signature hash
    sighash = _compute_signature_hash(t, sig, sighash_flag)
    if sighash is None:
        t.dstack.push_byte_array(encode_bool(False))
        return None
    
    # Verify signature and check null fail
    result = _verify_signature_with_nullfail(t, pub_key, sig_bytes, sighash)
    if isinstance(result, Error):
        return result
    
    t.dstack.push_byte_array(encode_bool(result))
    return None

def _validate_signature_and_pubkey_encoding(t: "Thread", sig: bytes, pub_key: bytes) -> Optional[Error]:
    """Validate signature and public key encodings based on flags."""
    require_der = t.flags.has_flag(t.flags.VERIFY_DER_SIGNATURES) or t.flags.has_flag(t.flags.VERIFY_STRICT_ENCODING)
    require_low_s = t.flags.has_flag(t.flags.VERIFY_LOW_S)
    require_strict = t.flags.has_flag(t.flags.VERIFY_STRICT_ENCODING)

    err = check_signature_encoding(sig, require_low_s, require_der, require_strict)
    if err:
        return err
    
    if require_strict:
        return check_public_key_encoding(pub_key)
    return None

def _extract_sighash_from_signature(t: "Thread", sig: bytes) -> tuple:
    """Extract sighash type from signature."""
    sighash_type = sig[-1]
    sig_bytes = sig[:-1]
    
    require_der = t.flags.has_flag(t.flags.VERIFY_DER_SIGNATURES) or t.flags.has_flag(t.flags.VERIFY_STRICT_ENCODING)
    
    if require_der:
        try:
            sighash_flag = SIGHASH(sighash_type)
        except (ValueError, TypeError):
            return None, None, Error(ErrorCode.ERR_SIG_HASHTYPE, "invalid sighash type")
    else:
        sighash_flag = SIGHASH.ALL
    
    return sighash_flag, sig_bytes, None

def _compute_signature_hash(t: "Thread", sig: bytes, sighash_flag) -> Optional[bytes]:
    """Compute the signature hash for verification."""
    sub_script = t.sub_script()
    
    if not (sighash_flag & SIGHASH.FORKID):
        sub_script = remove_signature_from_script(sub_script, sig)
    
    try:
        script_bytes = b"".join(
            opcode.opcode + (opcode.data if opcode.data else b"")
            for opcode in sub_script
        )
        
        from bsv.script.script import Script
        original_locking_script = t.tx.inputs[t.input_idx].locking_script
        t.tx.inputs[t.input_idx].locking_script = Script.from_bytes(script_bytes)
        
        sighash = t.tx.preimage(t.input_idx)
        
        t.tx.inputs[t.input_idx].locking_script = original_locking_script
        return sighash
    except Exception:
        return None

def _verify_signature_with_nullfail(t: "Thread", pub_key: bytes, sig_bytes: bytes, sighash: bytes):
    """Verify signature and check null fail condition."""
    try:
        pubkey_obj = PublicKey(pub_key)
        result = pubkey_obj.verify(sig_bytes, sighash)
    except Exception:
        result = False
    
    if not result and len(sig_bytes) > 0 and t.flags.has_flag(t.flags.VERIFY_NULL_FAIL):
        return Error(ErrorCode.ERR_NULLFAIL, "signature not empty on failed checksig")
    
    return result


def op_checksig_verify(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_CHECKSIGVERIFY."""
    err = op_checksig(pop, t)
    if err:
        return err
    val = t.dstack.pop_byte_array()
    if not cast_to_bool(val):
        return Error(ErrorCode.ERR_CHECK_SIG_VERIFY, "OP_CHECKSIGVERIFY failed")
    return None


def op_checkmultisig(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_CHECKMULTISIG."""
    # Simplified implementation - full version would verify signatures
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_CHECKMULTISIG requires at least one item on stack")
    
    keys_count = bin2num(t.dstack.peek_byte_array(0))
    if keys_count < 0 or keys_count > t.cfg.max_pub_keys_per_multisig():
        return Error(ErrorCode.ERR_PUBKEY_COUNT, f"invalid key count: {keys_count}")
    
    # Simplified - just return False for now
    result = False
    t.dstack.push_byte_array(encode_bool(result))
    return None


def op_checkmultisig_verify(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_CHECKMULTISIGVERIFY."""
    err = op_checkmultisig(pop, t)
    if err:
        return err
    val = t.dstack.pop_byte_array()
    if not cast_to_bool(val):
        return Error(ErrorCode.ERR_CHECK_MULTISIG_VERIFY, "OP_CHECKMULTISIGVERIFY failed")
    return None


def op_cat(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_CAT."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_CAT requires at least two items on stack")
    x1 = t.dstack.pop_byte_array()
    x2 = t.dstack.pop_byte_array()
    if len(x1) + len(x2) > t.cfg.max_script_element_size():
        return Error(ErrorCode.ERR_ELEMENT_TOO_BIG, "OP_CAT result exceeds max element size")
    t.dstack.push_byte_array(x1 + x2)
    return None


def op_split(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_SPLIT."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_SPLIT requires at least two items on stack")
    n = bin2num(t.dstack.pop_byte_array())
    x1 = t.dstack.pop_byte_array()
    if n < 0 or n > len(x1):
        return Error(ErrorCode.ERR_INVALID_SPLIT_RANGE, f"OP_SPLIT index {n} out of range")
    t.dstack.push_byte_array(x1[:n])
    t.dstack.push_byte_array(x1[n:])
    return None


def op_num2bin(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NUM2BIN."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_NUM2BIN requires at least two items on stack")
    size = bin2num(t.dstack.pop_byte_array())
    if size > t.cfg.max_script_element_size():
        return Error(ErrorCode.ERR_ELEMENT_TOO_BIG, "OP_NUM2BIN size exceeds max element size")
    n = bin2num(t.dstack.pop_byte_array())
    x = bytearray(minimally_encode(n))
    
    if len(x) > size:
        return Error(ErrorCode.ERR_INVALID_NUMBER_RANGE, "OP_NUM2BIN size too small for number")
    
    msb = b"\x00"
    if len(x) > 0:
        msb = bytes([x[-1] & 0x80])
        x[-1] &= 0x7F
    
    octets = x + b"\x00" * (size - len(x))
    octets[-1] |= int.from_bytes(msb, "big")
    
    t.dstack.push_byte_array(bytes(octets))
    return None


def op_bin2num(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_BIN2NUM."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_BIN2NUM requires at least one item on stack")
    x = t.dstack.pop_byte_array()
    result = bin2num(x)
    t.dstack.push_byte_array(minimally_encode(result))
    return None


def op_invert(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_INVERT."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_INVERT requires at least one item on stack")
    x = t.dstack.pop_byte_array()
    result = bytes([~b & 0xFF for b in x])
    t.dstack.push_byte_array(result)
    return None


def op_and(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_AND."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_AND requires at least two items on stack")
    x1 = t.dstack.pop_byte_array()
    x2 = t.dstack.pop_byte_array()
    if len(x1) != len(x2):
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_AND requires operands of same size")
    result = bytes([a & b for a, b in zip(x1, x2)])
    t.dstack.push_byte_array(result)
    return None


def op_or(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_OR."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_OR requires at least two items on stack")
    x1 = t.dstack.pop_byte_array()
    x2 = t.dstack.pop_byte_array()
    if len(x1) != len(x2):
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_OR requires operands of same size")
    result = bytes([a | b for a, b in zip(x1, x2)])
    t.dstack.push_byte_array(result)
    return None


def op_xor(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_XOR."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_XOR requires at least two items on stack")
    x1 = t.dstack.pop_byte_array()
    x2 = t.dstack.pop_byte_array()
    if len(x1) != len(x2):
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_XOR requires operands of same size")
    result = bytes([a ^ b for a, b in zip(x1, x2)])
    t.dstack.push_byte_array(result)
    return None


def op_lshift(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_LSHIFT."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_LSHIFT requires at least two items on stack")
    n = bin2num(t.dstack.pop_byte_array())
    if n < 0:
        return Error(ErrorCode.ERR_INVALID_BIT_NUMBER, "OP_LSHIFT requires non-negative shift amount")
    x = t.dstack.pop_byte_array()
    if n >= len(x):
        result = b"\x00" * len(x)
    else:
        result = x[n:] + b"\x00" * n
    t.dstack.push_byte_array(result)
    return None


def op_rshift(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_RSHIFT."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_RSHIFT requires at least two items on stack")
    n = bin2num(t.dstack.pop_byte_array())
    if n < 0:
        return Error(ErrorCode.ERR_INVALID_BIT_NUMBER, "OP_RSHIFT requires non-negative shift amount")
    x = t.dstack.pop_byte_array()
    if n >= len(x):
        result = b"\x00" * len(x)
    else:
        result = b"\x00" * n + x[:-n] if n > 0 else x
    t.dstack.push_byte_array(result)
    return None


# Opcode dispatch table
OPCODE_DISPATCH = {
    # Data push opcodes
    **{bytes([i]): op_push_data for i in range(1, 76)},  # OP_DATA_1 through OP_DATA_75
    OpCode.OP_PUSHDATA1: op_push_data,
    OpCode.OP_PUSHDATA2: op_push_data,
    OpCode.OP_PUSHDATA4: op_push_data,
    OpCode.OP_0: op_push_data,
    OpCode.OP_1NEGATE: op_1negate,
    OpCode.OP_1: op_n,
    OpCode.OP_2: op_n,
    OpCode.OP_3: op_n,
    OpCode.OP_4: op_n,
    OpCode.OP_5: op_n,
    OpCode.OP_6: op_n,
    OpCode.OP_7: op_n,
    OpCode.OP_8: op_n,
    OpCode.OP_9: op_n,
    OpCode.OP_10: op_n,
    OpCode.OP_11: op_n,
    OpCode.OP_12: op_n,
    OpCode.OP_13: op_n,
    OpCode.OP_14: op_n,
    OpCode.OP_15: op_n,
    OpCode.OP_16: op_n,
    # Control opcodes
    OpCode.OP_NOP: op_nop,
    OpCode.OP_NOP1: op_nop,
    OpCode.OP_NOP2: op_nop,
    OpCode.OP_NOP3: op_nop,
    OpCode.OP_NOP4: op_nop,
    OpCode.OP_NOP5: op_nop,
    OpCode.OP_NOP6: op_nop,
    OpCode.OP_NOP7: op_nop,
    OpCode.OP_NOP8: op_nop,
    OpCode.OP_NOP9: op_nop,
    OpCode.OP_NOP10: op_nop,
    OpCode.OP_NOP11: op_nop,
    OpCode.OP_NOP12: op_nop,
    OpCode.OP_NOP13: op_nop,
    OpCode.OP_NOP14: op_nop,
    OpCode.OP_NOP15: op_nop,
    OpCode.OP_NOP16: op_nop,
    OpCode.OP_NOP17: op_nop,
    OpCode.OP_NOP18: op_nop,
    OpCode.OP_NOP19: op_nop,
    OpCode.OP_NOP20: op_nop,
    OpCode.OP_NOP21: op_nop,
    OpCode.OP_NOP22: op_nop,
    OpCode.OP_NOP23: op_nop,
    OpCode.OP_NOP24: op_nop,
    OpCode.OP_NOP25: op_nop,
    OpCode.OP_NOP26: op_nop,
    OpCode.OP_NOP27: op_nop,
    OpCode.OP_NOP28: op_nop,
    OpCode.OP_NOP29: op_nop,
    OpCode.OP_NOP30: op_nop,
    OpCode.OP_NOP31: op_nop,
    OpCode.OP_NOP32: op_nop,
    OpCode.OP_NOP33: op_nop,
    OpCode.OP_NOP34: op_nop,
    OpCode.OP_NOP35: op_nop,
    OpCode.OP_NOP36: op_nop,
    OpCode.OP_NOP37: op_nop,
    OpCode.OP_NOP38: op_nop,
    OpCode.OP_NOP39: op_nop,
    OpCode.OP_NOP40: op_nop,
    OpCode.OP_NOP41: op_nop,
    OpCode.OP_NOP42: op_nop,
    OpCode.OP_NOP43: op_nop,
    OpCode.OP_NOP44: op_nop,
    OpCode.OP_NOP45: op_nop,
    OpCode.OP_NOP46: op_nop,
    OpCode.OP_NOP47: op_nop,
    OpCode.OP_NOP48: op_nop,
    OpCode.OP_NOP49: op_nop,
    OpCode.OP_NOP50: op_nop,
    OpCode.OP_NOP51: op_nop,
    OpCode.OP_NOP52: op_nop,
    OpCode.OP_NOP53: op_nop,
    OpCode.OP_NOP54: op_nop,
    OpCode.OP_NOP55: op_nop,
    OpCode.OP_NOP56: op_nop,
    OpCode.OP_NOP57: op_nop,
    OpCode.OP_NOP58: op_nop,
    OpCode.OP_NOP59: op_nop,
    OpCode.OP_NOP60: op_nop,
    OpCode.OP_NOP61: op_nop,
    OpCode.OP_NOP62: op_nop,
    OpCode.OP_NOP63: op_nop,
    OpCode.OP_NOP64: op_nop,
    OpCode.OP_NOP65: op_nop,
    OpCode.OP_NOP66: op_nop,
    OpCode.OP_NOP67: op_nop,
    OpCode.OP_NOP68: op_nop,
    OpCode.OP_NOP69: op_nop,
    OpCode.OP_NOP70: op_nop,
    OpCode.OP_NOP71: op_nop,
    OpCode.OP_NOP72: op_nop,
    OpCode.OP_NOP73: op_nop,
    OpCode.OP_NOP77: op_nop,
    OpCode.OP_IF: op_if,
    OpCode.OP_NOTIF: op_notif,
    OpCode.OP_ELSE: op_else,
    OpCode.OP_ENDIF: op_endif,
    OpCode.OP_VERIFY: op_verify,
    OpCode.OP_RETURN: op_return,
    # Stack opcodes
    OpCode.OP_TOALTSTACK: op_to_alt_stack,
    OpCode.OP_FROMALTSTACK: op_from_alt_stack,
    OpCode.OP_2DROP: op_2drop,
    OpCode.OP_2DUP: op_2dup,
    OpCode.OP_3DUP: op_3dup,
    OpCode.OP_2OVER: op_2over,
    OpCode.OP_2ROT: op_2rot,
    OpCode.OP_2SWAP: op_2swap,
    OpCode.OP_IFDUP: op_ifdup,
    OpCode.OP_DEPTH: op_depth,
    OpCode.OP_DROP: op_drop,
    OpCode.OP_DUP: op_dup,
    OpCode.OP_NIP: op_nip,
    OpCode.OP_OVER: op_over,
    OpCode.OP_PICK: op_pick,
    OpCode.OP_ROLL: op_roll,
    OpCode.OP_ROT: op_rot,
    OpCode.OP_SWAP: op_swap,
    OpCode.OP_TUCK: op_tuck,
    OpCode.OP_SIZE: op_size,
    # Bitwise/arithmetic opcodes
    OpCode.OP_EQUAL: op_equal,
    OpCode.OP_EQUALVERIFY: op_equal_verify,
    OpCode.OP_1ADD: op_1add,
    OpCode.OP_1SUB: op_1sub,
    OpCode.OP_NEGATE: op_negate,
    OpCode.OP_ABS: op_abs,
    OpCode.OP_NOT: op_not,
    OpCode.OP_0NOTEQUAL: op_0notequal,
    OpCode.OP_ADD: op_add,
    OpCode.OP_SUB: op_sub,
    OpCode.OP_MUL: op_mul,
    OpCode.OP_DIV: op_div,
    OpCode.OP_MOD: op_mod,
    OpCode.OP_BOOLAND: op_booland,
    OpCode.OP_BOOLOR: op_boolor,
    OpCode.OP_NUMEQUAL: op_numequal,
    OpCode.OP_NUMEQUALVERIFY: op_numequal_verify,
    OpCode.OP_NUMNOTEQUAL: op_numnotequal,
    OpCode.OP_LESSTHAN: op_lessthan,
    OpCode.OP_GREATERTHAN: op_greaterthan,
    OpCode.OP_LESSTHANOREQUAL: op_lessthanorequal,
    OpCode.OP_GREATERTHANOREQUAL: op_greaterthanorequal,
    OpCode.OP_MIN: op_min,
    OpCode.OP_MAX: op_max,
    OpCode.OP_WITHIN: op_within,
    # Hash opcodes
    OpCode.OP_RIPEMD160: op_ripemd160,
    OpCode.OP_SHA1: op_sha1,
    OpCode.OP_SHA256: op_sha256,
    OpCode.OP_HASH160: op_hash160,
    OpCode.OP_HASH256: op_hash256,
    OpCode.OP_CODESEPARATOR: op_codeseparator,
    OpCode.OP_CHECKSIG: op_checksig,
    OpCode.OP_CHECKSIGVERIFY: op_checksig_verify,
    OpCode.OP_CHECKMULTISIG: op_checkmultisig,
    OpCode.OP_CHECKMULTISIGVERIFY: op_checkmultisig_verify,
    # Splice opcodes
    OpCode.OP_CAT: op_cat,
    OpCode.OP_SPLIT: op_split,
    OpCode.OP_NUM2BIN: op_num2bin,
    OpCode.OP_BIN2NUM: op_bin2num,
    # Bitwise logic opcodes
    OpCode.OP_INVERT: op_invert,
    OpCode.OP_AND: op_and,
    OpCode.OP_OR: op_or,
    OpCode.OP_XOR: op_xor,
    OpCode.OP_LSHIFT: op_lshift,
    OpCode.OP_RSHIFT: op_rshift,
}

