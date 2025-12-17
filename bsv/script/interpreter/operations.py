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
from bsv.utils import unsigned_to_bytes, unsigned_to_varint, deserialize_ecdsa_der, serialize_ecdsa_der

from .errs import Error, ErrorCode
from .number import ScriptNumber
from .op_parser import ParsedOpcode
from .scriptflag import Flag
from .stack import Stack

# Type hint for Thread to avoid circular import
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .thread import Thread

opCondFalse = 0
opCondTrue = 1
opCondSkip = 2


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

def _pop_script_int(t: "Thread") -> tuple[Optional[ScriptNumber], Optional[Error]]:
    """
    Pop a ScriptNumber from the data stack and convert common parsing failures into interpreter errors.
    """
    try:
        return t.dstack.pop_int(), None
    except ValueError as e:
        msg = str(e)
        if "stack is empty" in msg:
            return None, Error(ErrorCode.ERR_INVALID_STACK_OPERATION, msg)
        if "exceeds max length" in msg:
            return None, Error(ErrorCode.ERR_NUMBER_TOO_BIG, msg)
        if "non-minimally encoded" in msg:
            return None, Error(ErrorCode.ERR_MINIMAL_DATA, msg)
        return None, Error(ErrorCode.ERR_INVALID_NUMBER_RANGE, msg)


def check_signature_encoding(sig: bytes, require_low_s: bool = True, require_der: bool = True, require_strict: bool = False) -> Optional[Error]:  # NOSONAR - Complexity (26), requires refactoring
    """
    Check signature encoding with detailed DER validation.

    This implements the same validation as the Go SDK's checkSignatureEncoding.
    """
    # Mirror go-sdk: DER validation is required for low S checking
    require_der = require_der or require_low_s or require_strict

    # Mirror go-sdk: only enforce requirements when any related flags are enabled.
    if not require_der:
        return None

    # Basic length checks are performed when validation is required (Go SDK behavior)
    sig_len = len(sig)
    min_sig_len = 8
    max_sig_len = 72

    if sig_len < min_sig_len:
        return Error(ErrorCode.ERR_SIG_TOO_SHORT, f"malformed signature: too short: {sig_len} < {min_sig_len}")
    if sig_len > max_sig_len:
        return Error(ErrorCode.ERR_SIG_TOO_LONG, f"malformed signature: too long: {sig_len} > {max_sig_len}")

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

    # If DER validation is not required, skip all DER checks
    if not require_der:
        pass  # Skip DER validation
    else:
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
        # In DER: rTypeOffset(2), rLenOffset(3), rStart(4). S type begins after R bytes.
        r_start = r_len_offset + 1
        s_type_offset = r_start + r_len
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
    # Low S checking requires valid DER structure, so only check when DER validation passed
    if require_low_s and require_der:
        # Parse S value from the validated DER structure
        # The DER structure has already been validated, so we can extract S
        try:
            # Skip sequence byte, length byte, R type, R length, R data
            pos = 4  # After 0x30, length, 0x02, r_len
            r_len = sig[r_len_offset]
            pos += r_len  # Skip R data

            # Now at S type (0x02)
            if pos + 2 >= len(sig):
                return Error(ErrorCode.ERR_SIG_HIGH_S, "invalid DER structure for S extraction")

            s_len = sig[pos + 1]
            s_start = pos + 2
            s_end = s_start + s_len

            if s_end > len(sig):
                return Error(ErrorCode.ERR_SIG_HIGH_S, "invalid DER structure for S extraction")

            s_bytes = sig[s_start:s_end]
            if len(s_bytes) == 0:
                return Error(ErrorCode.ERR_SIG_HIGH_S, "empty S value")

            # Convert to integer and check if > curve.n // 2
            s_value = int.from_bytes(s_bytes, byteorder='big')
            curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            if s_value > curve_order // 2:
                return Error(ErrorCode.ERR_SIG_HIGH_S, "signature is not canonical due to unnecessarily high S value")
        except (IndexError, ValueError):
            return Error(ErrorCode.ERR_SIG_HIGH_S, "failed to parse S value from DER signature")

    return None

def _deserialize_ecdsa_der_lax(data: bytes) -> tuple[int, int]:
    """
    Lenient DER decoder used when strict signature rules are not enabled.
    This intentionally ignores any trailing garbage after the ASN.1 sequence.
    """
    if len(data) < 2 or data[0] != 0x30:
        raise ValueError("not a DER sequence")
    total_len = int(data[1])
    end = 2 + total_len
    if end > len(data):
        raise ValueError("truncated DER sequence")
    der = data[:end]
    if len(der) < 8 or der[2] != 0x02:
        raise ValueError("bad DER integer")
    r_len = int(der[3])
    r_off = 4
    if r_off + r_len + 2 > len(der):
        raise ValueError("bad DER R length")
    r = int.from_bytes(der[r_off:r_off + r_len], "big", signed=False)
    s_type_off = r_off + r_len
    if der[s_type_off] != 0x02:
        raise ValueError("bad DER S marker")
    s_len = int(der[s_type_off + 1])
    s_off = s_type_off + 2
    if s_off + s_len != len(der):
        raise ValueError("bad DER S length")
    s = int.from_bytes(der[s_off:s_off + s_len], "big", signed=False)
    return r, s


def remove_signature_from_script(script: List[ParsedOpcode], sig: bytes) -> List[ParsedOpcode]:
    """
    Remove all occurrences of the signature from the script.

    This is used for sighash generation when not using FORKID.
    """
    # Mirror Bitcoin Core's FindAndDelete behavior as used by go-sdk:
    # signatures are removed only when they appear in the script using the
    # *canonical push opcode* for that data length (push prefix matters).
    if len(sig) == 0:
        return list(script)

    sig_len = len(sig)
    if sig_len <= 75:
        want_opcode = bytes([sig_len])
    elif sig_len <= 0xFF:
        want_opcode = OpCode.OP_PUSHDATA1.value
    elif sig_len <= 0xFFFF:
        want_opcode = OpCode.OP_PUSHDATA2.value
    else:
        want_opcode = OpCode.OP_PUSHDATA4.value

    return [pop for pop in script if not (pop.data == sig and pop.opcode == want_opcode)]


def remove_opcode(script: List[ParsedOpcode], opcode: bytes) -> List[ParsedOpcode]:
    """Remove all occurrences of an opcode (by opcode byte) from the script."""
    return [pop for pop in script if pop.opcode != opcode]


def _serialize_parsed_script(script: List[ParsedOpcode]) -> bytes:
    """Serialize ParsedScript back into raw script bytes (sufficient for sighash scriptCode)."""
    out = bytearray()
    for pop in script:
        opv = pop.opcode[0]
        out += pop.opcode
        if pop.data is None:
            continue
        data_len = len(pop.data)
        if 1 <= opv <= 75:
            # direct push, opcode already encodes length
            out += pop.data
        elif opv == OpCode.OP_PUSHDATA1.value[0]:
            out += bytes([data_len])
            out += pop.data
        elif opv == OpCode.OP_PUSHDATA2.value[0]:
            out += data_len.to_bytes(2, "little")
            out += pop.data
        elif opv == OpCode.OP_PUSHDATA4.value[0]:
            out += data_len.to_bytes(4, "little")
            out += pop.data
        else:
            # Defensive: if parser ever attaches data to non-push ops, just append data.
            out += pop.data
    return bytes(out)

def _sighash_from_int(v: int) -> SIGHASH:
    """
    Convert an arbitrary sighash int into a `SIGHASH` enum value.
    The upstream `SIGHASH` Enum only defines some combinations; for others we create a pseudo-member.
    """
    try:
        return SIGHASH(v)
    except Exception:
        obj = int.__new__(SIGHASH, v)
        obj._name_ = f"SIGHASH_{hex(v)}"
        obj._value_ = v
        return obj


def _check_hash_type_encoding(t: "Thread", shf_val: int) -> Optional[Error]:
    """
    Port of go-sdk thread.checkHashTypeEncoding.
    Only enforced under VERIFY_STRICT_ENCODING.
    """
    if not t.flags.has_flag(Flag.VERIFY_STRICT_ENCODING):
        return None

    sig_hash_type = shf_val & ~int(SIGHASH.ANYONECANPAY)

    if t.flags.has_flag(Flag.VERIFY_BIP143_SIGHASH):
        sig_hash_type ^= int(SIGHASH.FORKID)
        if (shf_val & int(SIGHASH.FORKID)) == 0:
            return Error(ErrorCode.ERR_SIG_HASHTYPE, f"hash type does not contain uahf forkID 0x{shf_val:x}")

    # No-FORKID types: ALL/NONE/SINGLE
    if (sig_hash_type & int(SIGHASH.FORKID)) == 0:
        if sig_hash_type < int(SIGHASH.ALL) or sig_hash_type > int(SIGHASH.SINGLE):
            return Error(ErrorCode.ERR_SIG_HASHTYPE, f"invalid hash type 0x{shf_val:x}")
        return None

    # FORKID types: ALL_FORKID/NONE_FORKID/SINGLE_FORKID
    if sig_hash_type < int(SIGHASH.ALL_FORKID) or sig_hash_type > int(SIGHASH.SINGLE_FORKID):
        return Error(ErrorCode.ERR_SIG_HASHTYPE, f"invalid hash type 0x{shf_val:x}")

    if (not t.flags.has_flag(Flag.ENABLE_SIGHASH_FORK_ID)) and (shf_val & int(SIGHASH.FORKID)):
        return Error(ErrorCode.ERR_ILLEGAL_FORKID, "fork id sighash set without flag")
    if t.flags.has_flag(Flag.ENABLE_SIGHASH_FORK_ID) and (shf_val & int(SIGHASH.FORKID)) == 0:
        return Error(ErrorCode.ERR_ILLEGAL_FORKID, "fork id sighash not set with flag")

    return None


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

    return None


# Reserved/invalid opcode handlers (match go-sdk behavior)
def op_reserved(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    return Error(ErrorCode.ERR_RESERVED_OPCODE, f"attempt to execute reserved opcode {pop.name()}")


def op_verconditional(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    # Mirror go-sdk: in after-genesis context, allow it to be skipped if execution is disabled.
    if t.after_genesis and not t.should_exec(pop):
        return None
    return op_reserved(pop, t)


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
    # Match go-sdk: only NOP1..NOP10 (and NOP2/NOP3 aliases) are treated as NOPs.
    # Any higher "NOP" opcodes (e.g. 0xba) are treated as invalid/reserved for interpreter parity.
    opv = pop.opcode[0]
    if opv > OpCode.OP_NOP10.value[0]:
        return Error(ErrorCode.ERR_RESERVED_OPCODE, f"attempt to execute reserved opcode {pop.name()}")

    # NOP2/NOP3 are CHECKLOCKTIMEVERIFY/CHECKSEQUENCEVERIFY under flags (pre-genesis only).
    if pop.opcode == OpCode.OP_NOP2:
        if (not t.flags.has_flag(Flag.VERIFY_CHECK_LOCK_TIME_VERIFY)) or t.after_genesis:
            if t.flags.has_flag(Flag.DISCOURAGE_UPGRADABLE_NOPS):
                return Error(ErrorCode.ERR_DISCOURAGE_UPGRADABLE_NOPS, "script.OpNOP2 reserved for soft-fork upgrades")
            return None
        return op_checklocktimeverify(pop, t)

    if pop.opcode == OpCode.OP_NOP3:
        if (not t.flags.has_flag(Flag.VERIFY_CHECK_SEQUENCE_VERIFY)) or t.after_genesis:
            if t.flags.has_flag(Flag.DISCOURAGE_UPGRADABLE_NOPS):
                return Error(ErrorCode.ERR_DISCOURAGE_UPGRADABLE_NOPS, "script.OpNOP3 reserved for soft-fork upgrades")
            return None
        return op_checksequenceverify(pop, t)

    # OP_NOP itself is always allowed (even with discourage flag).
    if pop.opcode == OpCode.OP_NOP:
        return None

    # Discourage upgradable nops (NOP1..NOP10) when flagged (pre-genesis behavior).
    if t.flags.has_flag(t.flags.DISCOURAGE_UPGRADABLE_NOPS) and pop.opcode != OpCode.OP_NOP:
        return Error(ErrorCode.ERR_DISCOURAGE_UPGRADABLE_NOPS, "script.OpNOP reserved for soft-fork upgrades")

    return None


# Locktime constants (mirrors go-sdk interpreter)
LOCKTIME_THRESHOLD = 500_000_000
SEQUENCE_LOCKTIME_DISABLED = 1 << 31
SEQUENCE_LOCKTIME_IS_SECONDS = 1 << 22
SEQUENCE_LOCKTIME_MASK = 0x0000FFFF
MAX_TXIN_SEQUENCE_NUM = 0xFFFFFFFF


def _verify_lock_time(tx_lock_time: int, threshold: int, lock_time: int) -> Optional[Error]:
    # Match go-sdk verifyLockTime.
    if (tx_lock_time < threshold and lock_time >= threshold) or (tx_lock_time >= threshold and lock_time < threshold):
        return Error(
            ErrorCode.ERR_UNSATISFIED_LOCKTIME,
            f"mismatched locktime types -- tx locktime {tx_lock_time}, stack locktime {lock_time}",
        )
    if lock_time > tx_lock_time:
        return Error(
            ErrorCode.ERR_UNSATISFIED_LOCKTIME,
            f"locktime requirement not satisfied -- locktime is greater than the transaction locktime: {lock_time} > {tx_lock_time}",
        )
    return None


def _peek_script_num_with_len(t: "Thread", max_len: int) -> tuple[Optional[ScriptNumber], Optional[Error]]:
    if t.dstack.depth() < 1:
        return None, Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "stack is empty")
    data = t.dstack.peek_byte_array(0)
    try:
        return ScriptNumber.from_bytes(data, max_len, t.dstack.verify_minimal_data), None
    except ValueError as e:
        msg = str(e)
        if "exceeds max length" in msg:
            return None, Error(ErrorCode.ERR_NUMBER_TOO_BIG, msg)
        if "non-minimally encoded" in msg:
            return None, Error(ErrorCode.ERR_MINIMAL_DATA, msg)
        return None, Error(ErrorCode.ERR_INVALID_NUMBER_RANGE, msg)


def op_checklocktimeverify(_: ParsedOpcode, t: "Thread") -> Optional[Error]:
    # See go-sdk opcodeCheckLockTimeVerify.
    sn, err = _peek_script_num_with_len(t, 5)
    if err:
        return err
    assert sn is not None

    if sn.value < 0:
        return Error(ErrorCode.ERR_NEGATIVE_LOCKTIME, f"negative lock time: {sn.value}")

    if t.tx is None:
        return Error(ErrorCode.ERR_INVALID_PARAMS, "missing transaction")

    err = _verify_lock_time(int(t.tx.locktime), LOCKTIME_THRESHOLD, int(sn.value))
    if err:
        return err

    if t.tx.inputs[t.input_idx].sequence == MAX_TXIN_SEQUENCE_NUM:
        return Error(ErrorCode.ERR_UNSATISFIED_LOCKTIME, "transaction input is finalized")

    return None


def op_checksequenceverify(_: ParsedOpcode, t: "Thread") -> Optional[Error]:
    # See go-sdk opcodeCheckSequenceVerify.
    sn, err = _peek_script_num_with_len(t, 5)
    if err:
        return err
    assert sn is not None

    if sn.value < 0:
        return Error(ErrorCode.ERR_NEGATIVE_LOCKTIME, f"negative sequence: {sn.value}")

    if t.tx is None:
        return Error(ErrorCode.ERR_INVALID_PARAMS, "missing transaction")

    sequence = int(sn.value)

    # Disabled lock-time flag set => NOP.
    if sequence & SEQUENCE_LOCKTIME_DISABLED:
        return None

    if t.tx.version < 2:
        return Error(ErrorCode.ERR_UNSATISFIED_LOCKTIME, f"invalid transaction version: {t.tx.version}")

    tx_seq = int(t.tx.inputs[t.input_idx].sequence)
    if tx_seq & SEQUENCE_LOCKTIME_DISABLED:
        return Error(
            ErrorCode.ERR_UNSATISFIED_LOCKTIME,
            f"transaction sequence has sequence locktime disabled bit set: 0x{tx_seq:x}",
        )

    lock_time_mask = SEQUENCE_LOCKTIME_IS_SECONDS | SEQUENCE_LOCKTIME_MASK
    return _verify_lock_time(tx_seq & lock_time_mask, SEQUENCE_LOCKTIME_IS_SECONDS, sequence & lock_time_mask)


def op_if(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_IF."""
    cond_val = opCondFalse
    # Always process conditionals even when not executing to maintain nesting.
    if t.should_exec(pop):
        if t.is_branch_executing():
            if t.dstack.depth() < 1:
                return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_IF requires at least one item on stack")
            if t.flags.has_flag(t.flags.VERIFY_MINIMAL_IF):
                b = t.dstack.peek_byte_array(0)
                if len(b) > 1:
                    return Error(ErrorCode.ERR_MINIMAL_IF, f"conditionl has data of length {len(b)}")
                if len(b) == 1 and b[0] != 1:
                    return Error(ErrorCode.ERR_MINIMAL_IF, "conditional failed")
            val = t.dstack.pop_byte_array()
            if cast_to_bool(val):
                cond_val = opCondTrue
        else:
            # Nested inside a non-executing branch: mark as skip so ELSE doesn't toggle execution.
            cond_val = opCondSkip
    t.cond_stack.append(cond_val)
    t.else_stack.append(False)
    return None


def op_notif(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NOTIF."""
    cond_val = opCondFalse
    if t.should_exec(pop):
        if t.is_branch_executing():
            if t.dstack.depth() < 1:
                return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_NOTIF requires at least one item on stack")
            if t.flags.has_flag(t.flags.VERIFY_MINIMAL_IF):
                b = t.dstack.peek_byte_array(0)
                if len(b) > 1:
                    return Error(ErrorCode.ERR_MINIMAL_IF, f"conditionl has data of length {len(b)}")
                if len(b) == 1 and b[0] != 1:
                    return Error(ErrorCode.ERR_MINIMAL_IF, "conditional failed")
            val = t.dstack.pop_byte_array()
            if not cast_to_bool(val):
                cond_val = opCondTrue
        else:
            cond_val = opCondSkip
    t.cond_stack.append(cond_val)
    t.else_stack.append(False)
    return None


def op_else(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ELSE."""
    if len(t.cond_stack) == 0:
        return Error(ErrorCode.ERR_UNBALANCED_CONDITIONAL, "OP_ELSE requires preceding OP_IF")
    # Enforce only one ELSE per IF after genesis.
    if t.after_genesis:
        if len(t.else_stack) == 0:
            return Error(ErrorCode.ERR_UNBALANCED_CONDITIONAL, "OP_ELSE requires preceding OP_IF")
        if t.else_stack[-1]:
            return Error(ErrorCode.ERR_UNBALANCED_CONDITIONAL, "OP_ELSE requires preceding OP_IF")
        t.else_stack[-1] = True
    else:
        # Pre-genesis: multiple ELSE toggles are permitted.
        if len(t.else_stack) > 0:
            t.else_stack[-1] = True

    if t.cond_stack[-1] == opCondTrue:
        t.cond_stack[-1] = opCondFalse
    elif t.cond_stack[-1] == opCondFalse:
        t.cond_stack[-1] = opCondTrue
    elif t.cond_stack[-1] == opCondSkip:
        pass
    return None


def op_endif(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ENDIF."""
    if len(t.cond_stack) == 0:
        return Error(ErrorCode.ERR_UNBALANCED_CONDITIONAL, "OP_ENDIF requires preceding OP_IF")
    t.cond_stack.pop()
    if len(t.else_stack) > 0:
        t.else_stack.pop()
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
    # Match go-sdk:
    # - Before genesis: always an error (early return).
    # - After genesis: marks early return; if not inside conditionals, returns success (ERR_OK).
    if not t.after_genesis:
        return Error(ErrorCode.ERR_EARLY_RETURN, "script returned early")

    t.early_return_after_genesis = True
    if len(t.cond_stack) == 0:
        return Error(ErrorCode.ERR_OK, "success")
    return None


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
    n, err = _pop_script_int(t)
    if err:
        return err
    idx = n.value
    if idx < 0 or idx >= t.dstack.depth():
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, f"OP_PICK index {idx} out of range")
    val = t.dstack.peek_byte_array(idx)
    t.dstack.push_byte_array(val)
    return None


def op_roll(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ROLL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_ROLL requires at least two items on stack")
    n, err = _pop_script_int(t)
    if err:
        return err
    idx = n.value
    if idx < 0 or idx >= t.dstack.depth():
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, f"OP_ROLL index {idx} out of range")
    val = t.dstack.nip_n(idx)
    t.dstack.push_byte_array(val)
    return None


def op_rot(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ROT."""
    if t.dstack.depth() < 3:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_ROT requires at least three items on stack")
    # Stack: [... x1 x2 x3] -> [... x2 x3 x1]
    x3 = t.dstack.pop_byte_array()
    x2 = t.dstack.pop_byte_array()
    x1 = t.dstack.pop_byte_array()
    t.dstack.push_byte_array(x2)
    t.dstack.push_byte_array(x3)
    t.dstack.push_byte_array(x1)
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
    # Stack: [... x1 x2] -> [... x2 x1 x2]
    x2 = t.dstack.pop_byte_array()
    x1 = t.dstack.pop_byte_array()
    t.dstack.push_byte_array(x2)
    t.dstack.push_byte_array(x1)
    t.dstack.push_byte_array(x2)
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
    x, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(x.value + 1))
    return None


def op_1sub(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_1SUB."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_1SUB requires at least one item on stack")
    x, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(x.value - 1))
    return None


def op_negate(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NEGATE."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_NEGATE requires at least one item on stack")
    x, err = _pop_script_int(t)
    if err:
        return err
    result = ScriptNumber(-x.value)
    t.dstack.push_int(result)
    return None


def op_abs(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ABS."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_ABS requires at least one item on stack")
    x, err = _pop_script_int(t)
    if err:
        return err
    result = ScriptNumber(abs(x.value))
    t.dstack.push_int(result)
    return None


def op_not(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NOT."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_NOT requires at least one item on stack")
    x, err = _pop_script_int(t)
    if err:
        return err
    result = ScriptNumber(1 if x.value == 0 else 0)
    t.dstack.push_int(result)
    return None


def op_0notequal(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_0NOTEQUAL."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_0NOTEQUAL requires at least one item on stack")
    x, err = _pop_script_int(t)
    if err:
        return err
    result = ScriptNumber(1 if x.value != 0 else 0)
    t.dstack.push_int(result)
    return None


def op_add(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_ADD."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_ADD requires at least two items on stack")
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(v1.value + v0.value))
    return None


def op_sub(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_SUB."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_SUB requires at least two items on stack")
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(v1.value - v0.value))
    return None


def op_mul(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_MUL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_MUL requires at least two items on stack")
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(v1.value * v0.value))
    return None


def op_div(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_DIV."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_DIV requires at least two items on stack")
    v0, err = _pop_script_int(t)  # divisor (top)
    if err:
        return err
    v1, err = _pop_script_int(t)  # dividend
    if err:
        return err
    x1 = v0.value
    x2 = v1.value
    if x1 == 0:
        return Error(ErrorCode.ERR_DIVIDE_BY_ZERO, "OP_DIV cannot divide by zero")
    # Go big.Int.Quo truncates toward zero.
    q = abs(x2) // abs(x1)
    if (x2 < 0) ^ (x1 < 0):
        q = -q
    t.dstack.push_int(ScriptNumber(q))
    return None


def op_mod(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_MOD."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_MOD requires at least two items on stack")
    v0, err = _pop_script_int(t)  # divisor (top)
    if err:
        return err
    v1, err = _pop_script_int(t)  # dividend
    if err:
        return err
    x1 = v0.value
    x2 = v1.value
    if x1 == 0:
        return Error(ErrorCode.ERR_DIVIDE_BY_ZERO, "OP_MOD cannot divide by zero")
    # Go big.Int.Rem has the same sign as the dividend.
    q = abs(x2) // abs(x1)
    if (x2 < 0) ^ (x1 < 0):
        q = -q
    t.dstack.push_int(ScriptNumber(x2 - (q * x1)))
    return None


def op_booland(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_BOOLAND."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_BOOLAND requires at least two items on stack")
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(1 if (v0.value != 0 and v1.value != 0) else 0))
    return None


def op_boolor(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_BOOLOR."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_BOOLOR requires at least two items on stack")
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(1 if (v0.value != 0 or v1.value != 0) else 0))
    return None


def op_numequal(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_NUMEQUAL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_NUMEQUAL requires at least two items on stack")
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(1 if v1.value == v0.value else 0))
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
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(1 if v1.value != v0.value else 0))
    return None


def op_lessthan(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_LESSTHAN."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_LESSTHAN requires at least two items on stack")
    # Stack: [... x1 x2] -> [... (x1 < x2)]
    x2, err = _pop_script_int(t)
    if err:
        return err
    x1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(1 if x1.value < x2.value else 0))
    return None


def op_greaterthan(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_GREATERTHAN."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_GREATERTHAN requires at least two items on stack")
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(1 if v1.value > v0.value else 0))
    return None


def op_lessthanorequal(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_LESSTHANOREQUAL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_LESSTHANOREQUAL requires at least two items on stack")
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(1 if v1.value <= v0.value else 0))
    return None


def op_greaterthanorequal(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_GREATERTHANOREQUAL."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_GREATERTHANOREQUAL requires at least two items on stack")
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(1 if v1.value >= v0.value else 0))
    return None


def op_min(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_MIN."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_MIN requires at least two items on stack")
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(min(v1.value, v0.value)))
    return None


def op_max(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_MAX."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_MAX requires at least two items on stack")
    v0, err = _pop_script_int(t)
    if err:
        return err
    v1, err = _pop_script_int(t)
    if err:
        return err
    t.dstack.push_int(ScriptNumber(max(v1.value, v0.value)))
    return None


def op_within(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_WITHIN."""
    if t.dstack.depth() < 3:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_WITHIN requires at least three items on stack")
    # Stack: [... x min max] -> [... bool]
    max_val, err = _pop_script_int(t)
    if err:
        return err
    min_val, err = _pop_script_int(t)
    if err:
        return err
    x, err = _pop_script_int(t)
    if err:
        return err
    result = ScriptNumber(1 if min_val.value <= x.value < max_val.value else 0)
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

    # Handle empty signature - push false (EVAL_FALSE)
    if len(sig) < 1:
        t.dstack.push_byte_array(encode_bool(False))
        return None

    # Extract and validate sighash (strict rules) and split to DER bytes.
    sighash_flag, sig_bytes, err = _extract_sighash_from_signature(t, sig)
    if err:
        return err

    # Validate signature and pubkey encodings (go order: sighash type -> sig -> pubkey).
    require_der = t.flags.has_flag(t.flags.VERIFY_DER_SIGNATURES) or t.flags.has_flag(t.flags.VERIFY_STRICT_ENCODING)
    require_low_s = t.flags.has_flag(t.flags.VERIFY_LOW_S)
    require_strict = t.flags.has_flag(t.flags.VERIFY_STRICT_ENCODING)

    err = check_signature_encoding(sig_bytes, require_low_s, require_der, require_strict)
    if err:
        return err
    if require_strict:
        err = check_public_key_encoding(pub_key)
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

    shf_val = int(sighash_type)
    err = _check_hash_type_encoding(t, shf_val)
    if err:
        return None, None, err

    sighash_flag = _sighash_from_int(shf_val)
    return sighash_flag, sig_bytes, None

def _compute_signature_hash(t: "Thread", sig: bytes, sighash_flag) -> Optional[bytes]:
    """Compute the signature hash digest (32 bytes) for verification."""
    sub_script = t.sub_script()
    
    # Mirror go-sdk: remove signature and OP_CODESEPARATOR when not using forkid mode.
    if (not t.flags.has_flag(t.flags.ENABLE_SIGHASH_FORK_ID)) or not (int(sighash_flag) & int(SIGHASH.FORKID)):
        sub_script = remove_signature_from_script(sub_script, sig)
        sub_script = remove_opcode(sub_script, OpCode.OP_CODESEPARATOR.value)
    
    try:
        script_bytes = _serialize_parsed_script(sub_script)

        if t.tx is None:
            return None

        shf_val = int(sighash_flag)
        use_bip143 = t.flags.has_flag(Flag.VERIFY_BIP143_SIGHASH) or (shf_val & int(SIGHASH.FORKID)) != 0

        if use_bip143:
            txin = t.tx.inputs[t.input_idx]
            original_locking_script = txin.locking_script
            original_sighash = txin.sighash
            txin.locking_script = Script.from_bytes(script_bytes)
            txin.sighash = _sighash_from_int(shf_val)
            preimage = t.tx.preimage(t.input_idx)
            txin.locking_script = original_locking_script
            txin.sighash = original_sighash
            return hash256(preimage)

        # Legacy (non-BIP143) signature hashing.
        hash_type = shf_val & 0x1F
        anyone_can_pay = (shf_val & int(SIGHASH.ANYONECANPAY)) != 0

        # SIGHASH_SINGLE bug: if input index >= outputs, signature hash is 1.
        if hash_type == int(SIGHASH.SINGLE) and t.input_idx >= len(t.tx.outputs):
            return b"\x01" + (b"\x00" * 31)

        raw = bytearray()
        raw += t.tx.version.to_bytes(4, "little")

        # Inputs
        if anyone_can_pay:
            raw += unsigned_to_varint(1)
            ins = [(t.input_idx, t.tx.inputs[t.input_idx])]
        else:
            raw += unsigned_to_varint(len(t.tx.inputs))
            ins = list(enumerate(t.tx.inputs))

        for i, txin in ins:
            raw += bytes.fromhex(txin.source_txid)[::-1]
            raw += txin.source_output_index.to_bytes(4, "little")
            if i == t.input_idx:
                raw += unsigned_to_varint(len(script_bytes))
                raw += script_bytes
            else:
                raw += b"\x00"

            seq = txin.sequence
            if i != t.input_idx and (hash_type == int(SIGHASH.NONE) or hash_type == int(SIGHASH.SINGLE)):
                seq = 0
            raw += seq.to_bytes(4, "little")

        # Outputs
        if hash_type == int(SIGHASH.NONE):
            raw += unsigned_to_varint(0)
        elif hash_type == int(SIGHASH.SINGLE):
            raw += unsigned_to_varint(t.input_idx + 1)
            # "Null" outputs for indices < input_idx
            null_out = (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") + b"\x00"
            for _ in range(t.input_idx):
                raw += null_out
            raw += t.tx.outputs[t.input_idx].serialize()
        else:
            raw += unsigned_to_varint(len(t.tx.outputs))
            for o in t.tx.outputs:
                raw += o.serialize()

        raw += t.tx.locktime.to_bytes(4, "little")
        raw += shf_val.to_bytes(4, "little")

        return hash256(bytes(raw))
    except Exception:
        return None

def _verify_signature_with_nullfail(t: "Thread", pub_key: bytes, sig_bytes: bytes, sighash: bytes):
    """Verify signature and check null fail condition."""
    try:
        pubkey_obj = PublicKey(pub_key)

        sig_to_verify = sig_bytes
        # When strict DER/LOW_S/STRICTENC rules are NOT enabled, go-sdk uses a more lenient
        # signature parser.  CoinCurve verification is strict DER, so canonicalize any
        # reasonably-parseable DER signature into strict form before verifying.
        if not t.flags.has_any(Flag.VERIFY_DER_SIGNATURES, Flag.VERIFY_LOW_S, Flag.VERIFY_STRICT_ENCODING):
            try:
                r, s = _deserialize_ecdsa_der_lax(sig_bytes)
                sig_to_verify = serialize_ecdsa_der((r, s))
            except Exception:
                sig_to_verify = sig_bytes

        result = pubkey_obj.verify(sig_to_verify, sighash, hasher=lambda m: m)
    except Exception:
        result = False
    
    if not result and len(sig_bytes) > 0 and t.flags.has_flag(t.flags.VERIFY_NULL_FAIL):
        return Error(ErrorCode.ERR_SIG_NULLFAIL, "signature not empty on failed checksig")
    
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
    # Consensus stack handling + (partial) verification semantics aligned to go-sdk.
    #
    # Stack:
    # [... dummy [sig ...] numsigs [pubkey ...] numpubkeys] -> [... bool]
    num_keys, err = _pop_script_int(t)
    if err:
        return err

    num_pubkeys = num_keys.value
    if num_pubkeys < 0 or num_pubkeys > t.cfg.max_pub_keys_per_multisig():
        return Error(ErrorCode.ERR_PUBKEY_COUNT, f"invalid key count: {num_pubkeys}")

    # Count operations (each pubkey counts as an op in go-sdk)
    t.num_ops += num_pubkeys
    if t.num_ops > t.cfg.max_ops():
        return Error(ErrorCode.ERR_TOO_MANY_OPERATIONS, f"exceeded max operation limit of {t.cfg.max_ops()}")

    pubkeys: list[bytes] = []
    for _ in range(num_pubkeys):
        try:
            pubkeys.append(t.dstack.pop_byte_array())
        except Exception:
            return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_CHECKMULTISIG missing pubkey")

    num_sigs, err = _pop_script_int(t)
    if err:
        return err

    num_signatures = num_sigs.value
    if num_signatures < 0 or num_signatures > num_pubkeys:
        return Error(ErrorCode.ERR_SIG_COUNT, f"invalid signature count: {num_signatures}")

    sigs: list[bytes] = []
    for _ in range(num_signatures):
        try:
            sigs.append(t.dstack.pop_byte_array())
        except Exception:
            return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_CHECKMULTISIG missing signature")

    # Pop the historical (buggy) extra dummy element.
    try:
        dummy = t.dstack.pop_byte_array()
    except Exception:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_CHECKMULTISIG missing dummy element")

    if t.flags.has_flag(t.flags.STRICT_MULTISIG) and len(dummy) != 0:
        return Error(ErrorCode.ERR_SIG_NULLDUMMY, f"multisig dummy argument has length {len(dummy)} instead of 0")

    # Build scriptCode (subscript) with all signatures removed, and with CODESEPARATOR removed.
    scr = t.sub_script()
    for rs in sigs:
        scr = remove_signature_from_script(scr, rs)
    scr = remove_opcode(scr, OpCode.OP_CODESEPARATOR.value)

    try:
        script_bytes = _serialize_parsed_script(scr)
    except Exception:
        script_bytes = b""

    def _calc_sighash(flag: SIGHASH) -> Optional[bytes]:
        """
        Return signature hash digest (32 bytes) for this multisig evaluation.
        Mirrors go-sdk CalcInputSignatureHash selection between legacy and BIP143-style.
        """
        if t.tx is None:
            return None
        try:
            shf_val = int(flag)
            use_bip143 = t.flags.has_flag(Flag.VERIFY_BIP143_SIGHASH) or (shf_val & int(SIGHASH.FORKID)) != 0
            if use_bip143:
                txin = t.tx.inputs[t.input_idx]
                original_locking_script = txin.locking_script
                original_sighash = txin.sighash
                txin.locking_script = Script.from_bytes(script_bytes)
                txin.sighash = _sighash_from_int(shf_val)
                preimage = t.tx.preimage(t.input_idx)
                txin.locking_script = original_locking_script
                txin.sighash = original_sighash
                return hash256(preimage)

            hash_type = shf_val & 0x1F
            anyone_can_pay = (shf_val & int(SIGHASH.ANYONECANPAY)) != 0

            if hash_type == int(SIGHASH.SINGLE) and t.input_idx >= len(t.tx.outputs):
                return b"\x01" + (b"\x00" * 31)

            raw = bytearray()
            raw += t.tx.version.to_bytes(4, "little")

            if anyone_can_pay:
                raw += unsigned_to_varint(1)
                ins = [(t.input_idx, t.tx.inputs[t.input_idx])]
            else:
                raw += unsigned_to_varint(len(t.tx.inputs))
                ins = list(enumerate(t.tx.inputs))

            for i, txin in ins:
                raw += bytes.fromhex(txin.source_txid)[::-1]
                raw += txin.source_output_index.to_bytes(4, "little")
                if i == t.input_idx:
                    raw += unsigned_to_varint(len(script_bytes))
                    raw += script_bytes
                else:
                    raw += b"\x00"

                seq = txin.sequence
                if i != t.input_idx and (hash_type == int(SIGHASH.NONE) or hash_type == int(SIGHASH.SINGLE)):
                    seq = 0
                raw += seq.to_bytes(4, "little")

            if hash_type == int(SIGHASH.NONE):
                raw += unsigned_to_varint(0)
            elif hash_type == int(SIGHASH.SINGLE):
                raw += unsigned_to_varint(t.input_idx + 1)
                null_out = (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") + b"\x00"
                for _ in range(t.input_idx):
                    raw += null_out
                raw += t.tx.outputs[t.input_idx].serialize()
            else:
                raw += unsigned_to_varint(len(t.tx.outputs))
                for o in t.tx.outputs:
                    raw += o.serialize()

            raw += t.tx.locktime.to_bytes(4, "little")
            raw += shf_val.to_bytes(4, "little")
            return hash256(bytes(raw))
        except Exception:
            return None

    # Go-sdk semantics:
    # - only check pubkey encoding once the signature is non-empty and has passed its encoding checks
    # - signature encoding is checked before pubkey encoding (observable under NOT + STRICTENC)
    success = True
    remaining_sigs = num_signatures
    sig_idx = 0
    pubkey_idx = -1
    remaining_pubkeys = num_pubkeys + 1

    while remaining_sigs > 0:
        pubkey_idx += 1
        remaining_pubkeys -= 1
        if remaining_sigs > remaining_pubkeys:
            success = False
            break

        raw_sig = sigs[sig_idx]
        pub_key = pubkeys[pubkey_idx]

        if len(raw_sig) == 0:
            # Skip to the next pubkey if signature is empty.
            continue

        # Split the signature into hash type and signature components.
        shf_val = int(raw_sig[-1])
        sig_bytes = raw_sig[:-1]

        err = _check_hash_type_encoding(t, shf_val)
        if err:
            return err
        shf = _sighash_from_int(shf_val)

        # Signature encoding checks (before pubkey checks).
        require_der = t.flags.has_flag(t.flags.VERIFY_DER_SIGNATURES) or t.flags.has_flag(t.flags.VERIFY_STRICT_ENCODING)
        require_low_s = t.flags.has_flag(t.flags.VERIFY_LOW_S)
        require_strict = t.flags.has_flag(t.flags.VERIFY_STRICT_ENCODING)
        err = check_signature_encoding(sig_bytes, require_low_s, require_der, require_strict)
        if err:
            return err

        # Pubkey encoding checks (STRICTENC) only when the signature is being evaluated.
        if require_strict:
            err = check_public_key_encoding(pub_key)
            if err:
                return err

        sighash = _calc_sighash(shf)
        if sighash is None:
            # Mirror go-sdk: push false on sighash failure, not a hard error.
            success = False
            break

        try:
            sig_to_verify = sig_bytes
            if not t.flags.has_any(Flag.VERIFY_DER_SIGNATURES, Flag.VERIFY_LOW_S, Flag.VERIFY_STRICT_ENCODING):
                try:
                    r, s = _deserialize_ecdsa_der_lax(sig_bytes)
                    sig_to_verify = serialize_ecdsa_der((r, s))
                except Exception:
                    sig_to_verify = sig_bytes
            ok = PublicKey(pub_key).verify(sig_to_verify, sighash, hasher=lambda m: m)
        except Exception:
            ok = False

        if ok:
            sig_idx += 1
            remaining_sigs -= 1

    if not success and t.flags.has_flag(t.flags.VERIFY_NULL_FAIL):
        if any(len(s) > 0 for s in sigs):
            return Error(ErrorCode.ERR_SIG_NULLFAIL, "not all signatures empty on failed checkmultisig")

    t.dstack.push_byte_array(encode_bool(success))
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
    # Stack: [... x2 x1] -> [... x2||x1]
    t.dstack.push_byte_array(x2 + x1)
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
    # Match go-sdk opcodeNum2bin:
    # Stack: a n -> x
    n = t.dstack.pop_int()  # target size
    a = t.dstack.pop_byte_array()  # raw bytes representing a number

    if n.value > t.cfg.max_script_element_size():
        return Error(ErrorCode.ERR_NUMBER_TOO_BIG, f"n is larger than the max of {t.cfg.max_script_element_size()}")

    try:
        sn = ScriptNumber.from_bytes(a, max_num_len=len(a), require_minimal=False)
    except Exception as e:
        return Error(ErrorCode.ERR_INVALID_NUMBER_RANGE, str(e))

    b = bytearray(sn.bytes())
    if n.value < len(b):
        return Error(ErrorCode.ERR_NUMBER_TOO_SMALL, "cannot fit it into n sized array")
    if n.value == len(b):
        t.dstack.push_byte_array(bytes(b))
        return None

    signbit = 0x00
    if len(b) > 0:
        signbit = b[-1] & 0x80
        b[-1] &= 0x7F

    while n.value > (len(b) + 1):
        b.append(0x00)

    b.append(signbit)
    t.dstack.push_byte_array(bytes(b))
    return None


def op_bin2num(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_BIN2NUM."""
    if t.dstack.depth() < 1:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_BIN2NUM requires at least one item on stack")
    x = t.dstack.pop_byte_array()
    result = bin2num(x)
    b = minimally_encode(result)
    if len(b) > t.cfg.max_script_number_length():
        return Error(ErrorCode.ERR_NUMBER_TOO_BIG, f"script numbers are limited to {t.cfg.max_script_number_length()} bytes")
    t.dstack.push_byte_array(b)
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
        return Error(ErrorCode.ERR_INVALID_INPUT_LENGTH, "OP_AND requires operands of same size")
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
        return Error(ErrorCode.ERR_INVALID_INPUT_LENGTH, "OP_OR requires operands of same size")
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
        return Error(ErrorCode.ERR_INVALID_INPUT_LENGTH, "OP_XOR requires operands of same size")
    result = bytes([a ^ b for a, b in zip(x1, x2)])
    t.dstack.push_byte_array(result)
    return None


def op_lshift(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_LSHIFT."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_LSHIFT requires at least two items on stack")
    num = t.dstack.pop_int()
    n = num.value
    if n < 0:
        return Error(ErrorCode.ERR_NUMBER_TOO_SMALL, "n less than 0")

    x = t.dstack.pop_byte_array()
    bit_shift = n % 8
    byte_shift = n // 8
    mask = [0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01][bit_shift]
    overflow_mask = (~mask) & 0xFF

    result = bytearray(len(x))
    for idx in range(len(x), 0, -1):
        i = idx - 1
        if byte_shift <= i:
            k = i - byte_shift
            val = (x[i] & mask) << bit_shift
            result[k] |= val & 0xFF
            if k >= 1:
                carry = (x[i] & overflow_mask) >> (8 - bit_shift) if bit_shift != 0 else 0
                result[k - 1] |= carry & 0xFF

    t.dstack.push_byte_array(bytes(result))
    return None


def op_rshift(pop: ParsedOpcode, t: "Thread") -> Optional[Error]:
    """Handle OP_RSHIFT."""
    if t.dstack.depth() < 2:
        return Error(ErrorCode.ERR_INVALID_STACK_OPERATION, "OP_RSHIFT requires at least two items on stack")
    num = t.dstack.pop_int()
    n = num.value
    if n < 0:
        return Error(ErrorCode.ERR_NUMBER_TOO_SMALL, "n less than 0")

    x = t.dstack.pop_byte_array()
    byte_shift = n // 8
    bit_shift = n % 8
    mask = [0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80][bit_shift]
    overflow_mask = (~mask) & 0xFF

    result = bytearray(len(x))
    for i, b in enumerate(x):
        k = i + byte_shift
        if k < len(x):
            val = (b & mask) >> bit_shift if bit_shift != 0 else (b & mask)
            result[k] |= val & 0xFF
        if k + 1 < len(x):
            carry = (b & overflow_mask) << (8 - bit_shift) if bit_shift != 0 else 0
            result[k + 1] |= carry & 0xFF

    t.dstack.push_byte_array(bytes(result))
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
    OpCode.OP_2MUL: op_reserved,
    OpCode.OP_2DIV: op_reserved,
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
    OpCode.OP_RESERVED: op_reserved,
    OpCode.OP_VER: op_reserved,
    OpCode.OP_RESERVED1: op_reserved,
    OpCode.OP_RESERVED2: op_reserved,
    OpCode.OP_VERIF: op_verconditional,
    OpCode.OP_VERNOTIF: op_verconditional,
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

