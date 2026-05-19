"""Standard opcodes in real signed transactions.

Each test builds a Transaction with a custom locking script exercising
one or more standard opcodes, signs it, validates via Spend.validate(),
and verifies it produces a valid txid.
"""

import pytest

from bsv.constants import SIGHASH, OpCode
from bsv.hash import hash160, hash256, ripemd160, sha1, sha256
from bsv.script.script import Script
from bsv.script.type import P2PKH, BareMultisig
from bsv.utils import encode_pushdata

from .conftest import (
    build_signed_tx,
    custom_unlock,
    p2pkh_lock_with_prefix,
)

# Default: BIP143 v1. A subset also tested with OTDA v2.
SH = SIGHASH.ALL_FORKID
SH_C = SIGHASH.ALL_FORKID_CHRONICLE


# ---------------------------------------------------------------------------
# Helper to build and validate in one line
# ---------------------------------------------------------------------------


def _run(priv_key, prefix_asm, data_asm="", sighash=SH, tx_version=1):
    """Build a tx with locking prefix + P2PKH suffix, validate, return tx."""
    lock = p2pkh_lock_with_prefix(prefix_asm, priv_key)
    data = Script.from_asm(data_asm) if data_asm else None
    unlock = custom_unlock(priv_key, data_prefix_script=data)
    return build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    """OP_0 through OP_16 and OP_1NEGATE in signed transactions."""

    @pytest.mark.parametrize(
        "push_op,expected_op",
        [
            ("OP_1", "OP_1"),
            ("OP_2", "OP_2"),
            ("OP_3", "OP_3"),
            ("OP_4", "OP_4"),
            ("OP_5", "OP_5"),
            ("OP_6", "OP_6"),
            ("OP_7", "OP_7"),
            ("OP_8", "OP_8"),
            ("OP_9", "OP_9"),
            ("OP_10", "OP_10"),
            ("OP_11", "OP_11"),
            ("OP_12", "OP_12"),
            ("OP_13", "OP_13"),
            ("OP_14", "OP_14"),
            ("OP_15", "OP_15"),
            ("OP_16", "OP_16"),
        ],
    )
    def test_push_constants(self, priv_key, push_op, expected_op):
        """Push a constant, verify it equals itself via NUMEQUALVERIFY."""
        _run(priv_key, f"{push_op} {expected_op} OP_NUMEQUALVERIFY")

    def test_op_1negate(self, priv_key):
        _run(priv_key, "OP_1NEGATE OP_1NEGATE OP_NUMEQUALVERIFY")

    def test_op_false_op_true(self, priv_key):
        """OP_FALSE pushes empty, OP_TRUE pushes 1; drop FALSE, verify TRUE."""
        _run(priv_key, "OP_FALSE OP_TRUE OP_VERIFY OP_DROP")


# ---------------------------------------------------------------------------
# Stack operations
# ---------------------------------------------------------------------------


class TestStackOps:
    """Stack manipulation opcodes in signed transactions."""

    def test_op_dup(self, priv_key):
        """DUP duplicates top, EQUALVERIFY checks they match, then P2PKH."""
        _run(priv_key, "OP_DUP OP_EQUALVERIFY", data_asm="OP_5")

    def test_op_drop(self, priv_key):
        """Push extra value, DROP it, then P2PKH works."""
        _run(priv_key, "OP_DROP", data_asm="OP_5")

    def test_op_swap(self, priv_key):
        """Push 3, 5 -> SWAP -> 5, 3. Verify top is 3."""
        _run(priv_key, "OP_SWAP OP_3 OP_NUMEQUALVERIFY OP_DROP", data_asm="OP_3 OP_5")

    def test_op_over(self, priv_key):
        """Push 3, 5. OVER copies 3 to top. Verify 3, drop extras."""
        _run(priv_key, "OP_OVER OP_3 OP_NUMEQUALVERIFY OP_DROP OP_DROP", data_asm="OP_3 OP_5")

    def test_op_rot(self, priv_key):
        """Push 3, 4, 5. ROT -> 4, 5, 3. Verify top is 3."""
        _run(
            priv_key,
            "OP_ROT OP_3 OP_NUMEQUALVERIFY OP_DROP OP_DROP",
            data_asm="OP_3 OP_4 OP_5",
        )

    def test_op_nip(self, priv_key):
        """Push 3, 5. NIP removes second-to-top (3). Verify top is 5."""
        _run(priv_key, "OP_NIP OP_5 OP_NUMEQUALVERIFY", data_asm="OP_3 OP_5")

    def test_op_tuck(self, priv_key):
        """Push 3, 5. TUCK -> 5, 3, 5. Verify top is 5, drop extras."""
        _run(
            priv_key,
            "OP_TUCK OP_5 OP_NUMEQUALVERIFY OP_DROP OP_DROP",
            data_asm="OP_3 OP_5",
        )

    def test_op_2dup(self, priv_key):
        """Push 3, 5. 2DUP -> 3, 5, 3, 5. Drop all but verify."""
        _run(
            priv_key,
            "OP_2DUP OP_5 OP_NUMEQUALVERIFY OP_3 OP_NUMEQUALVERIFY OP_DROP OP_DROP",
            data_asm="OP_3 OP_5",
        )

    def test_op_2drop(self, priv_key):
        """Push 3, 5. 2DROP removes both."""
        _run(priv_key, "OP_2DROP", data_asm="OP_3 OP_5")

    def test_op_depth(self, priv_key):
        """Push one value. Stack has sig, pubkey, value = 3 items. DEPTH=3."""
        _run(priv_key, "OP_DEPTH OP_3 OP_NUMEQUALVERIFY OP_DROP", data_asm="OP_5")

    def test_op_size(self, priv_key):
        """Push 5-byte data. SIZE pushes 5. Verify."""
        lock = p2pkh_lock_with_prefix("OP_SIZE OP_5 OP_NUMEQUALVERIFY OP_DROP", priv_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_toaltstack_fromaltstack(self, priv_key):
        """Push to alt stack, then retrieve."""
        _run(
            priv_key,
            "OP_TOALTSTACK OP_FROMALTSTACK OP_5 OP_NUMEQUALVERIFY",
            data_asm="OP_5",
        )

    def test_op_ifdup(self, priv_key):
        """IFDUP on truthy value duplicates it."""
        _run(priv_key, "OP_IFDUP OP_5 OP_NUMEQUALVERIFY OP_DROP", data_asm="OP_5")

    def test_op_pick(self, priv_key):
        """Push 3, 4, 5. PICK(1) copies second-from-top (4) to top."""
        _run(
            priv_key,
            "OP_PICK OP_4 OP_NUMEQUALVERIFY OP_DROP OP_DROP OP_DROP",
            data_asm="OP_3 OP_4 OP_5 OP_1",
        )

    def test_op_roll(self, priv_key):
        """Push 3, 4, 5. ROLL(1) moves second-from-top (4) to top."""
        _run(
            priv_key,
            "OP_ROLL OP_4 OP_NUMEQUALVERIFY OP_DROP OP_DROP",
            data_asm="OP_3 OP_4 OP_5 OP_1",
        )


# ---------------------------------------------------------------------------
# Arithmetic — Unary
# ---------------------------------------------------------------------------


class TestArithmeticUnary:
    """Unary arithmetic opcodes."""

    @pytest.mark.parametrize(
        "input_val,opcode,expected",
        [
            ("OP_5", "OP_1ADD", "OP_6"),
            ("OP_5", "OP_1SUB", "OP_4"),
            ("OP_5", "OP_NEGATE", "OP_1NEGATE OP_4 OP_SUB"),  # -5
            ("OP_5", "OP_ABS", "OP_5"),
            ("OP_0", "OP_NOT", "OP_1"),
            ("OP_5", "OP_NOT", "OP_0"),
            ("OP_0", "OP_0NOTEQUAL", "OP_0"),
            ("OP_5", "OP_0NOTEQUAL", "OP_1"),
        ],
        ids=["1add", "1sub", "negate", "abs", "not_zero", "not_nonzero", "0ne_zero", "0ne_nonzero"],
    )
    def test_unary(self, priv_key, input_val, opcode, expected):
        _run(
            priv_key,
            f"{opcode} {expected} OP_NUMEQUALVERIFY",
            data_asm=input_val,
        )


# ---------------------------------------------------------------------------
# Arithmetic — Binary
# ---------------------------------------------------------------------------


class TestArithmeticBinary:
    """Binary arithmetic opcodes."""

    @pytest.mark.parametrize(
        "a,b,opcode,expected",
        [
            ("OP_3", "OP_4", "OP_ADD", "OP_7"),
            ("OP_7", "OP_3", "OP_SUB", "OP_4"),
            ("OP_3", "OP_4", "OP_MUL", "OP_12"),
            ("OP_12", "OP_4", "OP_DIV", "OP_3"),
            ("OP_7", "OP_3", "OP_MOD", "OP_1"),
            ("OP_3", "OP_4", "OP_MIN", "OP_3"),
            ("OP_3", "OP_4", "OP_MAX", "OP_4"),
        ],
        ids=["add", "sub", "mul", "div", "mod", "min", "max"],
    )
    def test_binary(self, priv_key, a, b, opcode, expected):
        _run(
            priv_key,
            f"{opcode} {expected} OP_NUMEQUALVERIFY",
            data_asm=f"{a} {b}",
        )

    def test_op_within(self, priv_key):
        """5 WITHIN(3, 7) = TRUE"""
        _run(
            priv_key,
            "OP_WITHIN OP_VERIFY",
            data_asm="OP_5 OP_3 OP_7",
        )


# ---------------------------------------------------------------------------
# Arithmetic — Comparison
# ---------------------------------------------------------------------------


class TestArithmeticComparison:
    """Comparison opcodes."""

    @pytest.mark.parametrize(
        "a,b,opcode,expected",
        [
            ("OP_3", "OP_3", "OP_NUMEQUAL", "OP_1"),
            ("OP_3", "OP_4", "OP_NUMNOTEQUAL", "OP_1"),
            ("OP_3", "OP_4", "OP_LESSTHAN", "OP_1"),
            ("OP_4", "OP_3", "OP_GREATERTHAN", "OP_1"),
            ("OP_3", "OP_3", "OP_LESSTHANOREQUAL", "OP_1"),
            ("OP_3", "OP_3", "OP_GREATERTHANOREQUAL", "OP_1"),
        ],
        ids=["eq", "neq", "lt", "gt", "lte", "gte"],
    )
    def test_comparison(self, priv_key, a, b, opcode, expected):
        _run(
            priv_key,
            f"{opcode} {expected} OP_NUMEQUALVERIFY",
            data_asm=f"{a} {b}",
        )

    def test_op_numequalverify(self, priv_key):
        """NUMEQUALVERIFY consumes both and continues if equal."""
        _run(priv_key, "OP_NUMEQUALVERIFY", data_asm="OP_5 OP_5")

    @pytest.mark.parametrize(
        "a,b,opcode,expected",
        [
            ("OP_1", "OP_1", "OP_BOOLAND", "OP_1"),
            ("OP_1", "OP_0", "OP_BOOLAND", "OP_0"),
            ("OP_1", "OP_0", "OP_BOOLOR", "OP_1"),
            ("OP_0", "OP_0", "OP_BOOLOR", "OP_0"),
        ],
        ids=["and_tt", "and_tf", "or_tf", "or_ff"],
    )
    def test_boolean(self, priv_key, a, b, opcode, expected):
        _run(
            priv_key,
            f"{opcode} {expected} OP_NUMEQUALVERIFY",
            data_asm=f"{a} {b}",
        )


# ---------------------------------------------------------------------------
# Bitwise / Splice
# ---------------------------------------------------------------------------


class TestBitwiseSplice:
    """Bitwise and splice opcodes."""

    def test_op_equal(self, priv_key):
        _run(priv_key, "OP_EQUAL OP_VERIFY", data_asm="OP_5 OP_5")

    def test_op_equalverify(self, priv_key):
        _run(priv_key, "OP_EQUALVERIFY", data_asm="OP_5 OP_5")

    def test_op_and(self, priv_key):
        """0xff AND 0x0f = 0x0f"""
        lock = p2pkh_lock_with_prefix("OP_AND 0f OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(b"\xff") + encode_pushdata(b"\x0f"))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_or(self, priv_key):
        """0xf0 OR 0x0f = 0xff"""
        lock = p2pkh_lock_with_prefix("OP_OR ff OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(b"\xf0") + encode_pushdata(b"\x0f"))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_xor(self, priv_key):
        """0xff XOR 0x0f = 0xf0"""
        lock = p2pkh_lock_with_prefix("OP_XOR f0 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(b"\xff") + encode_pushdata(b"\x0f"))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_invert(self, priv_key):
        """INVERT 0x0f = 0xf0"""
        lock = p2pkh_lock_with_prefix("OP_INVERT f0 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(b"\x0f"))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_cat(self, priv_key):
        """CAT "ab" + "cd" = "abcd" """
        lock = p2pkh_lock_with_prefix("OP_CAT 61626364 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(b"\x61\x62") + encode_pushdata(b"\x63\x64"))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_split(self, priv_key):
        """SPLIT "abcd" at 2 -> "ab", "cd". Verify left part."""
        lock = p2pkh_lock_with_prefix("OP_SPLIT 6364 OP_EQUALVERIFY 6162 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(b"\x61\x62\x63\x64") + Script.from_asm("OP_2").serialize())
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_num2bin(self, priv_key):
        """NUM2BIN: convert 5 to 4-byte representation."""
        lock = p2pkh_lock_with_prefix("OP_NUM2BIN 05000000 OP_EQUALVERIFY", priv_key)
        data = Script.from_asm("OP_5 OP_4")  # value=5, size=4
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_bin2num(self, priv_key):
        """BIN2NUM: convert 4-byte to number."""
        lock = p2pkh_lock_with_prefix("OP_BIN2NUM OP_5 OP_NUMEQUALVERIFY", priv_key)
        data = Script(encode_pushdata(b"\x05\x00\x00\x00"))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)


# ---------------------------------------------------------------------------
# Crypto / Hash opcodes
# ---------------------------------------------------------------------------


class TestCryptoOps:
    """Hash and signature opcodes."""

    def test_op_ripemd160(self, priv_key):
        """RIPEMD160 of known data matches expected hash."""
        data_bytes = b"hello"
        expected = ripemd160(data_bytes)
        lock = p2pkh_lock_with_prefix(f"OP_RIPEMD160 {expected.hex()} OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(data_bytes))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_sha1(self, priv_key):
        data_bytes = b"hello"
        expected = sha1(data_bytes)
        lock = p2pkh_lock_with_prefix(f"OP_SHA1 {expected.hex()} OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(data_bytes))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_sha256(self, priv_key):
        data_bytes = b"hello"
        expected = sha256(data_bytes)
        lock = p2pkh_lock_with_prefix(f"OP_SHA256 {expected.hex()} OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(data_bytes))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_hash160(self, priv_key):
        data_bytes = b"hello"
        expected = hash160(data_bytes)
        lock = p2pkh_lock_with_prefix(f"OP_HASH160 {expected.hex()} OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(data_bytes))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_hash256(self, priv_key):
        data_bytes = b"hello"
        expected = hash256(data_bytes)
        lock = p2pkh_lock_with_prefix(f"OP_HASH256 {expected.hex()} OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(data_bytes))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_checksigverify(self, priv_key):
        """OP_CHECKSIGVERIFY: like CHECKSIG but consumes result, continues if valid."""
        pkh = hash160(priv_key.public_key().serialize())
        lock = Script(
            OpCode.OP_DUP
            + OpCode.OP_HASH160
            + encode_pushdata(pkh)
            + OpCode.OP_EQUALVERIFY
            + OpCode.OP_CHECKSIGVERIFY
            # Need something truthy on stack after CHECKSIGVERIFY
            + OpCode.OP_TRUE
        )
        unlock = custom_unlock(priv_key)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_checkmultisig(self, priv_key, priv_key2, priv_key3):
        """Standard 2-of-3 CHECKMULTISIG in a signed transaction."""
        multisig = BareMultisig()
        pubkeys = [
            priv_key.public_key().serialize(),
            priv_key2.public_key().serialize(),
            priv_key3.public_key().serialize(),
        ]
        lock = multisig.lock(pubkeys, threshold=2)
        unlock = multisig.unlock([priv_key, priv_key2])
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_checkmultisigverify(self, priv_key, priv_key2, priv_key3):
        """CHECKMULTISIGVERIFY: like CHECKMULTISIG but consumes result."""
        from bsv.utils import encode_int

        pubkeys = [
            priv_key.public_key().serialize(),
            priv_key2.public_key().serialize(),
            priv_key3.public_key().serialize(),
        ]
        lock = Script(
            encode_int(2)
            + encode_pushdata(pubkeys[0])
            + encode_pushdata(pubkeys[1])
            + encode_pushdata(pubkeys[2])
            + encode_int(3)
            + OpCode.OP_CHECKMULTISIGVERIFY
            + OpCode.OP_TRUE
        )
        unlock = BareMultisig().unlock([priv_key, priv_key2])
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)

    def test_op_codeseparator(self, priv_key):
        """OP_CODESEPARATOR before CHECKSIG changes subscript for sig hash."""
        pkh = hash160(priv_key.public_key().serialize())
        lock = Script(
            OpCode.OP_CODESEPARATOR
            + OpCode.OP_DUP
            + OpCode.OP_HASH160
            + encode_pushdata(pkh)
            + OpCode.OP_EQUALVERIFY
            + OpCode.OP_CHECKSIG
        )
        unlock = custom_unlock(priv_key)
        build_signed_tx(lock, unlock, sighash=SH, tx_version=1)


# ---------------------------------------------------------------------------
# Flow control
# ---------------------------------------------------------------------------


class TestFlowControl:
    """Flow control opcodes."""

    def test_op_if_true(self, priv_key):
        """OP_IF with TRUE takes the true branch."""
        _run(priv_key, "OP_IF OP_5 OP_ELSE OP_6 OP_ENDIF OP_5 OP_NUMEQUALVERIFY", data_asm="OP_TRUE")

    def test_op_if_false(self, priv_key):
        """OP_IF with FALSE takes the else branch."""
        _run(priv_key, "OP_IF OP_5 OP_ELSE OP_6 OP_ENDIF OP_6 OP_NUMEQUALVERIFY", data_asm="OP_FALSE")

    def test_op_notif_true(self, priv_key):
        """OP_NOTIF with FALSE takes the true branch."""
        _run(priv_key, "OP_NOTIF OP_5 OP_ELSE OP_6 OP_ENDIF OP_5 OP_NUMEQUALVERIFY", data_asm="OP_FALSE")

    def test_op_verify(self, priv_key):
        """OP_VERIFY consumes truthy value and continues."""
        _run(priv_key, "OP_VERIFY", data_asm="OP_TRUE")

    def test_op_nop(self, priv_key):
        """OP_NOP is a no-op, doesn't affect execution."""
        _run(priv_key, "OP_NOP")

    @pytest.mark.parametrize(
        "nop",
        ["OP_NOP1", "OP_NOP9", "OP_NOP10"],
        ids=["nop1", "nop9", "nop10"],
    )
    def test_remaining_nops(self, priv_key, nop):
        """OP_NOP1, NOP9, NOP10 are still no-ops after Chronicle."""
        _run(priv_key, nop)

    def test_op_return_data_script(self, priv_key):
        """OP_FALSE OP_RETURN creates unspendable data output (construction only)."""
        from bsv.script.type import OpReturn

        op_return = OpReturn()
        data_script = op_return.lock(["test data", b"\xde\xad"])
        # Can't spend OP_RETURN, just verify we can build a tx with it as an output
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv_key.address())
        unlock = p2pkh.unlock(priv_key)
        from bsv.transaction import Transaction
        from bsv.transaction_input import TransactionInput
        from bsv.transaction_output import TransactionOutput

        from .conftest import build_funding_tx, validate_all_inputs

        funding_tx = build_funding_tx(lock, satoshis=10_000)
        inp = TransactionInput(
            source_transaction=funding_tx,
            source_output_index=0,
            unlocking_script_template=unlock,
            sequence=0xFFFFFFFF,
            sighash=SIGHASH(SH),
        )
        tx = Transaction(
            [inp],
            [
                TransactionOutput(locking_script=lock, satoshis=9000),
                TransactionOutput(locking_script=data_script, satoshis=0),
            ],
            version=1,
        )
        tx.sign(bypass=False)
        validate_all_inputs(tx)
        assert tx.txid()


# ---------------------------------------------------------------------------
# Cross-path: verify same opcodes work with OTDA (Chronicle sighash)
# ---------------------------------------------------------------------------


class TestStandardOpcodesOTDA:
    """Spot-check standard opcodes also work with OTDA/Chronicle sighash."""

    def test_add_otda(self, priv_key):
        _run(priv_key, "OP_ADD OP_7 OP_NUMEQUALVERIFY", "OP_3 OP_4", SH_C, 2)

    def test_hash160_otda(self, priv_key):
        data_bytes = b"hello"
        expected = hash160(data_bytes)
        lock = p2pkh_lock_with_prefix(f"OP_HASH160 {expected.hex()} OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(data_bytes))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH_C, tx_version=2)

    def test_if_else_otda(self, priv_key):
        _run(priv_key, "OP_IF OP_5 OP_ELSE OP_6 OP_ENDIF OP_5 OP_NUMEQUALVERIFY", "OP_TRUE", SH_C, 2)

    def test_cat_otda(self, priv_key):
        lock = p2pkh_lock_with_prefix("OP_CAT 61626364 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(b"\x61\x62") + encode_pushdata(b"\x63\x64"))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        build_signed_tx(lock, unlock, sighash=SH_C, tx_version=2)

    def test_multisig_otda(self, priv_key, priv_key2, priv_key3):
        multisig = BareMultisig()
        pubkeys = [
            priv_key.public_key().serialize(),
            priv_key2.public_key().serialize(),
            priv_key3.public_key().serialize(),
        ]
        lock = multisig.lock(pubkeys, threshold=2)
        unlock = multisig.unlock([priv_key, priv_key2])
        build_signed_tx(lock, unlock, sighash=SH_C, tx_version=2)
