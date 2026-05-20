"""Malleability relaxation tests: v1 enforces, v2 relaxes.

Tests the 7 malleability restrictions controlled by `Spend.is_relaxed()`.
Each restriction has a v2-passes and v1-fails pair to verify the gate
is properly controlled by transaction version.
"""

import pytest

from bsv.constants import NUMBER_BYTE_LENGTH, SIGHASH, OpCode
from bsv.curve import curve
from bsv.hash import hash160
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.spend import Spend
from bsv.script.type import P2PKH, BareMultisig, to_unlock_script_template
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.utils import deserialize_ecdsa_der, encode_pushdata

from .conftest import (
    build_funding_tx,
    validate_spend,
)

# ---------------------------------------------------------------------------
# Helper: build a signed transaction and return it WITHOUT validation
# ---------------------------------------------------------------------------


def _build_tx_no_validate(locking_script, unlock_template, tx_version=1, sighash=SIGHASH.ALL_FORKID):
    """Build and sign a transaction but do NOT validate (caller will test validation)."""
    funding_tx = build_funding_tx(locking_script, satoshis=10_000)
    inp = TransactionInput(
        source_transaction=funding_tx,
        source_output_index=0,
        unlocking_script_template=unlock_template,
        sequence=0xFFFFFFFF,
        sighash=SIGHASH(sighash),
    )
    # Use a standard P2PKH output (not the custom locking script)
    output_script = Script.from_asm("OP_TRUE")
    tx = Transaction(
        [inp],
        [TransactionOutput(locking_script=output_script, satoshis=9_000)],
        version=tx_version,
    )
    tx.sign(bypass=False)
    return tx


# ---------------------------------------------------------------------------
# 1. Non-minimal push encoding (in unlocking script)
# ---------------------------------------------------------------------------


class TestNonMinimalPush:
    """REQUIRE_MINIMAL_PUSH is relaxed for tx version > 1."""

    def _make_nonminimal_unlock(self, priv_key):
        """Unlocking template that pushes data non-minimally before sig+pubkey.

        Uses PUSHDATA1 for a 1-byte value (should be a direct push opcode).
        The locking script checks this value with NUMEQUALVERIFY.
        """

        def sign(tx, input_index):
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash
            signature = priv_key.sign(tx.preimage(input_index))
            public_key = priv_key.public_key().serialize()
            sig_script = encode_pushdata(signature + sighash.to_bytes(1, "little")) + encode_pushdata(public_key)
            # Non-minimal push: PUSHDATA1 0x01 0x05 instead of OP_5 (0x55)
            nonminimal_5 = OpCode.OP_PUSHDATA1 + b"\x01" + b"\x05"
            return Script(sig_script + nonminimal_5)

        return to_unlock_script_template(sign, lambda: 120)

    def _make_lock_with_verify(self, priv_key):
        """Locking script: OP_5 OP_NUMEQUALVERIFY <P2PKH>"""
        from .conftest import p2pkh_lock_with_prefix

        return p2pkh_lock_with_prefix("OP_5 OP_NUMEQUALVERIFY", priv_key)

    def test_v2_allows_nonminimal_push(self, priv_key):
        """v2 tx allows non-minimal push encoding in unlocking script."""
        lock = self._make_lock_with_verify(priv_key)
        unlock = self._make_nonminimal_unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=2)
        assert validate_spend(tx, 0)

    def test_v1_rejects_nonminimal_push(self, priv_key):
        """v1 tx rejects non-minimal push encoding in unlocking script."""
        lock = self._make_lock_with_verify(priv_key)
        unlock = self._make_nonminimal_unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=1)
        with pytest.raises(RuntimeError, match="not minimally-encoded"):
            validate_spend(tx, 0)


# ---------------------------------------------------------------------------
# 2. Push-only unlocking scripts
# ---------------------------------------------------------------------------


class TestPushOnlyUnlocking:
    """REQUIRE_PUSH_ONLY_UNLOCKING_SCRIPTS is relaxed for tx version > 1."""

    def _make_nop_unlock(self, priv_key):
        """Unlocking template that includes OP_NOP (non-push opcode)."""

        def sign(tx, input_index):
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash
            signature = priv_key.sign(tx.preimage(input_index))
            public_key = priv_key.public_key().serialize()
            return Script(
                OpCode.OP_NOP  # non-push opcode
                + encode_pushdata(signature + sighash.to_bytes(1, "little"))
                + encode_pushdata(public_key)
            )

        return to_unlock_script_template(sign, lambda: 110)

    def test_v2_allows_nop_in_unlocking(self, priv_key):
        """v2 tx allows non-push opcodes in unlocking script."""
        lock = P2PKH().lock(priv_key.address())
        unlock = self._make_nop_unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=2)
        assert validate_spend(tx, 0)

    def test_v1_rejects_nop_in_unlocking(self, priv_key):
        """v1 tx rejects non-push opcodes in unlocking script."""
        lock = P2PKH().lock(priv_key.address())
        unlock = self._make_nop_unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=1)
        with pytest.raises(RuntimeError, match="can only contain push operations"):
            validate_spend(tx, 0)


# ---------------------------------------------------------------------------
# 3. Clean stack
# ---------------------------------------------------------------------------


class TestCleanStack:
    """REQUIRE_CLEAN_STACK is relaxed for tx version > 1."""

    def _make_dirty_stack_lock(self, priv_key):
        """P2PKH locking script that pushes an extra TRUE after CHECKSIG.

        After CHECKSIG, stack = [TRUE]. Then OP_TRUE pushes another.
        Stack = [TRUE, TRUE] — 2 items, violates clean stack.
        """
        pkh = hash160(priv_key.public_key().serialize())
        return Script(
            OpCode.OP_DUP
            + OpCode.OP_HASH160
            + encode_pushdata(pkh)
            + OpCode.OP_EQUALVERIFY
            + OpCode.OP_CHECKSIG
            + OpCode.OP_TRUE  # extra item: stack ends with [TRUE, TRUE]
        )

    def test_v2_allows_dirty_stack(self, priv_key):
        """v2 tx allows more than 1 item on stack after execution."""
        lock = self._make_dirty_stack_lock(priv_key)
        unlock = P2PKH().unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=2)
        assert validate_spend(tx, 0)

    def test_v1_rejects_dirty_stack(self, priv_key):
        """v1 tx requires exactly 1 item on stack after execution."""
        lock = self._make_dirty_stack_lock(priv_key)
        unlock = P2PKH().unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=1)
        with pytest.raises(RuntimeError, match="clean stack rule"):
            validate_spend(tx, 0)


# ---------------------------------------------------------------------------
# 4. Low-S signatures
# ---------------------------------------------------------------------------


class TestLowSSignature:
    """REQUIRE_LOW_S_SIGNATURES is relaxed for tx version > 1.

    Note: coincurve (libsecp256k1) rejects high-S signatures at the crypto
    level regardless of malleability settings. So we test the check_signature_encoding
    gate directly via Spend, and verify that v1 rejects with a signature-related
    error while v2 bypasses the early check (though crypto verification still fails).
    """

    def _make_high_s_unlock(self, priv_key):
        """Unlocking template that produces a high-S signature."""

        def sign(tx, input_index):
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash
            preimage = tx.preimage(input_index)
            sig = priv_key.sign(preimage)

            # Extract r, s from DER signature and negate s if low
            r, s = deserialize_ecdsa_der(sig)
            if s <= curve.n // 2:
                s = curve.n - s  # Make it high-S
            # Manually serialize DER without low-S normalization
            r_bytes = r.to_bytes(NUMBER_BYTE_LENGTH, "big").lstrip(b"\x00")
            if r_bytes[0] & 0x80:
                r_bytes = b"\x00" + r_bytes
            s_bytes = s.to_bytes(NUMBER_BYTE_LENGTH, "big").lstrip(b"\x00")
            if s_bytes[0] & 0x80:
                s_bytes = b"\x00" + s_bytes
            sig = (
                bytes([0x30, 2 + len(r_bytes) + 2 + len(s_bytes)])
                + bytes([0x02, len(r_bytes)])
                + r_bytes
                + bytes([0x02, len(s_bytes)])
                + s_bytes
            )

            public_key = priv_key.public_key().serialize()
            return Script(encode_pushdata(sig + sighash.to_bytes(1, "little")) + encode_pushdata(public_key))

        return to_unlock_script_template(sign, lambda: 107)

    def test_v1_rejects_high_s(self, priv_key):
        """v1 tx rejects high-S signatures during encoding check.

        The RuntimeError from low-S check is caught by suppress(Exception)
        in check_signature_encoding, so the error surfaces as 'signature format'.
        """
        lock = P2PKH().lock(priv_key.address())
        unlock = self._make_high_s_unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=1)
        with pytest.raises(RuntimeError, match="signature format is invalid"):
            validate_spend(tx, 0)

    def test_v2_bypasses_low_s_check(self, priv_key):
        """v2 tx bypasses low-S encoding check (fails later at crypto level).

        With is_relaxed()=True, check_signature_encoding passes the high-S sig.
        But coincurve's verify() rejects high-S at the crypto level, so
        CHECKSIG returns FALSE and the script fails.
        """
        lock = P2PKH().lock(priv_key.address())
        unlock = self._make_high_s_unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=2)
        with pytest.raises(RuntimeError, match="truthy after script evaluation"):
            validate_spend(tx, 0)


# ---------------------------------------------------------------------------
# 5. NULLFAIL
# ---------------------------------------------------------------------------


class TestNullFail:
    """NULLFAIL is relaxed for tx version > 1."""

    def _make_nullfail_scripts(self, priv_key):
        """Create scripts where CHECKSIG will fail but signature is non-empty.

        Locking script checks sig against a DIFFERENT pubkey (will fail),
        then uses OP_NOT to invert the FALSE result to TRUE.
        """
        # Use a different key for the locking script so signature verification fails
        other_key = PrivateKey()
        other_pub = other_key.public_key().serialize()
        lock = Script(encode_pushdata(other_pub) + OpCode.OP_CHECKSIG + OpCode.OP_NOT)  # FALSE -> TRUE
        return lock

    def _make_nonempty_sig_unlock(self, priv_key):
        """Unlocking script with a real (but wrong) signature - non-empty."""

        def sign(tx, input_index):
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash
            # Sign with our key (but locking script checks against different key)
            sig = priv_key.sign(tx.preimage(input_index))
            return Script(encode_pushdata(sig + sighash.to_bytes(1, "little")))

        return to_unlock_script_template(sign, lambda: 73)

    def test_v2_allows_nonempty_nullfail(self, priv_key):
        """v2 tx allows non-empty signature on failed CHECKSIG."""
        lock = self._make_nullfail_scripts(priv_key)
        unlock = self._make_nonempty_sig_unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=2)
        assert validate_spend(tx, 0)

    def test_v1_rejects_nonempty_nullfail(self, priv_key):
        """v1 tx rejects non-empty signature when CHECKSIG fails."""
        lock = self._make_nullfail_scripts(priv_key)
        unlock = self._make_nonempty_sig_unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=1)
        with pytest.raises(RuntimeError, match="empty signature"):
            validate_spend(tx, 0)


# ---------------------------------------------------------------------------
# 6. NULLDUMMY (CHECKMULTISIG extra stack item)
# ---------------------------------------------------------------------------


class TestNullDummy:
    """NULLDUMMY is relaxed for tx version > 1."""

    def _make_nonnull_dummy_unlock(self, priv_key, priv_key2):
        """Unlocking template for 2-of-2 multisig with non-zero dummy."""

        def sign(tx, input_index):
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash
            sig1 = priv_key.sign(tx.preimage(input_index))
            sig2 = priv_key2.sign(tx.preimage(input_index))
            return Script(
                OpCode.OP_1  # Non-zero dummy instead of OP_0
                + encode_pushdata(sig1 + sighash.to_bytes(1, "little"))
                + encode_pushdata(sig2 + sighash.to_bytes(1, "little"))
            )

        return to_unlock_script_template(sign, lambda: 180)

    def test_v2_allows_nonnull_dummy(self, priv_key, priv_key2):
        """v2 tx allows non-zero dummy in CHECKMULTISIG."""
        multisig = BareMultisig()
        pubkeys = [
            priv_key.public_key().serialize(),
            priv_key2.public_key().serialize(),
        ]
        lock = multisig.lock(pubkeys, threshold=2)
        unlock = self._make_nonnull_dummy_unlock(priv_key, priv_key2)
        tx = _build_tx_no_validate(lock, unlock, tx_version=2)
        assert validate_spend(tx, 0)

    def test_v1_rejects_nonnull_dummy(self, priv_key, priv_key2):
        """v1 tx rejects non-zero dummy in CHECKMULTISIG."""
        multisig = BareMultisig()
        pubkeys = [
            priv_key.public_key().serialize(),
            priv_key2.public_key().serialize(),
        ]
        lock = multisig.lock(pubkeys, threshold=2)
        unlock = self._make_nonnull_dummy_unlock(priv_key, priv_key2)
        tx = _build_tx_no_validate(lock, unlock, tx_version=1)
        with pytest.raises(RuntimeError, match="extra stack item to be empty"):
            validate_spend(tx, 0)


# ---------------------------------------------------------------------------
# 7. MINIMALIF (OP_IF/OP_NOTIF conditional encoding)
# ---------------------------------------------------------------------------


class TestMinimalIf:
    """MINIMALIF is relaxed for tx version > 1."""

    def _make_nonminimal_if_unlock(self, priv_key):
        """Unlocking template that pushes 0x02 (truthy but non-minimal) for OP_IF."""

        def sign(tx, input_index):
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash
            signature = priv_key.sign(tx.preimage(input_index))
            public_key = priv_key.public_key().serialize()
            sig_script = encode_pushdata(signature + sighash.to_bytes(1, "little")) + encode_pushdata(public_key)
            # Push 0x02 (truthy but not minimal — should be 0x01)
            nonminimal_true = encode_pushdata(b"\x02")
            return Script(sig_script + nonminimal_true)

        return to_unlock_script_template(sign, lambda: 120)

    def _make_if_lock(self, priv_key):
        """Locking: OP_IF <P2PKH> OP_ELSE OP_FALSE OP_ENDIF"""
        pkh = hash160(priv_key.public_key().serialize())
        return Script(
            OpCode.OP_IF
            + OpCode.OP_DUP
            + OpCode.OP_HASH160
            + encode_pushdata(pkh)
            + OpCode.OP_EQUALVERIFY
            + OpCode.OP_CHECKSIG
            + OpCode.OP_ELSE
            + OpCode.OP_FALSE
            + OpCode.OP_ENDIF
        )

    def test_v2_allows_nonminimal_if(self, priv_key):
        """v2 tx allows non-minimal boolean in OP_IF condition."""
        lock = self._make_if_lock(priv_key)
        unlock = self._make_nonminimal_if_unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=2)
        assert validate_spend(tx, 0)

    def test_v1_rejects_nonminimal_if(self, priv_key):
        """v1 tx rejects non-minimal boolean in OP_IF condition."""
        lock = self._make_if_lock(priv_key)
        unlock = self._make_nonminimal_if_unlock(priv_key)
        tx = _build_tx_no_validate(lock, unlock, tx_version=1)
        with pytest.raises(RuntimeError, match="minimally encoded"):
            validate_spend(tx, 0)
