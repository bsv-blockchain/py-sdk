"""F11b — Transaction.verify() shared-hash / context tests.

Covers completion conditions C1-C13 from f11b-transaction-verify-plan.md.
Tests both the native VM and pure-Python paths.
"""

import subprocess
import sys
from unittest.mock import patch

import pytest

from bsv.constants import SIGHASH
from bsv.hash import hash256
from bsv.keys import PrivateKey
from bsv.native import NATIVE_AVAILABLE
from bsv.script.script import Script
from bsv.script.spend import Spend
from bsv.script.type import P2PKH
from bsv.spv import GullibleHeadersClient
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.transaction_preimage import (
    PreparedVerificationContext,
    SignatureHashCache,
    build_verification_context,
    tx_preimage,
    tx_preimage_cached,
)

# Tests that drive the C extension directly (or spy on it) cannot run when the
# extension is absent — BSV_NO_NATIVE=1 or a pure-Python install.
requires_native = pytest.mark.skipif(not NATIVE_AVAILABLE, reason="native extension not available")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_source(priv_key, num_outputs=1, satoshis=100_000):
    """Synthetic source transaction (no inputs) that terminates verify recursion."""
    addr = priv_key.address()
    return Transaction(
        tx_inputs=[],
        tx_outputs=[
            TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=satoshis) for _ in range(num_outputs)
        ],
    )


def _make_spending_tx(priv_key, num_inputs, sighash=SIGHASH.ALL_FORKID, source_tx=None):
    """Build and sign a tx spending num_inputs UTXOs from a single source."""
    if source_tx is None:
        source_tx = _make_source(priv_key, num_inputs)
    addr = priv_key.address()
    total = num_inputs * 100_000
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=source_tx,
                source_output_index=i,
                unlocking_script_template=P2PKH().unlock(priv_key),
                sighash=sighash,
            )
            for i in range(num_inputs)
        ],
        tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=total - 1000)],
    )
    tx.sign()
    return tx


def _make_mixed_sighash_tx(priv_key, sighash_list):
    """Build a tx with different sighash types per input."""
    n = len(sighash_list)
    source_tx = _make_source(priv_key, n)
    addr = priv_key.address()
    outputs = []
    for _ in range(n):
        outputs.append(TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=10_000))

    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=source_tx,
                source_output_index=i,
                unlocking_script_template=P2PKH().unlock(priv_key),
                sighash=sh,
            )
            for i, sh in enumerate(sighash_list)
        ],
        tx_outputs=outputs,
    )
    tx.sign()
    return tx


# ---------------------------------------------------------------------------
# Correctness tests (C6-C9)
# ---------------------------------------------------------------------------


class TestVerifyCorrectness:
    """Verify correctness for various sighash types and input counts."""

    @pytest.mark.asyncio
    async def test_1_input_p2pkh_all_forkid(self):
        """C7: 1-input P2PKH ALL_FORKID."""
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 1)
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is True

    @pytest.mark.asyncio
    async def test_5_input_p2pkh_all_forkid(self):
        """C7: 5-input P2PKH ALL_FORKID."""
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 5)
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is True

    @pytest.mark.asyncio
    async def test_mixed_all_none_single_anyonecanpay(self):
        """C7: ALL/NONE/SINGLE/ANYONECANPAY mixed sighash types."""
        priv_key = PrivateKey()
        sighashes = [
            SIGHASH.ALL_FORKID,
            SIGHASH.NONE_FORKID,
            SIGHASH.SINGLE_FORKID,
            SIGHASH.ALL_ANYONECANPAY_FORKID,
        ]
        tx = _make_mixed_sighash_tx(priv_key, sighashes)
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is True

    @pytest.mark.asyncio
    async def test_single_output_in_range(self):
        """C6: SINGLE with input_index < len(outputs)."""
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 1, sighash=SIGHASH.SINGLE_FORKID)
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is True

    @pytest.mark.asyncio
    async def test_single_output_out_of_range(self):
        """C6: SINGLE with input_index >= len(outputs) → 32-byte zero hash."""
        priv_key = PrivateKey()
        source_tx = _make_source(priv_key, 3)
        addr = priv_key.address()
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=source_tx,
                    source_output_index=i,
                    unlocking_script_template=P2PKH().unlock(priv_key),
                    sighash=SIGHASH.SINGLE_FORKID,
                )
                for i in range(3)
            ],
            tx_outputs=[
                TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=10_000),
            ],
        )
        tx.sign()
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is True

    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(self):
        """C8: Invalid signature must be rejected."""
        priv_key = PrivateKey()
        wrong_key = PrivateKey()
        source_tx = _make_source(priv_key, 1)
        addr = priv_key.address()
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=source_tx,
                    source_output_index=0,
                    unlocking_script_template=P2PKH().unlock(wrong_key),
                )
            ],
            tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=50_000)],
        )
        tx.sign()
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is False


class TestVerifyParity:
    """C9: native and pure-Python produce the same verdict."""

    @pytest.mark.asyncio
    async def test_native_pure_parity_5_input(self):
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 5)
        ct = GullibleHeadersClient()

        result_default = await tx.verify(ct, scripts_only=True)

        with patch("bsv.script.spend._USE_NATIVE_VM", False):
            result_python = await tx.verify(ct, scripts_only=True)

        assert result_default == result_python is True

    @pytest.mark.asyncio
    async def test_native_pure_parity_mixed_sighash(self):
        priv_key = PrivateKey()
        sighashes = [
            SIGHASH.ALL_FORKID,
            SIGHASH.NONE_FORKID,
            SIGHASH.SINGLE_FORKID,
            SIGHASH.ALL_ANYONECANPAY_FORKID,
        ]
        tx = _make_mixed_sighash_tx(priv_key, sighashes)
        ct = GullibleHeadersClient()

        result_default = await tx.verify(ct, scripts_only=True)

        with patch("bsv.script.spend._USE_NATIVE_VM", False):
            result_python = await tx.verify(ct, scripts_only=True)

        assert result_default == result_python is True


# ---------------------------------------------------------------------------
# Legacy compatibility (C10)
# ---------------------------------------------------------------------------


class TestLegacySpend:
    """C10: standalone Spend(otherInputs=...) still works."""

    def test_standalone_spend_with_other_inputs(self):
        priv_key = PrivateKey()
        source_tx = _make_source(priv_key, 2)
        addr = priv_key.address()
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=source_tx,
                    source_output_index=i,
                    unlocking_script_template=P2PKH().unlock(priv_key),
                )
                for i in range(2)
            ],
            tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=100_000)],
        )
        tx.sign()

        source_output_0 = source_tx.outputs[0]
        other_inputs = [tx.inputs[1]]

        result = Spend(
            {
                "sourceTXID": tx.inputs[0].source_txid or source_tx.txid(),
                "sourceOutputIndex": 0,
                "sourceSatoshis": source_output_0.satoshis,
                "lockingScript": source_output_0.locking_script,
                "transactionVersion": tx.version,
                "otherInputs": other_inputs,
                "inputIndex": 0,
                "unlockingScript": tx.inputs[0].unlocking_script,
                "outputs": tx.outputs,
                "inputSequence": tx.inputs[0].sequence,
                "lockTime": tx.locktime,
            }
        ).validate()
        assert result is True

    @pytest.mark.parametrize("use_native", [True, False], ids=["native", "pure"])
    def test_standalone_spend_with_all_inputs_only(self, use_native):
        """allInputs without a verificationContext must digest the full input
        list on both backends. The native path used to ignore it and fall back
        to the (empty) otherInputs, disagreeing with pure Python on the same
        signature."""
        if use_native and not NATIVE_AVAILABLE:
            pytest.skip("native extension not available")

        priv_key = PrivateKey()
        source_tx = _make_source(priv_key, 2)
        addr = priv_key.address()
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=source_tx,
                    source_output_index=i,
                    unlocking_script_template=P2PKH().unlock(priv_key),
                )
                for i in range(2)
            ],
            tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=100_000)],
        )
        tx.sign()

        source_output_0 = source_tx.outputs[0]
        params = {
            "sourceTXID": tx.inputs[0].source_txid or source_tx.txid(),
            "sourceOutputIndex": 0,
            "sourceSatoshis": source_output_0.satoshis,
            "lockingScript": source_output_0.locking_script,
            "transactionVersion": tx.version,
            "otherInputs": [],
            "inputIndex": 0,
            "unlockingScript": tx.inputs[0].unlocking_script,
            "outputs": tx.outputs,
            "inputSequence": tx.inputs[0].sequence,
            "lockTime": tx.locktime,
            "allInputs": tx.inputs,
        }

        with patch("bsv.script.spend._USE_NATIVE_VM", use_native):
            assert Spend(params).validate() is True


# ---------------------------------------------------------------------------
# Context lifetime / mutation (C11)
# ---------------------------------------------------------------------------


class TestContextLifetime:
    """C11: context not reused after verify; stale cache not used after mutation."""

    @pytest.mark.asyncio
    async def test_verify_then_mutate_invalidates(self):
        """First verify passes; mutating output invalidates signatures → second verify fails."""
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 2)
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is True

        tx.outputs[0] = TransactionOutput(locking_script=P2PKH().lock(PrivateKey().address()), satoshis=50_000)
        assert await tx.verify(ct, scripts_only=True) is False

    @pytest.mark.asyncio
    async def test_independent_tx_not_affected(self):
        """A second tx sharing the same source still verifies after the first is
        mutated — proving no context/cache leaks across verify() passes."""
        priv_key = PrivateKey()
        ct = GullibleHeadersClient()

        source_tx = _make_source(priv_key, 4)
        tx1 = _make_spending_tx(priv_key, 2, source_tx=source_tx)
        tx2 = _make_spending_tx(priv_key, 2, source_tx=source_tx)

        assert await tx1.verify(ct, scripts_only=True) is True
        assert await tx2.verify(ct, scripts_only=True) is True

        # Invalidate tx1's signatures; its cached hashes must not be reused for tx2.
        tx1.outputs[0] = TransactionOutput(locking_script=P2PKH().lock(PrivateKey().address()), satoshis=50_000)
        assert await tx1.verify(ct, scripts_only=True) is False
        assert await tx2.verify(ct, scripts_only=True) is True


class TestVerifyOrdering:
    """Scripts are validated before ancestors, so a bad signature costs nothing
    in ancestor-graph work. Verifying every source first would let an attacker
    make a transaction with one bad signature pay for N expensive ancestors."""

    @pytest.mark.asyncio
    async def test_bad_script_skips_ancestor_verification(self):
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 5)
        source_tx = tx.inputs[0].source_transaction

        # A well-formed P2PKH unlock, but signed for a different input index.
        tx.inputs[0].unlocking_script = tx.inputs[1].unlocking_script

        calls = {"n": 0}
        original_verify = source_tx.verify

        async def spy(*a, **kw):
            calls["n"] += 1
            return await original_verify(*a, **kw)

        source_tx.verify = spy
        ct = GullibleHeadersClient()

        assert await tx.verify(ct, scripts_only=True) is False
        assert calls["n"] == 0, f"ancestors must not be verified when a script fails, got {calls['n']} call(s)"

    @pytest.mark.asyncio
    async def test_valid_tx_still_verifies_ancestors(self):
        """The reordering must not skip ancestor verification for a good tx."""
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 3)
        source_tx = tx.inputs[0].source_transaction

        calls = {"n": 0}
        original_verify = source_tx.verify

        async def spy(*a, **kw):
            calls["n"] += 1
            return await original_verify(*a, **kw)

        source_tx.verify = spy
        ct = GullibleHeadersClient()

        assert await tx.verify(ct, scripts_only=True) is True
        assert calls["n"] == 3, f"every input's source must still be verified, got {calls['n']}"

    @pytest.mark.asyncio
    async def test_invalid_ancestor_still_fails(self):
        """A tx whose scripts pass but whose ancestor fails must return False."""
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 2)
        source_tx = tx.inputs[0].source_transaction

        async def always_false(*a, **kw):
            return False

        source_tx.verify = always_false
        ct = GullibleHeadersClient()

        assert await tx.verify(ct, scripts_only=True) is False


# ---------------------------------------------------------------------------
# Complexity assertions (C1-C5)
# ---------------------------------------------------------------------------


class TestComplexityAssertions:
    """Spy/counter tests proving O(N) behavior."""

    @pytest.mark.asyncio
    async def test_c1_shared_hashes_computed_once(self):
        """C1: hash_prevouts/sequence/outputs_all computed once per verify pass.

        verify() recurses into source transactions so build_verification_context
        is called once per tx in the chain.  For the spending tx (5 inputs) it
        must be called exactly once — not 5 times.  We count calls whose inputs
        list has >0 items (source tx has no inputs → 0-input call per recursion).
        """
        priv_key = PrivateKey()
        n = 5
        tx = _make_spending_tx(priv_key, n)
        ct = GullibleHeadersClient()

        spending_ctx_calls = {"count": 0}
        original = build_verification_context

        def spy(inputs, *a, **kw):
            if len(inputs) > 0:
                spending_ctx_calls["count"] += 1
            return original(inputs, *a, **kw)

        with patch("bsv._legacy_transaction.build_verification_context", side_effect=spy):
            await tx.verify(ct, scripts_only=True)

        assert spending_ctx_calls["count"] == 1

    @pytest.mark.asyncio
    async def test_c2_no_other_inputs_filter(self):
        """C2: verify loop passes empty otherInputs, not N-1 filtered lists."""
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 5)
        ct = GullibleHeadersClient()

        original_init = Spend.__init__
        other_inputs_sizes = []
        context_ids = set()
        all_inputs_ids = set()

        def spy_init(self_spend, params):
            other_inputs_sizes.append(len(params.get("otherInputs", [])))
            context_ids.add(id(params.get("verificationContext")))
            all_inputs_ids.add(id(params.get("allInputs")))
            return original_init(self_spend, params)

        with patch.object(Spend, "__init__", spy_init):
            await tx.verify(ct, scripts_only=True)

        assert all(
            s == 0 for s in other_inputs_sizes
        ), f"otherInputs should be empty for all Spend instances, got sizes: {other_inputs_sizes}"
        # Every Spend shares one context and one allInputs sequence — a per-Spend
        # rebuild would show up here as more than one distinct object.
        assert len(context_ids) == 1, f"expected one shared verificationContext, got {len(context_ids)}"
        assert len(all_inputs_ids) == 1, f"expected one shared allInputs, got {len(all_inputs_ids)}"

    @pytest.mark.asyncio
    async def test_c3_output_serialization_once(self):
        """C3: build_verification_context serializes each output exactly once."""
        priv_key = PrivateKey()
        n_inputs = 5
        source_tx = _make_source(priv_key, n_inputs)
        addr = priv_key.address()
        outputs = [TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=n_inputs * 100_000 - 1000)]

        ctx = build_verification_context(
            [
                TransactionInput(
                    source_txid=source_tx.txid(),
                    source_output_index=i,
                    sequence=0xFFFFFFFF,
                    sighash=SIGHASH.ALL_FORKID,
                )
                for i in range(n_inputs)
            ],
            outputs,
        )
        assert len(ctx.serialized_outputs) == len(outputs)
        for i, out in enumerate(outputs):
            assert ctx.serialized_outputs[i] == out.serialize()

    @pytest.mark.asyncio
    async def test_c5_single_hash_cached_per_index(self):
        """C5: SINGLE output hash computed at most once per index in Python path."""
        priv_key = PrivateKey()
        sighashes = [SIGHASH.SINGLE_FORKID] * 3
        tx = _make_mixed_sighash_tx(priv_key, sighashes)
        ctx = build_verification_context(tx.inputs, tx.outputs)

        assert 0 not in ctx.sighash_cache.hash_outputs_single

        inp0 = tx.inputs[0]

        # Count the real hashing calls: an identity check alone would still pass a
        # regression that recomputes the hash and then re-stores an equal value.
        import bsv.transaction_preimage as tp

        real_hash256 = tp.hash256
        calls = {"n": 0}

        def counting_hash256(data):
            calls["n"] += 1
            return real_hash256(data)

        with patch.object(tp, "hash256", counting_hash256):
            tx_preimage_cached(0, inp0, ctx.all_inputs, tx.outputs, ctx.serialized_outputs, 1, 0, ctx.sighash_cache)
            assert 0 in ctx.sighash_cache.hash_outputs_single
            cached_val = ctx.sighash_cache.hash_outputs_single[0]
            after_first = calls["n"]

            tx_preimage_cached(0, inp0, ctx.all_inputs, tx.outputs, ctx.serialized_outputs, 1, 0, ctx.sighash_cache)

        assert ctx.sighash_cache.hash_outputs_single[0] is cached_val
        assert calls["n"] == after_first, f"second call must not hash again (extra calls: {calls['n'] - after_first})"


# ---------------------------------------------------------------------------
# BIP143 SINGLE zero-hash correctness (C6 detailed)
# ---------------------------------------------------------------------------


class TestSingleZeroHash:
    """C6: BIP143 SINGLE with input_index >= len(outputs) produces 32-byte zero."""

    def test_preimage_cached_single_out_of_range_returns_zero_hash(self):
        priv_key = PrivateKey()
        source_tx = _make_source(priv_key, 3)

        fake_inputs = []
        for i in range(3):
            inp = TransactionInput(
                source_txid=source_tx.txid(),
                source_output_index=i,
                sequence=0xFFFFFFFF,
                sighash=SIGHASH.SINGLE_FORKID,
            )
            inp.locking_script = source_tx.outputs[i].locking_script
            inp.satoshis = source_tx.outputs[i].satoshis
            fake_inputs.append(inp)

        all_inputs = tuple(fake_inputs)
        outputs = [TransactionOutput(locking_script=P2PKH().lock(priv_key.address()), satoshis=1000)]
        serialized_outputs = [o.serialize() for o in outputs]
        # Distinct sentinels: a zero-filled cache would make the hashOutputs
        # assertion below pass against any other field of the preimage.
        cache = SignatureHashCache(
            hash_prevouts=b"\x11" * 32,
            hash_sequence=b"\x22" * 32,
            hash_outputs_all=b"\x33" * 32,
        )

        # BIP143 layout: ... | hashOutputs(32) | nLocktime(4) | sighash(4)
        in_range = tx_preimage_cached(0, fake_inputs[0], all_inputs, outputs, serialized_outputs, 1, 0, cache)
        assert in_range[-40:-8] == hash256(serialized_outputs[0])
        assert cache.hash_outputs_single[0] == hash256(serialized_outputs[0])

        out_of_range = tx_preimage_cached(2, fake_inputs[2], all_inputs, outputs, serialized_outputs, 1, 0, cache)
        assert out_of_range[-40:-8] == b"\x00" * 32
        assert 2 not in cache.hash_outputs_single

        # Offsets are right: hashPrevouts keeps its sentinel, hashSequence is
        # zeroed for SINGLE. Without these, a shifted slice could still pass.
        assert out_of_range[4:36] == b"\x11" * 32
        assert out_of_range[36:68] == b"\x00" * 32


# ---------------------------------------------------------------------------
# Benchmark support tests
# ---------------------------------------------------------------------------


class TestVerifyScaling:
    """C13: verify preparation scales linearly with input count."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("n", [1, 10])
    async def test_verify_n_inputs(self, n):
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, n)
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is True


# ---------------------------------------------------------------------------
# OTDA tests
# ---------------------------------------------------------------------------


class TestOTDA:
    """BIP143 + OTDA mixed correctness."""

    @pytest.mark.asyncio
    async def test_all_otda_inputs(self):
        """All inputs using OTDA (FORKID|CHRONICLE) — correctness only."""
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 3, sighash=SIGHASH.ALL_FORKID_CHRONICLE)
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is True

    @pytest.mark.asyncio
    async def test_bip143_and_otda_mixed(self):
        """C7: BIP143 and OTDA mixed in same transaction."""
        priv_key = PrivateKey()
        sighashes = [
            SIGHASH.ALL_FORKID,
            SIGHASH.ALL_FORKID_CHRONICLE,
            SIGHASH.ALL_FORKID,
        ]
        tx = _make_mixed_sighash_tx(priv_key, sighashes)
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is True

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Pre-existing: OTDA SINGLE out-of-range raises during sign, not handled at preimage level")
    async def test_otda_single_bug_digest(self):
        """OTDA SINGLE out-of-range → bug digest 0x01 + 31 zero bytes."""
        priv_key = PrivateKey()
        source_tx = _make_source(priv_key, 3)
        addr = priv_key.address()
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=source_tx,
                    source_output_index=i,
                    unlocking_script_template=P2PKH().unlock(priv_key),
                    sighash=SIGHASH.SINGLE_FORKID_CHRONICLE,
                )
                for i in range(3)
            ],
            tx_outputs=[
                TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=10_000),
            ],
        )
        tx.sign()
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is True


# ---------------------------------------------------------------------------
# Native malformed args / error cleanup
# ---------------------------------------------------------------------------


@requires_native
class TestNativeErrorCleanup:
    """Malformed optional args to native spend_validate."""

    def test_shared_hashes_wrong_type_raises(self):
        """shared_hashes must be bytes, not str."""
        from bsv.native import NATIVE_MODULE

        with pytest.raises(TypeError, match="shared_hashes must be bytes"):
            NATIVE_MODULE.spend_validate(
                [],
                [],
                1,
                "ab" * 32,
                0,
                0,
                0,
                0xFFFFFFFF,
                0,
                [],
                [],
                "not bytes",
            )

    def test_shared_hashes_wrong_length_raises(self):
        """shared_hashes must be exactly 96 bytes."""
        from bsv.native import NATIVE_MODULE

        with pytest.raises(ValueError, match="96 bytes"):
            NATIVE_MODULE.spend_validate(
                [],
                [],
                1,
                "ab" * 32,
                0,
                0,
                0,
                0xFFFFFFFF,
                0,
                [],
                [],
                b"\x00" * 64,
            )


# ---------------------------------------------------------------------------
# Wire round-trip regression (Critical fix)
# ---------------------------------------------------------------------------


class TestWireRoundTrip:
    """Wire-restored transactions must verify correctly.

    TransactionInput.sighash defaults to ALL_FORKID after from_hex(),
    so OTDA routing in _validate_native must not rely on it.
    """

    @pytest.mark.asyncio
    async def test_bip143_only_round_trip(self):
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 3, sighash=SIGHASH.ALL_FORKID)
        source_tx = tx.inputs[0].source_transaction
        raw = tx.hex()

        restored = Transaction.from_hex(raw)
        for inp in restored.inputs:
            inp.source_transaction = source_tx

        ct = GullibleHeadersClient()
        assert await restored.verify(ct, scripts_only=True) is True

    @pytest.mark.asyncio
    async def test_bip143_otda_mixed_round_trip(self):
        """BIP143 + OTDA mixed, restored from wire — must not SIGSEGV."""
        priv_key = PrivateKey()
        sighashes = [
            SIGHASH.ALL_FORKID,
            SIGHASH.ALL_FORKID_CHRONICLE,
            SIGHASH.ALL_FORKID,
        ]
        tx = _make_mixed_sighash_tx(priv_key, sighashes)
        source_tx = tx.inputs[0].source_transaction
        raw = tx.hex()

        restored = Transaction.from_hex(raw)
        for inp in restored.inputs:
            inp.source_transaction = source_tx

        ct = GullibleHeadersClient()
        assert await restored.verify(ct, scripts_only=True) is True

    @pytest.mark.asyncio
    async def test_bip143_otda_mixed_round_trip_pure_python(self):
        priv_key = PrivateKey()
        sighashes = [
            SIGHASH.ALL_FORKID,
            SIGHASH.ALL_FORKID_CHRONICLE,
            SIGHASH.ALL_FORKID,
        ]
        tx = _make_mixed_sighash_tx(priv_key, sighashes)
        source_tx = tx.inputs[0].source_transaction
        raw = tx.hex()

        restored = Transaction.from_hex(raw)
        for inp in restored.inputs:
            inp.source_transaction = source_tx

        ct = GullibleHeadersClient()
        with patch("bsv.script.spend._USE_NATIVE_VM", False):
            assert await restored.verify(ct, scripts_only=True) is True


# ---------------------------------------------------------------------------
# Empty-input source transaction — no context constructed
# ---------------------------------------------------------------------------


class TestEmptyInputsNoContext:
    """Verify that zero-input transactions skip context construction."""

    @pytest.mark.asyncio
    async def test_zero_input_source_skips_context(self):
        priv_key = PrivateKey()
        source_tx = _make_source(priv_key, 1)

        calls = {"count": 0}
        original = build_verification_context

        def spy(inputs, *a, **kw):
            calls["count"] += 1
            return original(inputs, *a, **kw)

        ct = GullibleHeadersClient()
        with patch("bsv._legacy_transaction.build_verification_context", side_effect=spy):
            await source_tx.verify(ct, scripts_only=True)

        assert calls["count"] == 0, "build_verification_context should not be called for zero-input tx"


# ---------------------------------------------------------------------------
# Native lazy-parse verification
# ---------------------------------------------------------------------------


@requires_native
class TestNativeLazyParse:
    """Verify native call args and lazy parse behavior."""

    @pytest.mark.asyncio
    async def test_native_receives_empty_other_and_shared_all_inputs(self):
        """Native spend_validate is called with empty other_inputs and the
        same native_inputs tuple for every Spend."""
        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 3)
        ct = GullibleHeadersClient()

        calls = []
        import _bsv_native

        original_validate = _bsv_native.spend_validate

        def spy(*args):
            calls.append(args)
            return original_validate(*args)

        with patch("bsv.script.spend._bsv_native") as mock_mod:
            mock_mod.spend_validate = spy
            await tx.verify(ct, scripts_only=True)

        assert len(calls) == 3
        for call_args in calls:
            other_inputs = call_args[9]
            assert other_inputs == [], "other_inputs should be empty list"
            shared_hashes = call_args[11]
            assert isinstance(shared_hashes, bytes) and len(shared_hashes) == 96
            all_inputs = call_args[12]
            assert isinstance(all_inputs, tuple)

        assert calls[0][12] is calls[1][12] is calls[2][12], "all_inputs must be same tuple object"
        # C3: the same serialized_outputs list reaches every Spend. If any Spend
        # re-serialized the outputs it would hand C a different list object.
        assert calls[0][10] is calls[1][10] is calls[2][10], "serialized_outputs must be same list object"

    def test_bip143_ignores_garbage_all_inputs(self):
        """BIP143-only Spend succeeds even if all_inputs contains garbage tuples,
        proving C never parses them for BIP143."""
        from bsv.native import NATIVE_MODULE

        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 2)
        ctx = build_verification_context(tx.inputs, tx.outputs)

        garbage_inputs = (("not_hex", 0, b"", 0, 0, 0), ("also_bad", 0, b"", 0, 0, 0))

        source_output = tx.inputs[0].source_transaction.outputs[0]
        unlock_chunks = [(int.from_bytes(c.op, "big"), c.data) for c in tx.inputs[0].unlocking_script.chunks]
        lock_chunks = [(int.from_bytes(c.op, "big"), c.data) for c in source_output.locking_script.chunks]

        result = NATIVE_MODULE.spend_validate(
            unlock_chunks,
            lock_chunks,
            tx.version,
            tx.inputs[0].source_txid or tx.inputs[0].source_transaction.txid(),
            0,
            tx.locktime,
            0,
            tx.inputs[0].sequence,
            source_output.satoshis,
            [],
            ctx.serialized_outputs,
            ctx.shared_hashes,
            garbage_inputs,
        )
        assert result is True

    def test_otda_does_parse_garbage_all_inputs(self):
        """Mirror of the BIP143 test: an OTDA signature MUST reach the lazy parse,
        so the same garbage all_inputs that BIP143 ignores has to be rejected here.
        Together the two tests pin lazy parsing in both directions."""
        from bsv.native import NATIVE_MODULE

        priv_key = PrivateKey()
        tx = _make_spending_tx(priv_key, 2, sighash=SIGHASH.ALL_FORKID_CHRONICLE)
        ctx = build_verification_context(tx.inputs, tx.outputs)

        garbage_inputs = (("not_hex", 0, b"", 0, 0, 0), ("also_bad", 0, b"", 0, 0, 0))

        source_output = tx.inputs[0].source_transaction.outputs[0]
        unlock_chunks = [(int.from_bytes(c.op, "big"), c.data) for c in tx.inputs[0].unlocking_script.chunks]
        lock_chunks = [(int.from_bytes(c.op, "big"), c.data) for c in source_output.locking_script.chunks]

        with pytest.raises(ValueError, match="txid must be 64 hex chars|invalid txid hex in all_inputs"):
            NATIVE_MODULE.spend_validate(
                unlock_chunks,
                lock_chunks,
                tx.version,
                tx.inputs[0].source_txid or tx.inputs[0].source_transaction.txid(),
                0,
                tx.locktime,
                0,
                tx.inputs[0].sequence,
                source_output.satoshis,
                [],
                ctx.serialized_outputs,
                ctx.shared_hashes,
                garbage_inputs,
            )


# ---------------------------------------------------------------------------
# Bounds check — subprocess crash regression
# ---------------------------------------------------------------------------


# (label, extra_args_expr, input_index, expected_match)
# 11-arg = legacy, 12-arg = shared_hashes fast path, 13-arg = prepared path.
# 12-arg over-limit is NOT here: with empty other_inputs it is the legitimate
# standalone-BIP143 fast path; its bound is enforced at OTDA CHECKSIG time
# (see test_subprocess_otda_12arg_over_limit).
_BAD_INDEX_CASES = [
    ("11arg_over", "", 1, "out of range"),
    ("11arg_neg", "", -1, "non-negative"),
    ("12arg_neg", ', b"\\x00" * 96', -1, "non-negative"),
    ("13arg_neg", ', b"\\x00" * 96, (("ab" * 32, 0, b"", 0, 0xFFFFFFFF, 0x41),)', -1, "non-negative"),
    ("13arg_over", ', b"\\x00" * 96, (("ab" * 32, 0, b"", 0, 0xFFFFFFFF, 0x41),)', 1, "out of range"),
]


@requires_native
class TestBoundsCheckSubprocess:
    """Bad input_index must raise ValueError in every arity path, never crash."""

    @pytest.mark.parametrize("label,extra,index,match", _BAD_INDEX_CASES, ids=[c[0] for c in _BAD_INDEX_CASES])
    def test_bad_index_raises_in_process(self, label, extra, index, match):
        from bsv.native import NATIVE_MODULE

        shared = b"\x00" * 96
        all_inputs = (("ab" * 32, 0, b"", 0, 0xFFFFFFFF, 0x41),)
        args = [[], [], 1, "ab" * 32, 0, 0, index, 0xFFFFFFFF, 0, [], []]
        if "12arg" in label:
            args.append(shared)
        elif "13arg" in label:
            args.extend([shared, all_inputs])

        with pytest.raises(ValueError, match=match):
            NATIVE_MODULE.spend_validate(*args)

    def test_all_inputs_wrong_type_raises(self):
        from bsv.native import NATIVE_MODULE

        with pytest.raises(TypeError, match="all_inputs must be"):
            NATIVE_MODULE.spend_validate(
                [],
                [],
                1,
                "ab" * 32,
                0,
                0,
                0,
                0xFFFFFFFF,
                0,
                [],
                [],
                b"\x00" * 96,
                "not a tuple or list",
            )

    @pytest.mark.parametrize("label,extra,index,match", _BAD_INDEX_CASES, ids=[c[0] for c in _BAD_INDEX_CASES])
    def test_subprocess_no_crash_on_bad_index(self, label, extra, index, match):
        """Each arity path must exit cleanly (not SIGSEGV) on bad input_index."""
        code = f"""
import _bsv_native
try:
    _bsv_native.spend_validate(
        [], [], 1, "ab" * 32, 0, 0, {index}, 0xFFFFFFFF, 0,
        [], []{extra},
    )
except ValueError:
    pass
print("OK")
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"Process crashed: rc={result.returncode}, stderr={result.stderr}"
        assert "OK" in result.stdout

    def test_subprocess_otda_12arg_over_limit(self):
        """12-arg fast path + real OTDA signature + out-of-range input_index:
        must raise at OTDA preimage build, not SIGSEGV (reviewer repro)."""
        code = """
import _bsv_native
from bsv.constants import SIGHASH
from bsv.keys import PrivateKey
from bsv.script.type import P2PKH
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput

priv = PrivateKey()
addr = priv.address()
source = Transaction(
    tx_inputs=[],
    tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=100000)],
)
tx = Transaction(
    tx_inputs=[TransactionInput(
        source_transaction=source, source_output_index=0,
        unlocking_script_template=P2PKH().unlock(priv),
        sighash=SIGHASH.ALL_FORKID_CHRONICLE,
    )],
    tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=99000)],
)
tx.sign()
unlock_chunks = [(int.from_bytes(c.op, "big"), c.data) for c in tx.inputs[0].unlocking_script.chunks]
lock_chunks = [(int.from_bytes(c.op, "big"), c.data) for c in source.outputs[0].locking_script.chunks]
try:
    _bsv_native.spend_validate(
        unlock_chunks, lock_chunks, tx.version,
        tx.inputs[0].source_txid or source.txid(), 0,
        tx.locktime, 1, tx.inputs[0].sequence, 100000,
        [], [o.serialize() for o in tx.outputs],
        b"\\x00" * 96,
    )
except (ValueError, RuntimeError) as e:
    assert "out of range" in str(e), str(e)
print("OK")
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Process crashed: rc={result.returncode}, stderr={result.stderr}"
        assert "OK" in result.stdout


# ---------------------------------------------------------------------------
# Native memory-safety regressions (found by C audit)
# ---------------------------------------------------------------------------


@requires_native
class TestNativeMemorySafety:
    """Hostile arguments at the C API boundary must not corrupt memory.

    Not reachable through Transaction.verify() — TransactionOutput.serialize()
    is always >= 9 bytes and the SDK passes real ints — but spend_validate is a
    public symbol, so both cases are guarded in C.
    """

    def test_satoshis_index_callback_rejected(self):
        """A satoshis field with __index__ used to run arbitrary Python mid-parse,
        letting the callback shrink a list whose length C had already cached."""
        from bsv.native import NATIVE_MODULE

        victim = [("ab" * 32, 0, b"", 0, 0xFFFFFFFF, 0x41) for _ in range(4)]

        class Evil:
            def __index__(self):
                victim.clear()
                return 1000

        victim[1] = ("ab" * 32, 0, b"", Evil(), 0xFFFFFFFF, 0x41)

        with pytest.raises(TypeError, match="satoshis must be int"):
            NATIVE_MODULE.spend_validate([], [], 1, "ab" * 32, 0, 0, 0, 0xFFFFFFFF, 0, victim, [])

    @pytest.mark.parametrize("arity", [11, 13])
    def test_otda_single_short_outputs_no_overflow(self, arity):
        """OTDA SIGHASH_SINGLE writes a 9-byte placeholder per output before
        input_index; outputs shorter than that used to under-budget the malloc."""
        code = f"""
import _bsv_native
n = 100000
outputs = [b""] * (n + 1)
extra = []
if {arity} == 13:
    extra = [b"\\x00" * 96, tuple(("ab" * 32, 0, b"", 0, 0xFFFFFFFF, 0x43) for _ in range(n + 1))]
others = [] if {arity} == 13 else [("ab" * 32, 0, b"", 0, 0xFFFFFFFF, 0x43)] * n
try:
    _bsv_native.spend_validate(
        [], [], 1, "ab" * 32, 0, 0, n, 0xFFFFFFFF, 0,
        others, outputs, *extra,
    )
except (ValueError, RuntimeError, TypeError):
    pass
print("OK")
"""
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, f"Process crashed: rc={result.returncode}, stderr={result.stderr[-400:]}"
        assert "OK" in result.stdout


# ---------------------------------------------------------------------------
# Native CHECKMULTISIG SINGLE cache
# ---------------------------------------------------------------------------


class TestNativeCheckmultisigSingleCache:
    """SINGLE output hash cache correctness in native CHECKMULTISIG.

    Two signatures in one Spend hit the same SINGLE index: the second
    signature verifies against the cached hash, so a corrupted cache value
    fails this test.  Cache *existence* (that the second computation is
    skipped) is not observable from Python without C instrumentation; it is
    covered on the pure-Python side by
    TestComplexityAssertions.test_c5_single_hash_cached_per_index.
    """

    @pytest.mark.asyncio
    async def test_checkmultisig_single_verify(self):
        """A 2-of-2 multisig with SINGLE sighash verifies (cache hit on second sig)."""
        from bsv.script.type import BareMultisig

        priv1 = PrivateKey()
        priv2 = PrivateKey()
        source_tx = Transaction(
            tx_inputs=[],
            tx_outputs=[
                TransactionOutput(
                    locking_script=BareMultisig().lock([priv1.public_key().hex(), priv2.public_key().hex()], 2),
                    satoshis=100_000,
                ),
            ],
        )
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=source_tx,
                    source_output_index=0,
                    unlocking_script_template=BareMultisig().unlock([priv1, priv2]),
                    sighash=SIGHASH.SINGLE_FORKID,
                )
            ],
            tx_outputs=[
                TransactionOutput(
                    locking_script=P2PKH().lock(priv1.address()),
                    satoshis=90_000,
                )
            ],
        )
        tx.sign()
        ct = GullibleHeadersClient()
        assert await tx.verify(ct, scripts_only=True) is True
