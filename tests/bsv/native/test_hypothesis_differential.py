"""Hypothesis differential tests: native C path vs Python fallback.

Generates random valid transactions and verifies both paths produce
identical bytes for serialization and preimage computation.  Unlike
test_fuzz_native.py (crash oracle), these tests assert *equivalence*.

Run:
    pytest tests/bsv/native/test_hypothesis_differential.py -x -v
    pytest tests/bsv/native/test_hypothesis_differential.py -x -v --hypothesis-seed=0
"""

import sys

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

_bsv_native = pytest.importorskip("_bsv_native")

from bsv.constants import SIGHASH
from bsv.script.script import Script
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput

diff_settings = settings(
    max_examples=200,
    deadline=5000,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

hex64 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
uint32 = st.integers(min_value=0, max_value=0xFFFFFFFF)
uint64 = st.integers(min_value=0, max_value=2**64 - 1)
script_bytes = st.binary(min_size=0, max_size=1024)

# varint boundary sizes to exercise 1/3/5-byte encoding
varint_boundary_sizes = st.sampled_from([0, 1, 0xFC, 0xFD, 0xFF, 0x100, 0xFFFF])


def script_at_size(size):
    """Generate a script of exactly `size` bytes."""
    return st.just(b"\x00" * size)


varint_boundary_scripts = varint_boundary_sizes.flatmap(script_at_size)


@st.composite
def tx_input_strategy(draw, with_locking_script=False, sighash=None):
    txid = draw(hex64)
    vout = draw(st.integers(min_value=0, max_value=0xFFFFFFFF))
    unlock = draw(script_bytes)
    seq = draw(uint32)
    sh = sighash or SIGHASH.ALL_FORKID

    inp = TransactionInput(
        source_txid=txid,
        source_output_index=vout,
        unlocking_script=Script(unlock),
        sequence=seq,
        sighash=sh,
    )
    if with_locking_script:
        inp.locking_script = Script(draw(script_bytes.filter(lambda b: len(b) > 0)))
        inp.satoshis = draw(st.integers(min_value=0, max_value=2**63 - 1))
    return inp


@st.composite
def tx_output_strategy(draw):
    sats = draw(st.integers(min_value=0, max_value=2**64 - 1))
    script = draw(script_bytes)
    return TransactionOutput(satoshis=sats, locking_script=Script(script))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _toggle_serialize(tx):
    mod = sys.modules[Transaction.__module__]
    orig = mod._USE_NATIVE_TX
    mod._USE_NATIVE_TX = True
    native = tx.serialize()
    mod._USE_NATIVE_TX = False
    python = tx.serialize()
    mod._USE_NATIVE_TX = orig
    return native, python


def _toggle_preimage(tx, idx):
    import bsv.transaction_preimage as tp

    orig = tp._USE_NATIVE
    tp._USE_NATIVE = True
    try:
        native = tx.preimage(idx)
    finally:
        tp._USE_NATIVE = orig
    tp._USE_NATIVE = False
    try:
        python = tx.preimage(idx)
    finally:
        tp._USE_NATIVE = orig
    return native, python


# ---------------------------------------------------------------------------
# Differential: serialize
# ---------------------------------------------------------------------------


class TestSerializeDifferential:
    @diff_settings
    @given(
        version=uint32,
        locktime=uint32,
        inputs=st.lists(tx_input_strategy(), min_size=0, max_size=5),
        outputs=st.lists(tx_output_strategy(), min_size=0, max_size=5),
    )
    def test_random_tx_serialize_equivalence(self, version, locktime, inputs, outputs):
        tx = Transaction(version=version, tx_inputs=inputs, tx_outputs=outputs, locktime=locktime)
        native, python = _toggle_serialize(tx)
        assert native == python

    @diff_settings
    @given(
        version=uint32,
        locktime=uint32,
        n_inputs=st.integers(min_value=0, max_value=3),
        locking_script=varint_boundary_scripts,
        unlocking_script=varint_boundary_scripts,
    )
    def test_varint_boundary_serialize_equivalence(
        self, version, locktime, n_inputs, locking_script, unlocking_script
    ):
        inputs = [
            TransactionInput(
                source_txid="ab" * 32,
                source_output_index=0,
                unlocking_script=Script(unlocking_script),
                sequence=0xFFFFFFFF,
            )
            for _ in range(n_inputs)
        ]
        outputs = [TransactionOutput(satoshis=1000, locking_script=Script(locking_script))]
        tx = Transaction(version=version, tx_inputs=inputs, tx_outputs=outputs, locktime=locktime)
        native, python = _toggle_serialize(tx)
        assert native == python

    @diff_settings
    @given(
        version=st.sampled_from([0, 1, 2, 0x7FFFFFFF, 0xFFFFFFFF]),
        locktime=st.sampled_from([0, 1, 499999999, 500000000, 0xFFFFFFFF]),
    )
    def test_boundary_version_locktime_equivalence(self, version, locktime):
        inp = TransactionInput(
            source_txid="cc" * 32,
            source_output_index=0,
            unlocking_script=Script(b"\x51"),
            sequence=0xFFFFFFFF,
        )
        out = TransactionOutput(satoshis=546, locking_script=Script(b"\x76"))
        tx = Transaction(version=version, tx_inputs=[inp], tx_outputs=[out], locktime=locktime)
        native, python = _toggle_serialize(tx)
        assert native == python


# ---------------------------------------------------------------------------
# Differential: preimage (BIP143)
# ---------------------------------------------------------------------------


BIP143_FLAGS = [
    SIGHASH.ALL_FORKID,
    SIGHASH.NONE_FORKID,
    SIGHASH.SINGLE_FORKID,
    SIGHASH.ALL_FORKID | SIGHASH.ANYONECANPAY,
    SIGHASH.NONE_FORKID | SIGHASH.ANYONECANPAY,
    SIGHASH.SINGLE_FORKID | SIGHASH.ANYONECANPAY,
]

OTDA_FLAGS = [
    SIGHASH.ALL_FORKID | SIGHASH.CHRONICLE,
    SIGHASH.NONE_FORKID | SIGHASH.CHRONICLE,
    SIGHASH.SINGLE_FORKID | SIGHASH.CHRONICLE,
    SIGHASH.ALL_FORKID | SIGHASH.CHRONICLE | SIGHASH.ANYONECANPAY,
    SIGHASH.NONE_FORKID | SIGHASH.CHRONICLE | SIGHASH.ANYONECANPAY,
    SIGHASH.SINGLE_FORKID | SIGHASH.CHRONICLE | SIGHASH.ANYONECANPAY,
]


class TestPreimageBIP143Differential:
    @diff_settings
    @given(
        version=uint32,
        locktime=uint32,
        sighash=st.sampled_from(BIP143_FLAGS),
        locking_script=st.binary(min_size=1, max_size=512),
        n_outputs=st.integers(min_value=1, max_value=4),
    )
    def test_random_bip143_preimage_equivalence(
        self, version, locktime, sighash, locking_script, n_outputs
    ):
        inp = TransactionInput(
            source_txid="dd" * 32,
            source_output_index=0,
            unlocking_script=Script(b""),
            sequence=0xFFFFFFFF,
            sighash=sighash,
        )
        inp.locking_script = Script(locking_script)
        inp.satoshis = 100_000
        p2pkh = bytes.fromhex("76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
        outputs = [
            TransactionOutput(satoshis=1000 * (i + 1), locking_script=Script(p2pkh))
            for i in range(n_outputs)
        ]
        tx = Transaction(version=version, tx_inputs=[inp], tx_outputs=outputs, locktime=locktime)
        native, python = _toggle_preimage(tx, 0)
        assert native == python

    @diff_settings
    @given(
        sighash=st.sampled_from(BIP143_FLAGS),
        n_inputs=st.integers(min_value=1, max_value=4),
        sign_idx=st.data(),
    )
    def test_multi_input_bip143_equivalence(self, sighash, n_inputs, sign_idx):
        idx = sign_idx.draw(st.integers(min_value=0, max_value=n_inputs - 1))
        p2pkh = bytes.fromhex("76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
        inputs = []
        for i in range(n_inputs):
            inp = TransactionInput(
                source_txid=f"{i:02x}" * 32,
                source_output_index=i,
                unlocking_script=Script(b""),
                sequence=0xFFFFFFFF,
                sighash=sighash,
            )
            inp.locking_script = Script(p2pkh)
            inp.satoshis = 50_000 * (i + 1)
            inputs.append(inp)
        # SIGHASH_SINGLE requires outputs[sign_idx] to exist
        n_outputs = max(n_inputs, idx + 1)
        outputs = [
            TransactionOutput(satoshis=10_000 * (i + 1), locking_script=Script(p2pkh))
            for i in range(n_outputs)
        ]
        tx = Transaction(version=1, tx_inputs=inputs, tx_outputs=outputs, locktime=0)
        native, python = _toggle_preimage(tx, idx)
        assert native == python


# ---------------------------------------------------------------------------
# Differential: preimage (OTDA / Chronicle)
# ---------------------------------------------------------------------------


class TestPreimageOTDADifferential:
    @diff_settings
    @given(
        version=uint32,
        locktime=uint32,
        sighash=st.sampled_from(OTDA_FLAGS),
        locking_script=st.binary(min_size=1, max_size=512),
        n_outputs=st.integers(min_value=1, max_value=4),
    )
    def test_random_otda_preimage_equivalence(
        self, version, locktime, sighash, locking_script, n_outputs
    ):
        inp = TransactionInput(
            source_txid="ee" * 32,
            source_output_index=0,
            unlocking_script=Script(b""),
            sequence=0xFFFFFFFF,
            sighash=sighash,
        )
        inp.locking_script = Script(locking_script)
        inp.satoshis = 200_000
        p2pkh = bytes.fromhex("76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
        outputs = [
            TransactionOutput(satoshis=2000 * (i + 1), locking_script=Script(p2pkh))
            for i in range(n_outputs)
        ]
        tx = Transaction(version=version, tx_inputs=[inp], tx_outputs=outputs, locktime=locktime)
        native, python = _toggle_preimage(tx, 0)
        assert native == python

    @diff_settings
    @given(
        sighash=st.sampled_from(OTDA_FLAGS),
        n_inputs=st.integers(min_value=1, max_value=4),
        sign_idx=st.data(),
    )
    def test_multi_input_otda_equivalence(self, sighash, n_inputs, sign_idx):
        idx = sign_idx.draw(st.integers(min_value=0, max_value=n_inputs - 1))
        p2pkh = bytes.fromhex("76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
        inputs = []
        for i in range(n_inputs):
            inp = TransactionInput(
                source_txid=f"{i:02x}" * 32,
                source_output_index=i,
                unlocking_script=Script(b""),
                sequence=0xFFFFFFFF,
                sighash=sighash,
            )
            inp.locking_script = Script(p2pkh)
            inp.satoshis = 50_000 * (i + 1)
            inputs.append(inp)
        # SIGHASH_SINGLE requires outputs[sign_idx] to exist
        n_outputs = max(n_inputs, idx + 1)
        outputs = [
            TransactionOutput(satoshis=10_000 * (i + 1), locking_script=Script(p2pkh))
            for i in range(n_outputs)
        ]
        tx = Transaction(version=1, tx_inputs=inputs, tx_outputs=outputs, locktime=0)
        native, python = _toggle_preimage(tx, idx)
        assert native == python
