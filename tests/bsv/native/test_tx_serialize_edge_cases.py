"""
Edge-case equivalence tests for Transaction.serialize() and the signing
preimage path (BIP143 / OTDA) in the C extension.

Covers varint boundaries, large scripts (multi-MB NFT payloads),
satoshi boundary values, None unlocking scripts, input/output count
boundaries, and preimage computation with large outputs/scriptCodes --
everything the two fixed vectors in test_equivalence.py do NOT reach.
"""

import sys

import pytest

_bsv_native = pytest.importorskip("_bsv_native")

from bsv.constants import SIGHASH
from bsv.script.script import Script
from bsv.transaction import Transaction, TransactionInput, TransactionOutput


def _toggle_serialize(tx):
    """Return (native_bytes, python_bytes) for the same Transaction."""
    mod = sys.modules[Transaction.__module__]
    orig = mod._USE_NATIVE_TX

    mod._USE_NATIVE_TX = True
    native = tx.serialize()

    mod._USE_NATIVE_TX = False
    python = tx.serialize()

    mod._USE_NATIVE_TX = orig
    return native, python


_DEFAULT_TXID = "ab" * 32


def _make_input(*, unlocking_script=None, source_txid=_DEFAULT_TXID, vout=0, seq=0xFFFFFFFF):
    return TransactionInput(
        source_txid=source_txid,
        source_output_index=vout,
        unlocking_script=unlocking_script,
        sequence=seq,
    )


def _make_output(satoshis, script_bytes=b""):
    return TransactionOutput(
        satoshis=satoshis,
        locking_script=Script(script_bytes),
    )


# ═══════════════════════════════════════════════════════════════════════
# 1. Empty / minimal transactions
# ═══════════════════════════════════════════════════════════════════════


class TestEmptyAndMinimal:
    def test_zero_inputs_zero_outputs(self):
        tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
        native, python = _toggle_serialize(tx)
        assert native == python

    def test_one_input_zero_outputs(self):
        tx = Transaction(
            version=1,
            tx_inputs=[_make_input()],
            tx_outputs=[],
            locktime=0,
        )
        native, python = _toggle_serialize(tx)
        assert native == python

    def test_zero_inputs_one_output(self):
        tx = Transaction(
            version=1,
            tx_inputs=[],
            tx_outputs=[_make_output(1000, b"\x76\xa9")],
            locktime=0,
        )
        native, python = _toggle_serialize(tx)
        assert native == python


# ═══════════════════════════════════════════════════════════════════════
# 2. None / empty unlocking_script (the if-else branch in serialize())
# ═══════════════════════════════════════════════════════════════════════


class TestUnlockingScriptNone:
    def test_none_unlocking_script(self):
        inp = _make_input(unlocking_script=None)
        assert inp.unlocking_script is None
        tx = Transaction(version=1, tx_inputs=[inp], tx_outputs=[], locktime=0)
        native, python = _toggle_serialize(tx)
        assert native == python

    def test_empty_unlocking_script(self):
        inp = _make_input(unlocking_script=Script(b""))
        tx = Transaction(version=1, tx_inputs=[inp], tx_outputs=[], locktime=0)
        native, python = _toggle_serialize(tx)
        assert native == python

    def test_none_vs_empty_produce_same_bytes(self):
        inp_none = _make_input(unlocking_script=None)
        inp_empty = _make_input(unlocking_script=Script(b""))
        tx_none = Transaction(version=1, tx_inputs=[inp_none], tx_outputs=[], locktime=0)
        tx_empty = Transaction(version=1, tx_inputs=[inp_empty], tx_outputs=[], locktime=0)
        n1, p1 = _toggle_serialize(tx_none)
        n2, p2 = _toggle_serialize(tx_empty)
        assert n1 == n2 == p1 == p2

    def test_mixed_none_and_present(self):
        tx = Transaction(
            version=1,
            tx_inputs=[
                _make_input(unlocking_script=None),
                _make_input(unlocking_script=Script(b"\x00\x51")),
                _make_input(unlocking_script=None),
            ],
            tx_outputs=[],
            locktime=0,
        )
        native, python = _toggle_serialize(tx)
        assert native == python


# ═══════════════════════════════════════════════════════════════════════
# 3. Varint boundaries for SCRIPT LENGTH
#    < 0xFD (1-byte), == 0xFD (3-byte), > 0xFFFF (5-byte)
# ═══════════════════════════════════════════════════════════════════════


class TestVarintScriptLength:
    @pytest.mark.parametrize(
        "size,label",
        [
            (0, "empty"),
            (1, "1-byte"),
            (75, "max-direct-push"),
            (252, "max-1byte-varint"),
            (253, "first-3byte-varint-0xFD"),
            (254, "0xFD+1"),
            (0xFF, "0xFF"),
            (0x100, "0x100"),
            (0xFFFE, "0xFFFF-1"),
            (0xFFFF, "max-3byte-varint"),
            (0x10000, "first-5byte-varint-0x10000"),
        ],
        ids=lambda x: x if isinstance(x, str) else None,
    )
    def test_locking_script_varint_boundary(self, size, label):
        script_bytes = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
        assert len(script_bytes) == size
        tx = Transaction(
            version=1,
            tx_inputs=[],
            tx_outputs=[_make_output(500, script_bytes)],
            locktime=0,
        )
        native, python = _toggle_serialize(tx)
        assert native == python, f"mismatch at script size {size} ({label})"

    @pytest.mark.parametrize(
        "size",
        [252, 253, 0xFFFF, 0x10000],
        ids=["252", "253", "0xFFFF", "0x10000"],
    )
    def test_unlocking_script_varint_boundary(self, size):
        script_bytes = b"\x00" * size
        inp = _make_input(unlocking_script=Script(script_bytes))
        tx = Transaction(
            version=1,
            tx_inputs=[inp],
            tx_outputs=[],
            locktime=0,
        )
        native, python = _toggle_serialize(tx)
        assert native == python, f"mismatch at unlocking script size {size}"


# ═══════════════════════════════════════════════════════════════════════
# 4. Large scripts -- NFT images (multi-MB)
# ═══════════════════════════════════════════════════════════════════════


class TestLargeScripts:
    @pytest.mark.parametrize(
        "megabytes",
        [1, 4, 8, 20],
        ids=["1MB", "4MB", "8MB", "20MB"],
    )
    def test_large_locking_script_nft_image(self, megabytes):
        size = megabytes * 1024 * 1024
        script_bytes = b"\xab" * size
        tx = Transaction(
            version=1,
            tx_inputs=[_make_input(unlocking_script=Script(b"\x51"))],
            tx_outputs=[_make_output(0, script_bytes)],
            locktime=0,
        )
        native, python = _toggle_serialize(tx)
        assert native == python
        assert len(native) > size

    def test_large_unlocking_script(self):
        size = 2 * 1024 * 1024
        script_bytes = b"\xcd" * size
        inp = _make_input(unlocking_script=Script(script_bytes))
        tx = Transaction(
            version=1,
            tx_inputs=[inp],
            tx_outputs=[_make_output(1000)],
            locktime=0,
        )
        native, python = _toggle_serialize(tx)
        assert native == python

    def test_multiple_large_outputs(self):
        outputs = [_make_output(0, b"\xef" * (512 * 1024)) for _ in range(4)]
        tx = Transaction(
            version=1,
            tx_inputs=[_make_input()],
            tx_outputs=outputs,
            locktime=0,
        )
        native, python = _toggle_serialize(tx)
        assert native == python
        assert len(native) > 2 * 1024 * 1024

    def test_roundtrip_large_script(self):
        size = 1 * 1024 * 1024
        script_bytes = bytes(range(256)) * (size // 256)
        tx = Transaction(
            version=1,
            tx_inputs=[_make_input(unlocking_script=Script(b"\x00"))],
            tx_outputs=[_make_output(42, script_bytes)],
            locktime=0,
        )
        native, _ = _toggle_serialize(tx)
        tx2 = Transaction.from_hex(native)
        assert tx2.outputs[0].locking_script.serialize() == script_bytes
        assert tx2.serialize() == native


# ═══════════════════════════════════════════════════════════════════════
# 5. Varint boundaries for INPUT/OUTPUT COUNT
# ═══════════════════════════════════════════════════════════════════════


class TestVarintInputOutputCount:
    @pytest.mark.parametrize(
        "count",
        [1, 252, 253, 300],
        ids=["1", "252-max1byte", "253-first3byte", "300"],
    )
    def test_input_count_boundary(self, count):
        inputs = [_make_input() for _ in range(count)]
        tx = Transaction(version=1, tx_inputs=inputs, tx_outputs=[], locktime=0)
        native, python = _toggle_serialize(tx)
        assert native == python

    @pytest.mark.parametrize(
        "count",
        [1, 252, 253, 300],
        ids=["1", "252-max1byte", "253-first3byte", "300"],
    )
    def test_output_count_boundary(self, count):
        outputs = [_make_output(i, b"\x76") for i in range(count)]
        tx = Transaction(version=1, tx_inputs=[], tx_outputs=outputs, locktime=0)
        native, python = _toggle_serialize(tx)
        assert native == python


# ═══════════════════════════════════════════════════════════════════════
# 6. Satoshi boundary values
# ═══════════════════════════════════════════════════════════════════════


class TestSatoshiBoundaries:
    @pytest.mark.parametrize(
        "satoshis,label",
        [
            (0, "zero"),
            (1, "dust"),
            (0xFF, "1byte-max"),
            (0xFFFF, "2byte-max"),
            (0xFFFFFF, "3byte-max"),
            (0xFFFFFFFF, "uint32-max"),
            (0xFFFFFFFFFF, "5byte-max"),
            (21_000_000 * 100_000_000, "max-supply"),
            (0xFFFFFFFFFFFFFFFF, "uint64-max"),
        ],
        ids=lambda x: x if isinstance(x, str) else None,
    )
    def test_satoshi_value(self, satoshis, label):
        tx = Transaction(
            version=1,
            tx_inputs=[],
            tx_outputs=[_make_output(satoshis, b"\x76\xa9")],
            locktime=0,
        )
        native, python = _toggle_serialize(tx)
        assert native == python, f"mismatch at satoshis={satoshis} ({label})"


# ═══════════════════════════════════════════════════════════════════════
# 7. Version / locktime edge values
# ═══════════════════════════════════════════════════════════════════════


class TestVersionAndLocktime:
    @pytest.mark.parametrize("version", [0, 1, 2, 0xFF, 0xFFFF, 0xFFFFFFFF])
    def test_version_values(self, version):
        tx = Transaction(version=version, tx_inputs=[], tx_outputs=[], locktime=0)
        native, python = _toggle_serialize(tx)
        assert native == python

    @pytest.mark.parametrize(
        "locktime",
        [0, 1, 499_999_999, 500_000_000, 0xFFFFFFFE, 0xFFFFFFFF],
        ids=["zero", "one", "max-block-height", "min-timestamp", "max-1", "max-uint32"],
    )
    def test_locktime_values(self, locktime):
        tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=locktime)
        native, python = _toggle_serialize(tx)
        assert native == python


# ═══════════════════════════════════════════════════════════════════════
# 8. Input field edge values
# ═══════════════════════════════════════════════════════════════════════


class TestInputFieldEdges:
    def test_source_output_index_max(self):
        inp = _make_input(vout=0xFFFFFFFF)
        tx = Transaction(version=1, tx_inputs=[inp], tx_outputs=[], locktime=0)
        native, python = _toggle_serialize(tx)
        assert native == python

    def test_sequence_zero(self):
        inp = _make_input(seq=0)
        tx = Transaction(version=1, tx_inputs=[inp], tx_outputs=[], locktime=0)
        native, python = _toggle_serialize(tx)
        assert native == python

    def test_varied_source_txids(self):
        txids = [
            "00" * 32,
            "ff" * 32,
            "01" + "00" * 31,
            "00" * 31 + "01",
        ]
        inputs = [_make_input(source_txid=txid) for txid in txids]
        tx = Transaction(version=1, tx_inputs=inputs, tx_outputs=[], locktime=0)
        native, python = _toggle_serialize(tx)
        assert native == python


# ═══════════════════════════════════════════════════════════════════════
# 9. Full roundtrip: serialize → from_hex → serialize must be idempotent
# ═══════════════════════════════════════════════════════════════════════


class TestRoundTrip:
    def test_complex_tx_roundtrip(self):
        tx = Transaction(
            version=2,
            tx_inputs=[
                _make_input(unlocking_script=Script(b"\x00" * 200)),
                _make_input(unlocking_script=None),
                _make_input(unlocking_script=Script(b"\x51\x52\x93")),
            ],
            tx_outputs=[
                _make_output(0, b""),
                _make_output(21_000_000 * 100_000_000, b"\x76\xa9" + b"\x00" * 20 + b"\x88\xac"),
                _make_output(1, b"\x6a" + b"\x04" + b"\xde\xad\xbe\xef"),
            ],
            locktime=500_000,
        )
        native, python = _toggle_serialize(tx)
        assert native == python

        tx2 = Transaction.from_hex(native)
        assert tx2.serialize() == native

    def test_nft_like_tx_roundtrip(self):
        image_data = bytes(range(256)) * 4096  # ~1 MB
        op_return_script = b"\x6a" + b"\x4e" + len(image_data).to_bytes(4, "little") + image_data

        tx = Transaction(
            version=1,
            tx_inputs=[_make_input(unlocking_script=Script(b"\x00" * 107))],
            tx_outputs=[
                _make_output(0, op_return_script),
                _make_output(546, b"\x76\xa9" + b"\x14" + b"\xaa" * 20 + b"\x88\xac"),
            ],
            locktime=0,
        )
        native, python = _toggle_serialize(tx)
        assert native == python

        tx2 = Transaction.from_hex(native)
        assert tx2.outputs[0].locking_script.serialize() == op_return_script
        assert tx2.serialize() == native


# ═══════════════════════════════════════════════════════════════════════
# 10. Stress: many inputs × many outputs with varied scripts
# ═══════════════════════════════════════════════════════════════════════


class TestStressCombination:
    def test_many_inputs_many_outputs_varied(self):
        inputs = []
        for i in range(50):
            script_len = (i * 37) % 300
            script = Script(bytes([i & 0xFF]) * script_len) if script_len > 0 else None
            inputs.append(
                _make_input(
                    unlocking_script=script,
                    source_txid=f"{i:064x}",
                    vout=i,
                    seq=0xFFFFFFFF - i,
                )
            )

        outputs = []
        for i in range(50):
            script_len = (i * 53) % 500
            outputs.append(
                _make_output(
                    satoshis=i * 100_000,
                    script_bytes=bytes([(i + j) & 0xFF for j in range(script_len)]),
                )
            )

        tx = Transaction(version=2, tx_inputs=inputs, tx_outputs=outputs, locktime=12345)
        native, python = _toggle_serialize(tx)
        assert native == python


# ═══════════════════════════════════════════════════════════════════════
# 11. Error parity: C and Python must reject invalid inputs identically
# ═══════════════════════════════════════════════════════════════════════


class TestVersionLocktimeRejection:
    """version/locktime out-of-range must raise OverflowError on BOTH paths."""

    @pytest.mark.parametrize(
        "version,locktime,label",
        [
            (-1, 0, "negative-version"),
            (2**32, 0, "version-overflow"),
            (2**33, 0, "version-large-overflow"),
            (0, -1, "negative-locktime"),
            (0, 2**32, "locktime-overflow"),
            (0, 2**33, "locktime-large-overflow"),
        ],
        ids=lambda x: x if isinstance(x, str) else None,
    )
    def test_overflow_raises_on_both_paths(self, version, locktime, label):
        mod = sys.modules[Transaction.__module__]
        orig = mod._USE_NATIVE_TX

        tx = Transaction(version=version, tx_inputs=[], tx_outputs=[], locktime=locktime)

        # C path
        mod._USE_NATIVE_TX = True
        try:
            with pytest.raises(OverflowError):
                tx.serialize()
        finally:
            mod._USE_NATIVE_TX = orig

        # Python path
        mod._USE_NATIVE_TX = False
        try:
            with pytest.raises(OverflowError):
                tx.serialize()
        finally:
            mod._USE_NATIVE_TX = orig

    @pytest.mark.parametrize(
        "version,locktime",
        [(None, 0), (1.5, 0), ("1", 0), (0, None), (0, 1.5)],
        ids=["version-None", "version-float", "version-str", "locktime-None", "locktime-float"],
    )
    def test_type_error_on_native_path(self, version, locktime):
        tx = Transaction(version=version, tx_inputs=[], tx_outputs=[], locktime=locktime)
        mod = sys.modules[Transaction.__module__]
        orig = mod._USE_NATIVE_TX
        mod._USE_NATIVE_TX = True
        try:
            with pytest.raises(TypeError):
                tx.serialize()
        finally:
            mod._USE_NATIVE_TX = orig


class TestScriptTypeRejection:
    """Non-bytes script types must be rejected, not silently treated as empty."""

    @pytest.mark.parametrize(
        "bad_script",
        [bytearray(b"\x51"), memoryview(b"\x51"), "51", 42],
        ids=["bytearray", "memoryview", "str", "int"],
    )
    def test_unlocking_script_rejects_non_bytes(self, bad_script):
        inp_dict = {
            "source_txid": "aa" * 32,
            "source_output_index": 0,
            "unlocking_script": bad_script,
            "sequence": 0xFFFFFFFF,
        }
        with pytest.raises(TypeError, match="unlocking_script"):
            _bsv_native.tx_to_bytes(1, [inp_dict], [], 0)

    @pytest.mark.parametrize(
        "bad_script",
        [None, bytearray(b"\x76"), "76a9", 0],
        ids=["None", "bytearray", "str", "int"],
    )
    def test_locking_script_rejects_non_bytes(self, bad_script):
        out_dict = {"satoshis": 1000, "locking_script": bad_script}
        with pytest.raises(TypeError, match="locking_script"):
            _bsv_native.tx_to_bytes(1, [], [out_dict], 0)


class TestSourceTxidRejection:
    """source_txid edge cases: C and Python paths must agree."""

    INVALID_TXIDS = [
        ("aa" * 31, "short-62"),
        ("aa" * 33, "long-66"),
        ("gg" * 32, "non-hex"),
        ("", "empty"),
        ("aa " * 32, "with-spaces"),
    ]

    VALID_TXIDS = [
        ("AA" * 32, "uppercase"),
        ("aa" * 32, "normal"),
    ]

    @pytest.mark.parametrize(
        "txid,label",
        INVALID_TXIDS,
        ids=[t[1] for t in INVALID_TXIDS],
    )
    def test_invalid_txid_rejected_on_both_paths(self, txid, label):
        """Invalid txids must be rejected on both C and Python paths."""
        # C path (via _bsv_native directly)
        inp_dict = {
            "source_txid": txid,
            "source_output_index": 0,
            "unlocking_script": b"",
            "sequence": 0xFFFFFFFF,
        }
        with pytest.raises((TypeError, ValueError)):
            _bsv_native.tx_to_bytes(1, [inp_dict], [], 0)

        # Python path (via Transaction.serialize fallback)
        mod = sys.modules[Transaction.__module__]
        orig = mod._USE_NATIVE_TX
        mod._USE_NATIVE_TX = False
        try:
            inp = _make_input(source_txid=txid)
            tx = Transaction(version=1, tx_inputs=[inp], tx_outputs=[], locktime=0)
            with pytest.raises(ValueError):
                tx.serialize()
        finally:
            mod._USE_NATIVE_TX = orig

    def test_none_txid_rejected_on_c_path(self):
        inp_dict = {
            "source_txid": None,
            "source_output_index": 0,
            "unlocking_script": b"",
            "sequence": 0xFFFFFFFF,
        }
        with pytest.raises((TypeError, ValueError)):
            _bsv_native.tx_to_bytes(1, [inp_dict], [], 0)

    @pytest.mark.parametrize(
        "txid,label",
        VALID_TXIDS,
        ids=[t[1] for t in VALID_TXIDS],
    )
    def test_valid_txid_accepted_on_both_paths(self, txid, label):
        """Valid txids produce identical bytes on both paths."""
        inp = _make_input(source_txid=txid)
        tx = Transaction(version=1, tx_inputs=[inp], tx_outputs=[], locktime=0)
        native, python = _toggle_serialize(tx)
        assert native == python


class TestSatoshisRejection:
    """satoshis out-of-range in the C path."""

    @pytest.mark.parametrize(
        "satoshis",
        [-1, 2**64, -(2**63)],
        ids=["negative", "uint64-overflow", "large-negative"],
    )
    def test_satoshis_overflow(self, satoshis):
        out_dict = {"satoshis": satoshis, "locking_script": b""}
        with pytest.raises((OverflowError, ValueError)):
            _bsv_native.tx_to_bytes(1, [], [out_dict], 0)


class TestMissingKeys:
    """Missing required dict keys in the C path."""

    def test_missing_source_txid(self):
        inp = {"source_output_index": 0, "unlocking_script": b"", "sequence": 0xFFFFFFFF}
        with pytest.raises((TypeError, KeyError)):
            _bsv_native.tx_to_bytes(1, [inp], [], 0)

    def test_missing_sequence(self):
        inp = {"source_txid": "aa" * 32, "source_output_index": 0, "unlocking_script": b""}
        with pytest.raises(KeyError):
            _bsv_native.tx_to_bytes(1, [inp], [], 0)

    def test_missing_satoshis(self):
        out = {"locking_script": b""}
        with pytest.raises(KeyError):
            _bsv_native.tx_to_bytes(1, [], [out], 0)

    def test_missing_locking_script(self):
        out = {"satoshis": 1000}
        with pytest.raises(TypeError):
            _bsv_native.tx_to_bytes(1, [], [out], 0)

    def test_non_dict_input(self):
        with pytest.raises(TypeError):
            _bsv_native.tx_to_bytes(1, ["not a dict"], [], 0)

    def test_non_dict_output(self):
        with pytest.raises(TypeError):
            _bsv_native.tx_to_bytes(1, [], ["not a dict"], 0)

    def test_non_list_inputs(self):
        with pytest.raises(TypeError):
            _bsv_native.tx_to_bytes(1, "not a list", [], 0)

    def test_non_list_outputs(self):
        with pytest.raises(TypeError):
            _bsv_native.tx_to_bytes(1, [], "not a list", 0)


# ═══════════════════════════════════════════════════════════════════════
# 12. Signing preimage with large scripts (BIP143 + OTDA)
#     Verifies that hashOutputs / OTDA preimage buffers handle multi-MB
#     outputs (NFT images) and large scriptCodes correctly.
# ═══════════════════════════════════════════════════════════════════════


def _toggle_preimage(tx, input_index):
    """Return (native_preimage, python_preimage) for a single input."""
    import bsv.transaction_preimage as tp_mod

    orig = tp_mod._USE_NATIVE
    tp_mod._USE_NATIVE = True
    try:
        native = tx.preimage(input_index)
    finally:
        tp_mod._USE_NATIVE = orig

    tp_mod._USE_NATIVE = False
    try:
        python = tx.preimage(input_index)
    finally:
        tp_mod._USE_NATIVE = orig

    return native, python


P2PKH_SCRIPT = bytes.fromhex("76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")

BIP143_SIGHASH_FLAGS = [
    SIGHASH.ALL_FORKID,
    SIGHASH.NONE_FORKID,
    SIGHASH.SINGLE_FORKID,
    SIGHASH.ALL_FORKID | SIGHASH.ANYONECANPAY,
    SIGHASH.NONE_FORKID | SIGHASH.ANYONECANPAY,
    SIGHASH.SINGLE_FORKID | SIGHASH.ANYONECANPAY,
]

OTDA_SIGHASH_FLAGS = [
    SIGHASH.ALL_FORKID | SIGHASH.CHRONICLE,
    SIGHASH.NONE_FORKID | SIGHASH.CHRONICLE,
    SIGHASH.SINGLE_FORKID | SIGHASH.CHRONICLE,
    SIGHASH.ALL_FORKID | SIGHASH.CHRONICLE | SIGHASH.ANYONECANPAY,
    SIGHASH.NONE_FORKID | SIGHASH.CHRONICLE | SIGHASH.ANYONECANPAY,
    SIGHASH.SINGLE_FORKID | SIGHASH.CHRONICLE | SIGHASH.ANYONECANPAY,
]

ALL_SIGHASH_FLAGS = BIP143_SIGHASH_FLAGS + OTDA_SIGHASH_FLAGS


def _build_nft_tx(image_size, sighash, *, n_outputs=2):
    """Build a transaction with a large OP_RETURN output (NFT image)."""
    image_data = b"\xab" * image_size
    op_return_script = b"\x6a" + b"\x4e" + len(image_data).to_bytes(4, "little") + image_data

    outputs = [_make_output(0, op_return_script)]
    for i in range(1, n_outputs):
        outputs.append(_make_output(546 * i, P2PKH_SCRIPT))

    inp = TransactionInput(
        source_txid="aa" * 32,
        source_output_index=0,
        unlocking_script=None,
        sequence=0xFFFFFFFF,
    )
    inp.locking_script = Script(P2PKH_SCRIPT)
    inp.satoshis = 100_000
    inp.sighash = sighash

    return Transaction(version=1, tx_inputs=[inp], tx_outputs=outputs, locktime=0)


class TestPreimageLargeOutput:
    """BIP143 hashOutputs and OTDA preimage buffer with multi-MB outputs."""

    @pytest.mark.parametrize("megabytes", [1, 4, 20], ids=["1MB", "4MB", "20MB"])
    @pytest.mark.parametrize(
        "sighash",
        ALL_SIGHASH_FLAGS,
        ids=lambda s: f"0x{int(s):02x}",
    )
    def test_preimage_large_nft_output(self, megabytes, sighash):
        size = megabytes * 1024 * 1024
        tx = _build_nft_tx(size, sighash)
        native, python = _toggle_preimage(tx, 0)
        assert native == python
        assert len(native) > 0


class TestPreimageLargeScriptCode:
    """BIP143 scriptCode / OTDA scriptSig with a large locking_script on the
    signing input (e.g. spending from a complex smart contract)."""

    @pytest.mark.parametrize(
        "script_size",
        [253, 0x10000, 1 * 1024 * 1024],
        ids=["253B-varint-boundary", "64KB", "1MB"],
    )
    @pytest.mark.parametrize(
        "sighash",
        ALL_SIGHASH_FLAGS,
        ids=lambda s: f"0x{int(s):02x}",
    )
    def test_preimage_large_input_locking_script(self, script_size, sighash):
        large_locking = b"\x00" * script_size
        inp = TransactionInput(
            source_txid="bb" * 32,
            source_output_index=0,
            unlocking_script=None,
            sequence=0xFFFFFFFF,
        )
        inp.locking_script = Script(large_locking)
        inp.satoshis = 50_000
        inp.sighash = sighash

        tx = Transaction(
            version=1,
            tx_inputs=[inp],
            tx_outputs=[_make_output(1000, P2PKH_SCRIPT)],
            locktime=0,
        )
        native, python = _toggle_preimage(tx, 0)
        assert native == python
        assert len(native) > 0


class TestPreimageLargeOutputMultiInput:
    """Multi-input tx with large outputs — ensures shared hash caches and
    per-input preimage buffers are all sized correctly."""

    @pytest.mark.parametrize("sighash", ALL_SIGHASH_FLAGS, ids=lambda s: f"0x{int(s):02x}")
    def test_multi_input_large_output(self, sighash):
        image_data = b"\xcd" * (2 * 1024 * 1024)
        op_return_script = b"\x6a" + b"\x4e" + len(image_data).to_bytes(4, "little") + image_data

        inputs = []
        for i in range(3):
            inp = TransactionInput(
                source_txid=f"{i:064x}",
                source_output_index=i,
                unlocking_script=None,
                sequence=0xFFFFFFFF,
            )
            inp.locking_script = Script(P2PKH_SCRIPT)
            inp.satoshis = 100_000
            inp.sighash = sighash
            inputs.append(inp)

        tx = Transaction(
            version=1,
            tx_inputs=inputs,
            tx_outputs=[
                _make_output(0, op_return_script),
                _make_output(546, P2PKH_SCRIPT),
                _make_output(546, P2PKH_SCRIPT),
            ],
            locktime=0,
        )

        for idx in range(3):
            native, python = _toggle_preimage(tx, idx)
            assert native == python, f"preimage mismatch at input {idx}"


# ═══════════════════════════════════════════════════════════════════════
# 13. Subclass fallback: native path is only used for exact types.
#     Subclasses of TransactionInput / TransactionOutput must trigger
#     the Python fallback so serialize() overrides are honoured.
# ═══════════════════════════════════════════════════════════════════════


class _CustomInput(TransactionInput):
    """Subclass that appends a marker byte to the serialized output."""

    MARKER = b"\xfe"

    def serialize(self) -> bytes:
        return super().serialize() + self.MARKER


class _CustomOutput(TransactionOutput):
    """Subclass that appends a marker byte to the serialized output."""

    MARKER = b"\xfd"

    def serialize(self) -> bytes:
        return super().serialize() + self.MARKER


class TestSubclassFallback:
    """Subclassed inputs/outputs must fall back to the Python path."""

    def test_standard_types_use_native(self):
        """Exact TransactionInput/TransactionOutput should use native."""
        inp = _make_input()
        out = _make_output(1000, P2PKH_SCRIPT)
        tx = Transaction(version=1, tx_inputs=[inp], tx_outputs=[out], locktime=0)
        native, python = _toggle_serialize(tx)
        assert native == python

    def test_subclass_input_triggers_fallback(self):
        """A subclassed TransactionInput must call its serialize() override."""
        custom_inp = _CustomInput(
            source_txid="ab" * 32,
            source_output_index=0,
            unlocking_script=Script(b"\x00"),
            sequence=0xFFFFFFFF,
        )
        out = _make_output(1000, P2PKH_SCRIPT)
        tx = Transaction(version=1, tx_inputs=[custom_inp], tx_outputs=[out], locktime=0)
        result = tx.serialize()
        assert result.count(_CustomInput.MARKER) == 1

    def test_subclass_output_triggers_fallback(self):
        """A subclassed TransactionOutput must call its serialize() override."""
        inp = _make_input()
        custom_out = _CustomOutput(
            satoshis=1000,
            locking_script=Script(P2PKH_SCRIPT),
        )
        tx = Transaction(version=1, tx_inputs=[inp], tx_outputs=[custom_out], locktime=0)
        result = tx.serialize()
        assert result.count(_CustomOutput.MARKER) == 1

    def test_mixed_standard_and_subclass(self):
        """One subclass among standard types is enough to trigger fallback."""
        standard_inp = _make_input()
        custom_inp = _CustomInput(
            source_txid="cd" * 32,
            source_output_index=1,
            unlocking_script=Script(b"\x51"),
            sequence=0xFFFFFFFF,
        )
        out = _make_output(2000, P2PKH_SCRIPT)
        tx = Transaction(
            version=1,
            tx_inputs=[standard_inp, custom_inp],
            tx_outputs=[out],
            locktime=0,
        )
        result = tx.serialize()
        assert _CustomInput.MARKER in result
