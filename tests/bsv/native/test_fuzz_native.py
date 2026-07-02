"""Fuzz tests for _bsv_native C extension.

Uses hypothesis to generate random inputs and verify the C functions
never crash (segfault / abort). Every test is a crash-oracle: the
function may raise a Python exception, but must never cause a
process-level crash or memory corruption.

Run:
    pytest tests/bsv/native/test_fuzz_native.py -x -v --hypothesis-seed=0
    pytest tests/bsv/native/test_fuzz_native.py -x -v  # random seed
"""

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import _bsv_native

DEADLINE_MS = 2000
MAX_EXAMPLES = 200

fuzz_settings = settings(
    max_examples=MAX_EXAMPLES,
    deadline=DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

# ---------------------------------------------------------------------------
# Strategy helpers
# ---------------------------------------------------------------------------

bytes32 = st.binary(min_size=32, max_size=32)
bytes33 = st.binary(min_size=33, max_size=33)
bytes65 = st.binary(min_size=65, max_size=65)
short_bytes = st.binary(min_size=0, max_size=512)
medium_bytes = st.binary(min_size=0, max_size=4096)
hex64 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def valid_secret() -> st.SearchStrategy[bytes]:
    return st.integers(min_value=1, max_value=CURVE_ORDER - 1).map(lambda n: n.to_bytes(32, "big"))


# ---------------------------------------------------------------------------
# Hash functions — accept arbitrary bytes, never crash
# ---------------------------------------------------------------------------


class TestFuzzHash:
    @fuzz_settings
    @given(data=medium_bytes)
    def test_sha256_no_crash(self, data):
        result = _bsv_native.sha256(data)
        assert isinstance(result, bytes) and len(result) == 32

    @fuzz_settings
    @given(data=medium_bytes)
    def test_hash256_no_crash(self, data):
        result = _bsv_native.hash256(data)
        assert isinstance(result, bytes) and len(result) == 32

    @fuzz_settings
    @given(key=short_bytes, msg=short_bytes)
    def test_hmac_sha256_no_crash(self, key, msg):
        result = _bsv_native.hmac_sha256(key, msg)
        assert isinstance(result, bytes) and len(result) == 32


# ---------------------------------------------------------------------------
# Public key operations — may raise ValueError/OverflowError, never crash
# ---------------------------------------------------------------------------


class TestFuzzPubkey:
    @fuzz_settings
    @given(secret=bytes32)
    def test_pubkey_from_secret_no_crash(self, secret):
        try:
            result = _bsv_native.pubkey_from_secret(secret)
            assert isinstance(result, bytes)
        except (ValueError, OverflowError):
            pass

    @fuzz_settings
    @given(data=st.binary(min_size=0, max_size=128))
    def test_pubkey_parse_no_crash(self, data):
        try:
            result = _bsv_native.pubkey_parse(data)
            assert isinstance(result, bytes)
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(data=st.binary(min_size=0, max_size=128), compressed=st.booleans())
    def test_pubkey_serialize_no_crash(self, data, compressed):
        try:
            result = _bsv_native.pubkey_serialize(data, compressed)
            assert isinstance(result, bytes)
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(data=st.binary(min_size=0, max_size=128))
    def test_pubkey_point_no_crash(self, data):
        try:
            result = _bsv_native.pubkey_point(data)
            assert isinstance(result, tuple) and len(result) == 2
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(secret=valid_secret(), tweak=bytes32)
    def test_pubkey_tweak_add_no_crash(self, secret, tweak):
        try:
            pub = _bsv_native.pubkey_from_secret(secret)
            _bsv_native.pubkey_tweak_add(pub, tweak)
        except (ValueError, OverflowError):
            pass

    @fuzz_settings
    @given(secret=valid_secret(), tweak=bytes32)
    def test_pubkey_tweak_mul_no_crash(self, secret, tweak):
        try:
            pub = _bsv_native.pubkey_from_secret(secret)
            _bsv_native.pubkey_tweak_mul(pub, tweak)
        except (ValueError, OverflowError):
            pass

    @fuzz_settings
    @given(
        secrets=st.lists(valid_secret(), min_size=1, max_size=5),
        compressed=st.booleans(),
    )
    def test_pubkey_combine_no_crash(self, secrets, compressed):
        try:
            pubs = [_bsv_native.pubkey_from_secret(s) for s in secrets]
            result = _bsv_native.pubkey_combine(pubs, compressed)
            assert isinstance(result, bytes)
        except (ValueError, OverflowError):
            pass


# ---------------------------------------------------------------------------
# Secret key operations
# ---------------------------------------------------------------------------


class TestFuzzSeckey:
    @fuzz_settings
    @given(data=bytes32)
    def test_seckey_verify_no_crash(self, data):
        result = _bsv_native.seckey_verify(data)
        assert isinstance(result, bool)

    @fuzz_settings
    @given(secret=bytes32, tweak=bytes32)
    def test_seckey_tweak_add_no_crash(self, secret, tweak):
        try:
            result = _bsv_native.seckey_tweak_add(secret, tweak)
            assert isinstance(result, bytes) and len(result) == 32
        except (ValueError, OverflowError):
            pass


# ---------------------------------------------------------------------------
# ECDSA sign / verify / recover
# ---------------------------------------------------------------------------


class TestFuzzECDSA:
    @fuzz_settings
    @given(msg=bytes32, secret=valid_secret())
    def test_ecdsa_sign_no_crash(self, msg, secret):
        result = _bsv_native.ecdsa_sign(msg, secret)
        assert isinstance(result, bytes)

    @fuzz_settings
    @given(msg=bytes32, secret=bytes32)
    def test_ecdsa_sign_bad_secret_no_crash(self, msg, secret):
        try:
            _bsv_native.ecdsa_sign(msg, secret)
        except (ValueError, OverflowError):
            pass

    @fuzz_settings
    @given(sig=st.binary(min_size=0, max_size=128), msg=bytes32, pub=short_bytes)
    def test_ecdsa_verify_no_crash(self, sig, msg, pub):
        try:
            result = _bsv_native.ecdsa_verify(sig, msg, pub)
            assert isinstance(result, bool)
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(msg=bytes32, secret=valid_secret(), k=valid_secret())
    def test_ecdsa_sign_with_k_no_crash(self, msg, secret, k):
        try:
            result = _bsv_native.ecdsa_sign_with_k(msg, secret, k)
            assert isinstance(result, bytes)
        except (ValueError, OverflowError):
            pass

    @fuzz_settings
    @given(msg=bytes32, secret=valid_secret())
    def test_ecdsa_sign_recoverable_no_crash(self, msg, secret):
        result = _bsv_native.ecdsa_sign_recoverable(msg, secret)
        assert isinstance(result, bytes) and len(result) == 65

    @fuzz_settings
    @given(sig=bytes65, msg=bytes32, compressed=st.booleans())
    def test_ecdsa_recover_no_crash(self, sig, msg, compressed):
        try:
            result = _bsv_native.ecdsa_recover(sig, msg, compressed)
            assert isinstance(result, bytes)
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(msg=bytes32, secret=valid_secret())
    def test_ecdsa_roundtrip(self, msg, secret):
        sig = _bsv_native.ecdsa_sign(msg, secret)
        pub = _bsv_native.pubkey_from_secret(secret)
        assert _bsv_native.ecdsa_verify(sig, msg, pub)


# ---------------------------------------------------------------------------
# ECDH
# ---------------------------------------------------------------------------


class TestFuzzECDH:
    @fuzz_settings
    @given(s1=valid_secret(), s2=valid_secret())
    def test_ecdh_no_crash(self, s1, s2):
        pub2 = _bsv_native.pubkey_from_secret(s2)
        result = _bsv_native.ecdh(s1, pub2)
        assert isinstance(result, bytes) and len(result) == 32

    @fuzz_settings
    @given(secret=bytes32, pub=short_bytes)
    def test_ecdh_bad_inputs_no_crash(self, secret, pub):
        try:
            _bsv_native.ecdh(secret, pub)
        except (ValueError, TypeError):
            pass


# ---------------------------------------------------------------------------
# Tx parse / serialize — high-risk due to buffer parsing
# ---------------------------------------------------------------------------


class TestFuzzTx:
    @fuzz_settings
    @given(data=medium_bytes)
    def test_tx_from_bytes_no_crash(self, data):
        try:
            result = _bsv_native.tx_from_bytes(data)
            assert isinstance(result, dict)
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(data=st.binary(min_size=0, max_size=8192))
    def test_tx_from_bytes_large_no_crash(self, data):
        try:
            _bsv_native.tx_from_bytes(data)
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(
        version=st.integers(min_value=0, max_value=0xFFFFFFFF),
        locktime=st.integers(min_value=0, max_value=0xFFFFFFFF),
    )
    def test_tx_to_bytes_minimal_no_crash(self, version, locktime):
        try:
            result = _bsv_native.tx_to_bytes(version, [], [], locktime)
            assert isinstance(result, bytes)
        except (ValueError, TypeError, OverflowError):
            pass

    @fuzz_settings
    @given(data=st.binary(min_size=10, max_size=512))
    def test_tx_from_to_roundtrip_no_crash(self, data):
        try:
            parsed = _bsv_native.tx_from_bytes(data)
            rebuilt = _bsv_native.tx_to_bytes(
                parsed["version"],
                parsed["inputs"],
                parsed["outputs"],
                parsed["locktime"],
            )
            assert isinstance(rebuilt, bytes)
        except (ValueError, TypeError, KeyError):
            pass

    @fuzz_settings
    @given(
        txid=hex64,
        n_inputs=st.integers(min_value=0, max_value=3),
        locktime=st.integers(min_value=0, max_value=0xFFFFFFFF),
    )
    def test_tx_txid_no_crash(self, txid, n_inputs, locktime):
        inputs = []
        for _i in range(n_inputs):
            inputs.append(
                {
                    "source_txid": txid,
                    "source_output_index": 0,
                    "unlocking_script": b"",
                    "sequence": 0xFFFFFFFF,
                }
            )
        outputs = [{"satoshis": 1000, "locking_script": b""}]
        try:
            result = _bsv_native.tx_txid(1, inputs, outputs, locktime)
            assert isinstance(result, str) and len(result) == 64
        except (ValueError, TypeError):
            pass


# ---------------------------------------------------------------------------
# Script chunk parse / serialize
# ---------------------------------------------------------------------------


class TestFuzzScript:
    @fuzz_settings
    @given(data=medium_bytes)
    def test_parse_script_chunks_no_crash(self, data):
        try:
            result = _bsv_native.parse_script_chunks(data)
            assert isinstance(result, list)
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(
        chunks=st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=255),
                st.one_of(st.none(), st.binary(min_size=0, max_size=64)),
            ),
            min_size=0,
            max_size=20,
        )
    )
    def test_serialize_script_chunks_no_crash(self, chunks):
        try:
            result = _bsv_native.serialize_script_chunks(chunks)
            assert isinstance(result, bytes)
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(data=st.binary(min_size=0, max_size=512))
    def test_script_parse_serialize_roundtrip(self, data):
        try:
            chunks = _bsv_native.parse_script_chunks(data)
            rebuilt = _bsv_native.serialize_script_chunks(chunks)
            assert isinstance(rebuilt, bytes)
        except (ValueError, TypeError):
            pass


# ---------------------------------------------------------------------------
# Merkle path
# ---------------------------------------------------------------------------


class TestFuzzMerkle:
    @fuzz_settings
    @given(left=hex64, right=hex64)
    def test_merkle_hash_pair_no_crash(self, left, right):
        try:
            result = _bsv_native.merkle_hash_pair(left, right)
            assert isinstance(result, str) and len(result) == 64
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(
        txid=hex64,
        path=st.lists(
            st.tuples(st.integers(min_value=0, max_value=1), hex64),
            min_size=0,
            max_size=10,
        ),
    )
    def test_merkle_compute_root_no_crash(self, txid, path):
        try:
            result = _bsv_native.merkle_compute_root(txid, path)
            assert isinstance(result, str) and len(result) == 64
        except (ValueError, TypeError):
            pass


# ---------------------------------------------------------------------------
# Preimage — BIP143 and OTDA
# ---------------------------------------------------------------------------


class TestFuzzPreimage:
    @fuzz_settings
    @given(
        version=st.integers(min_value=0, max_value=0xFFFFFFFF),
        locktime=st.integers(min_value=0, max_value=0xFFFFFFFF),
        sighash=st.sampled_from([0x41, 0x42, 0x43, 0xC1, 0xC2, 0xC3]),
    )
    def test_tx_preimages_minimal_no_crash(self, version, locktime, sighash):
        txid = "aa" * 32
        inputs = [
            {
                "txid": txid,
                "vout": 0,
                "locking_script": b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac",
                "satoshis": 1000,
                "sequence": 0xFFFFFFFF,
                "sighash": sighash,
            }
        ]
        outputs = [b"\xe8\x03\x00\x00\x00\x00\x00\x00\x00"]
        try:
            result = _bsv_native.tx_preimages(version, locktime, inputs, outputs)
            assert isinstance(result, list)
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(data=st.binary(min_size=0, max_size=256))
    def test_tx_preimages_garbage_input_no_crash(self, data):
        try:
            _bsv_native.tx_preimages(1, 0, [data], [data])
        except (ValueError, TypeError):
            pass

    @fuzz_settings
    @given(
        version=st.integers(min_value=0, max_value=0xFFFFFFFF),
        locktime=st.integers(min_value=0, max_value=0xFFFFFFFF),
        sighash=st.sampled_from([0x61, 0x62, 0x63, 0xE1, 0xE2, 0xE3]),
    )
    def test_tx_preimage_otda_no_crash(self, version, locktime, sighash):
        txid = "bb" * 32
        inputs = [
            {
                "txid": txid,
                "vout": 0,
                "locking_script": b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac",
                "satoshis": 1000,
                "sequence": 0xFFFFFFFF,
                "sighash": sighash,
            }
        ]
        outputs = [b"\xe8\x03\x00\x00\x00\x00\x00\x00\x00"]
        try:
            result = _bsv_native.tx_preimage_otda(0, version, locktime, inputs, outputs)
            assert isinstance(result, bytes)
        except (ValueError, TypeError):
            pass


# ---------------------------------------------------------------------------
# spend_validate — full VM, highest risk
# ---------------------------------------------------------------------------


class TestFuzzSpendValidate:
    @fuzz_settings
    @given(
        unlock_ops=st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=255),
                st.one_of(st.none(), st.binary(min_size=0, max_size=64)),
            ),
            min_size=0,
            max_size=10,
        ),
        lock_ops=st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=255),
                st.one_of(st.none(), st.binary(min_size=0, max_size=64)),
            ),
            min_size=0,
            max_size=10,
        ),
        tx_version=st.integers(min_value=1, max_value=2),
    )
    def test_spend_validate_random_script_no_crash(self, unlock_ops, lock_ops, tx_version):
        txid = "00" * 32
        try:
            _bsv_native.spend_validate(
                unlock_ops,
                lock_ops,
                tx_version,
                txid,
                0,
                0,  # lock_time
                0,  # input_index
                0xFFFFFFFF,  # input_sequence
                1000,  # source_satoshis
                [],  # other_inputs
                [],  # outputs
            )
        except (RuntimeError, ValueError, TypeError, OverflowError):
            pass

    @fuzz_settings
    @given(
        data_items=st.lists(st.binary(min_size=1, max_size=32), min_size=1, max_size=5),
        tx_version=st.integers(min_value=1, max_value=2),
    )
    def test_spend_validate_stack_ops_no_crash(self, data_items, tx_version):
        unlock = [(1, item) for item in data_items]
        lock_ops = [
            (0x76, None),  # OP_DUP
            (0x75, None),  # OP_DROP
            (0x51, None),  # OP_1
        ]
        txid = "00" * 32
        try:
            _bsv_native.spend_validate(
                unlock,
                lock_ops,
                tx_version,
                txid,
                0,
                0,
                0,
                0xFFFFFFFF,
                1000,
                [],
                [],
            )
        except (RuntimeError, ValueError, TypeError, OverflowError):
            pass

    @fuzz_settings
    @given(
        ops=st.lists(
            st.sampled_from(
                [
                    (0x93, None),  # OP_ADD
                    (0x94, None),  # OP_SUB
                    (0x95, None),  # OP_MUL
                    (0x96, None),  # OP_DIV
                    (0x97, None),  # OP_MOD
                    (0x8B, None),  # OP_1ADD
                    (0x8C, None),  # OP_1SUB
                    (0x8F, None),  # OP_NEGATE
                    (0x90, None),  # OP_ABS
                    (0x9A, None),  # OP_NUMEQUAL
                ]
            ),
            min_size=1,
            max_size=8,
        ),
        values=st.lists(
            st.integers(min_value=-(2**31), max_value=2**31 - 1),
            min_size=2,
            max_size=4,
        ),
    )
    def test_spend_validate_arithmetic_no_crash(self, ops, values):
        unlock = []
        for v in values:
            if v == 0:
                unlock.append((0, None))  # OP_0
            elif 1 <= v <= 16:
                unlock.append((0x50 + v, None))
            elif v == -1:
                unlock.append((0x4F, None))  # OP_1NEGATE
            else:
                encoded = _encode_script_num(v)
                unlock.append((len(encoded), encoded))
        lock = [*list(ops), (0x51, None)]  # OP_1 to leave truthy on stack
        txid = "00" * 32
        try:
            _bsv_native.spend_validate(
                unlock,
                lock,
                1,
                txid,
                0,
                0,
                0,
                0xFFFFFFFF,
                1000,
                [],
                [],
            )
        except (RuntimeError, ValueError, TypeError, OverflowError):
            pass

    @fuzz_settings
    @given(
        n_if=st.integers(min_value=0, max_value=5),
        nest=st.booleans(),
    )
    def test_spend_validate_flow_control_no_crash(self, n_if, nest):
        unlock = [(0x51, None)]  # OP_1 (TRUE)
        lock = []
        for _ in range(n_if):
            lock.append((0x63, None))  # OP_IF
            lock.append((0x51, None))  # OP_1
            if not nest:
                lock.append((0x68, None))  # OP_ENDIF
        if nest:
            for _ in range(n_if):
                lock.append((0x68, None))  # OP_ENDIF
        txid = "00" * 32
        try:
            _bsv_native.spend_validate(
                unlock,
                lock,
                1,
                txid,
                0,
                0,
                0,
                0xFFFFFFFF,
                1000,
                [],
                [],
            )
        except (RuntimeError, ValueError, TypeError, OverflowError):
            pass

    @fuzz_settings
    @given(
        hash_op=st.sampled_from([0xA7, 0xA8, 0xA9, 0xAA, 0xAB]),
        data=short_bytes,
    )
    def test_spend_validate_hash_ops_no_crash(self, hash_op, data):
        if data:
            unlock = [(len(data), data)]
        else:
            unlock = [(0, None)]
        lock = [(hash_op, None), (0x75, None), (0x51, None)]  # hash, DROP, OP_1
        txid = "00" * 32
        try:
            _bsv_native.spend_validate(
                unlock,
                lock,
                1,
                txid,
                0,
                0,
                0,
                0xFFFFFFFF,
                1000,
                [],
                [],
            )
        except (RuntimeError, ValueError, TypeError, OverflowError):
            pass

    @fuzz_settings
    @given(
        bad_type_unlock=st.one_of(
            st.just("not a list"),
            st.just(42),
            st.just(None),
        ),
    )
    def test_spend_validate_bad_types_no_crash(self, bad_type_unlock):
        try:
            _bsv_native.spend_validate(
                bad_type_unlock,
                [(0x51, None)],
                1,
                "00" * 32,
                0,
                0,
                0,
                0xFFFFFFFF,
                1000,
                [],
                [],
            )
        except (RuntimeError, ValueError, TypeError, OverflowError):
            pass


def _encode_script_num(val: int) -> bytes:
    if val == 0:
        return b""
    negative = val < 0
    absval = abs(val)
    result = bytearray()
    while absval > 0:
        result.append(absval & 0xFF)
        absval >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


# ---------------------------------------------------------------------------
# Reference counting stress — detect Python refcount leaks
# ---------------------------------------------------------------------------


class TestRefcountStress:
    def test_hash256_repeated_no_leak(self):
        data = b"test" * 100
        for _ in range(10000):
            _bsv_native.hash256(data)

    def test_tx_from_bytes_error_path_no_leak(self):
        for _ in range(10000):
            try:
                _bsv_native.tx_from_bytes(b"\x01\x00")
            except ValueError:
                pass

    def test_pubkey_parse_error_path_no_leak(self):
        for _ in range(10000):
            try:
                _bsv_native.pubkey_parse(b"\xff" * 33)
            except ValueError:
                pass

    def test_spend_validate_error_path_no_leak(self):
        for _ in range(5000):
            try:
                _bsv_native.spend_validate(
                    [],
                    [(0x6A, None)],
                    1,
                    "00" * 32,
                    0,
                    0,
                    0,
                    0xFFFFFFFF,
                    1000,
                    [],
                    [],
                )
            except RuntimeError:
                pass

    def test_ecdsa_verify_error_path_no_leak(self):
        for _ in range(10000):
            try:
                _bsv_native.ecdsa_verify(b"\x30\x06", b"\x00" * 32, b"\x02" + b"\x00" * 32)
            except ValueError:
                pass

    def test_script_parse_roundtrip_no_leak(self):
        data = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
        for _ in range(10000):
            chunks = _bsv_native.parse_script_chunks(data)
            _bsv_native.serialize_script_chunks(chunks)


# ---------------------------------------------------------------------------
# Memory growth — detect unbounded per-call leaks (tracemalloc oracle)
# ---------------------------------------------------------------------------


class TestMemoryGrowth:
    """Assert that repeated success-path calls do not grow traced memory.

    TestRefcountStress above only detects crashes. A per-call reference
    leak (e.g. passing an inline-created object to PyDict_SetItemString,
    which does NOT steal references) passes those tests while leaking
    unboundedly. 20,000 iterations leaking even ~30 bytes/call exceed
    500 KB, while a leak-free function stays within allocator noise.
    """

    ITERATIONS = 20_000
    # A per-call reference leak keeps >= ITERATIONS blocks alive (one per
    # leaked object per call); allocator noise (arena growth under pytest)
    # keeps only a handful of large blocks alive. Block count separates
    # the two reliably where a byte threshold cannot.
    MAX_NEW_BLOCKS = 2_000

    TX_1IN_2OUT = bytes.fromhex(
        "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651"
        "0000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb07"
        "2cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137"
        "d26588ac00000000"
    )

    def _assert_no_growth(self, fn):
        import tracemalloc

        tracemalloc.start()
        for _ in range(2000):
            fn()  # in-session warmup: free-lists, interned strings
        snap1 = tracemalloc.take_snapshot()
        for _ in range(self.ITERATIONS):
            fn()
        snap2 = tracemalloc.take_snapshot()
        tracemalloc.stop()
        new_blocks = sum(
            stat.count_diff
            for stat in snap2.compare_to(snap1, "lineno")
            if stat.count_diff > 0
        )
        assert new_blocks < self.MAX_NEW_BLOCKS, (
            f"leaked ~{new_blocks / self.ITERATIONS:.2f} blocks/call "
            f"({new_blocks:,} new live blocks over {self.ITERATIONS:,} iterations)"
        )

    def test_tx_from_bytes_success_path_no_growth(self):
        raw = self.TX_1IN_2OUT
        self._assert_no_growth(lambda: _bsv_native.tx_from_bytes(raw))

    def test_tx_to_bytes_no_growth(self):
        parsed = _bsv_native.tx_from_bytes(self.TX_1IN_2OUT)
        self._assert_no_growth(
            lambda: _bsv_native.tx_to_bytes(
                parsed["version"], parsed["inputs"], parsed["outputs"], parsed["locktime"]
            )
        )

    def test_parse_script_chunks_success_path_no_growth(self):
        script = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
        self._assert_no_growth(lambda: _bsv_native.parse_script_chunks(script))

    def test_pubkey_point_no_growth(self):
        pk = _bsv_native.pubkey_from_secret(b"\x01" * 32)
        self._assert_no_growth(lambda: _bsv_native.pubkey_point(pk))


# ---------------------------------------------------------------------------
# Full-surface memory scan — every exported function, success + error paths
# ---------------------------------------------------------------------------


def _all_export_cases():
    """(id, callable) for every exported function. Error-path cases raise
    per call and exercise cleanup on the exception path."""
    N = _bsv_native
    tx = bytes.fromhex(TestMemoryGrowth.TX_1IN_2OUT.hex())
    txid = "93a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651"
    p2pkh = bytes.fromhex("76a9146a176cd51593e00542b8e1958b7da2be97452d0588ac")
    sec, sec2 = b"\x01" * 32, b"\x02" * 32
    pk, pk2 = N.pubkey_from_secret(sec), N.pubkey_from_secret(sec2)
    msg = N.hash256(b"msg")
    sig = N.ecdsa_sign(msg, sec)
    rsig = N.ecdsa_sign_recoverable(msg, sec)
    k = b"\x03" * 31 + b"\x07"
    tweak = b"\x00" * 31 + b"\x05"
    parsed = N.tx_from_bytes(tx)
    chunks = N.parse_script_chunks(p2pkh)
    in_tuples = [(txid, 0, p2pkh, 100_000_000, 0xFFFFFFFF, 0x41)]
    out_bytes = [(50_000).to_bytes(8, "little") + bytes([len(p2pkh)]) + p2pkh]
    mpath = [
        [{"offset": 0, "hash_str": txid}, {"offset": 1, "hash_str": "bb" * 32}],
        [{"offset": 1, "hash_str": "cc" * 32}],
    ]

    def swallow(f):
        def run():
            try:
                f()
            except Exception:
                pass
        return run

    return [
        ("sha256", lambda: N.sha256(b"x" * 64)),
        ("hash256", lambda: N.hash256(b"x" * 64)),
        ("hmac_sha256", lambda: N.hmac_sha256(b"key", b"data")),
        ("pubkey_from_secret", lambda: N.pubkey_from_secret(sec)),
        ("pubkey_parse", lambda: N.pubkey_parse(pk)),
        ("pubkey_serialize", lambda: N.pubkey_serialize(pk, True)),
        ("pubkey_serialize_unc", lambda: N.pubkey_serialize(pk, False)),
        ("pubkey_point", lambda: N.pubkey_point(pk)),
        ("pubkey_tweak_add", lambda: N.pubkey_tweak_add(pk, tweak)),
        ("pubkey_tweak_mul", lambda: N.pubkey_tweak_mul(pk, tweak)),
        ("pubkey_combine", lambda: N.pubkey_combine([pk, pk2])),
        ("seckey_verify", lambda: N.seckey_verify(sec)),
        ("seckey_tweak_add", lambda: N.seckey_tweak_add(sec, tweak)),
        ("ecdsa_sign", lambda: N.ecdsa_sign(msg, sec)),
        ("ecdsa_verify", lambda: N.ecdsa_verify(sig, msg, pk)),
        ("ecdsa_sign_recoverable", lambda: N.ecdsa_sign_recoverable(msg, sec)),
        ("ecdsa_recover", lambda: N.ecdsa_recover(rsig, msg)),
        ("ecdsa_sign_with_k", lambda: N.ecdsa_sign_with_k(msg, sec, k)),
        ("ecdh", lambda: N.ecdh(sec, pk2)),
        ("tx_from_bytes", lambda: N.tx_from_bytes(tx)),
        ("tx_to_bytes", lambda: N.tx_to_bytes(
            parsed["version"], parsed["inputs"], parsed["outputs"], parsed["locktime"])),
        ("tx_txid", lambda: N.tx_txid(tx)),
        ("tx_preimages", lambda: N.tx_preimages(1, 0, in_tuples, out_bytes)),
        ("tx_preimage_otda", lambda: N.tx_preimage_otda(0, 1, 0, in_tuples, out_bytes)),
        ("parse_script_chunks", lambda: N.parse_script_chunks(p2pkh)),
        ("serialize_script_chunks", lambda: N.serialize_script_chunks(chunks)),
        ("merkle_hash_pair", lambda: N.merkle_hash_pair("aa" * 32, "bb" * 32)),
        ("merkle_compute_root", lambda: N.merkle_compute_root(txid, mpath)),
        ("context_randomize", lambda: N.context_randomize(b"\x42" * 32)),
        # error paths
        ("ERR_pubkey_parse", swallow(lambda: N.pubkey_parse(b"\xff" * 33))),
        ("ERR_pubkey_tweak_add", swallow(lambda: N.pubkey_tweak_add(b"\xff" * 33, tweak))),
        ("ERR_pubkey_combine", swallow(lambda: N.pubkey_combine([b"\xff" * 33, pk]))),
        ("ERR_seckey_tweak_add", swallow(lambda: N.seckey_tweak_add(b"\x00" * 32, tweak))),
        ("ERR_ecdsa_sign", swallow(lambda: N.ecdsa_sign(msg, b"\x00" * 32))),
        ("ERR_ecdsa_recover_recid", swallow(lambda: N.ecdsa_recover(rsig[:64] + b"\x09", msg))),
        ("ERR_ecdh", swallow(lambda: N.ecdh(b"\x00" * 32, pk))),
        ("ERR_tx_from_bytes", swallow(lambda: N.tx_from_bytes(b"\x01\x00"))),
        ("ERR_serialize_chunks", swallow(lambda: N.serialize_script_chunks([(0x4C, b"x" * 300)]))),
        ("ERR_merkle_hash_pair", swallow(lambda: N.merkle_hash_pair("zz" * 32, "bb" * 32))),
        ("ERR_tx_preimage_otda_single", swallow(lambda: N.tx_preimage_otda(
            0, 2, 0, [(txid, 0, b"", 1, 0xFFFFFFFF, 0x63)], []))),
    ]


class TestFullSurfaceMemoryScan:
    """Every exported function, checked for per-call leaks via block-count
    oracle. Guards against the tx_from_bytes-style leak recurring in any
    function. Error-path cases confirm cleanup runs on the exception path."""

    ITERATIONS = 8_000
    MAX_NEW_BLOCKS = 1_000

    @pytest.mark.parametrize("label,fn", _all_export_cases(), ids=lambda v: v if isinstance(v, str) else "")
    def test_no_per_call_leak(self, label, fn):
        import tracemalloc

        fn()
        tracemalloc.start()
        for _ in range(1000):
            fn()
        snap1 = tracemalloc.take_snapshot()
        for _ in range(self.ITERATIONS):
            fn()
        snap2 = tracemalloc.take_snapshot()
        tracemalloc.stop()
        new_blocks = sum(
            s.count_diff for s in snap2.compare_to(snap1, "lineno") if s.count_diff > 0
        )
        assert new_blocks < self.MAX_NEW_BLOCKS, (
            f"{label}: leaked ~{new_blocks / self.ITERATIONS:.2f} blocks/call"
        )


# ---------------------------------------------------------------------------
# Crash / hang regression — must run in a subprocess so a SIGSEGV or infinite
# loop is caught as a nonzero/timeout exit instead of killing the test runner.
# In-process fuzz tests (which merely tolerate exceptions) cannot catch these.
# ---------------------------------------------------------------------------


class TestCrashHangRegression:
    def _run(self, body: str, timeout: float = 8.0):
        import subprocess
        import sys
        import textwrap

        src = "import _bsv_native\n" + textwrap.dedent(body)
        return subprocess.run(
            [sys.executable, "-c", src], capture_output=True, text=True, timeout=timeout
        )

    def test_sign_with_k_zero_does_not_hang(self):
        """k=0 (or any multiple of the curve order) once hung forever because
        nonce_fn_custom_k ignored the retry counter. Must raise, not loop."""
        import subprocess

        try:
            r = self._run(
                """
                msg = _bsv_native.hash256(b'm'); sec = b'\\x01' * 32
                try:
                    _bsv_native.ecdsa_sign_with_k(msg, sec, b'\\x00' * 32)
                    print('NOEXC')
                except ValueError:
                    print('VALUEERROR')
                """,
                timeout=8.0,
            )
        except subprocess.TimeoutExpired:
            pytest.fail("ecdsa_sign_with_k(k=0) hung (infinite nonce retry loop)")
        assert r.returncode == 0, f"crashed: rc={r.returncode} {r.stderr[-300:]}"
        assert "VALUEERROR" in r.stdout

    def test_spend_validate_otda_single_out_of_range_no_crash(self):
        """OTDA SIGHASH_SINGLE with input_index >= n_outputs once read
        outputs_list out of bounds (SIGSEGV). Must not crash the process."""
        r = self._run(
            """
            sec = b'\\x02' * 32
            pub = _bsv_native.pubkey_from_secret(sec)
            sig = _bsv_native.ecdsa_sign(_bsv_native.hash256(b'x'), sec) + b'\\x63'
            unlock = [(len(sig), sig), (len(pub), pub)]
            lock = [(0xAC, None)]
            try:
                _bsv_native.spend_validate(unlock, lock, 2, '00'*32, 0, 0, 0,
                                           0xffffffff, 1000, [], [])
            except RuntimeError:
                pass
            print('SURVIVED')
            """
        )
        assert r.returncode == 0, f"crashed: rc={r.returncode} {r.stderr[-300:]}"
        assert "SURVIVED" in r.stdout

    def test_spend_validate_otda_single_bug_digest(self):
        """A signature over hash256(0x01||0x00*31) must verify TRUE through the
        SIGHASH_SINGLE-bug path, proving the C digest matches the Python path."""
        r = self._run(
            """
            from bsv.hash import hash256
            sec = b'\\x02' * 32
            pub = _bsv_native.pubkey_from_secret(sec)
            digest = hash256(b'\\x01' + b'\\x00' * 31)
            sig = _bsv_native.ecdsa_sign(digest, sec) + b'\\x63'
            unlock = [(len(sig), sig), (len(pub), pub)]
            lock = [(0xAC, None)]
            r = _bsv_native.spend_validate(unlock, lock, 2, '00'*32, 0, 0, 0,
                                           0xffffffff, 1000, [], [])
            print('OK' if r else 'FALSE')
            """
        )
        assert r.returncode == 0, f"crashed: rc={r.returncode} {r.stderr[-300:]}"
        assert "OK" in r.stdout

    def test_tx_preimage_otda_single_out_of_range_raises(self):
        """Exported tx_preimage_otda with SINGLE + input_index >= n_outputs
        once overflowed its buffer / read OOB. Must raise IndexError."""
        r = self._run(
            """
            inp = [('11'*32, 0, b'', 500, 0xffffffff, 0x63)]
            try:
                _bsv_native.tx_preimage_otda(0, 2, 0, inp, [])
                print('NOEXC')
            except IndexError:
                print('INDEXERROR')
            """
        )
        assert r.returncode == 0, f"crashed: rc={r.returncode} {r.stderr[-300:]}"
        assert "INDEXERROR" in r.stdout
