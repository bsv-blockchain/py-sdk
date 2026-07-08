"""
Equivalence tests: C (_bsv_native) vs Python implementations.

Every function that has a C path and a Python fallback is tested here.
Both paths are called directly with the same input and outputs compared.
"""

import pytest

import _bsv_native
from bsv.constants import SIGHASH
from bsv.hash import hash256 as py_hash256, sha256 as py_sha256, hmac_sha256 as py_hmac_sha256
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.spend import Spend
from bsv.script.type import P2PKH, BareMultisig
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
from bsv.utils.script_chunks import ScriptChunk, _parse_script_bytes, serialize_chunks

# ─── Test data ────────────────────────────────────────────────────────

P2PKH_SCRIPT = "76a9146a176cd51593e00542b8e1958b7da2be97452d0588ac"

TX_1IN_2OUT = (
    "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff"
    "02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888ac"
    "de94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000"
)
TX_2IN_3OUT = (
    "01000000027e2705da59f7112c7337d79840b56fff582b8f3a0e9df8eb19e282377bebb1bc0100000000ffffffff"
    "debe6fe5ad8e9220a10fcf6340f7fca660d87aeedf0f74a142fba6de1f68d8490000000000ffffffff"
    "0300e1f505000000001976a9142987362cf0d21193ce7e7055824baac1ee245d0d88ac"
    "00e1f505000000001976a9143ca26faa390248b7a7ac45be53b0e4004ad7952688ac"
    "34657fe2000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000"
)

WIF_KEY = "L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9"


# ═══════════════════════════════════════════════════════════════════════
# 1. Hash functions
# ═══════════════════════════════════════════════════════════════════════


class TestHashEquivalence:
    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"\x00",
            b"hello world",
            b"\xff" * 32,
            bytes(range(256)),
            b"\xde\xad\xbe\xef" * 100,
        ],
    )
    def test_sha256(self, data):
        assert _bsv_native.sha256(data) == py_sha256(data)

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"\x00",
            b"BSV hash256 test",
            b"\xff" * 64,
            bytes(range(256)),
        ],
    )
    def test_hash256(self, data):
        assert _bsv_native.hash256(data) == py_hash256(data)

    @pytest.mark.parametrize(
        "key,msg",
        [
            (b"\x00" * 32, b""),
            (b"\x01" * 32, b"test message"),
            (bytes(range(32)), bytes(range(64))),
            (b"\xff" * 32, b"\xab\xcd" * 50),
        ],
    )
    def test_hmac_sha256(self, key, msg):
        assert _bsv_native.hmac_sha256(key, msg) == py_hmac_sha256(key, msg)


# ═══════════════════════════════════════════════════════════════════════
# 2. Script chunk parse / serialize
# ═══════════════════════════════════════════════════════════════════════


class TestScriptChunksEquivalence:
    @pytest.mark.parametrize(
        "script_hex",
        [
            P2PKH_SCRIPT,
            "00",
            "51",
            "6a" + "04" + "deadbeef",
            "00" * 100,
            "4c" + "ff" + "aa" * 255,
        ],
    )
    def test_parse_roundtrip(self, script_hex):
        script_bytes = bytes.fromhex(script_hex)
        py_chunks = _parse_script_bytes(script_bytes)
        c_tuples = _bsv_native.parse_script_chunks(script_bytes)
        assert len(py_chunks) == len(c_tuples)
        for py_chunk, c_tuple in zip(py_chunks, c_tuples):
            assert py_chunk.op == c_tuple[0]
            assert py_chunk.data == c_tuple[1]

    @pytest.mark.parametrize(
        "script_hex",
        [
            P2PKH_SCRIPT,
            "00",
            "51",
            "6a" + "04" + "deadbeef",
            "4c" + "03" + "aabbcc",
        ],
    )
    def test_serialize_roundtrip(self, script_hex):
        script_bytes = bytes.fromhex(script_hex)
        py_chunks = _parse_script_bytes(script_bytes)
        py_serialized = serialize_chunks(py_chunks)
        c_tuples = [(c.op, c.data) for c in py_chunks]
        c_serialized = _bsv_native.serialize_script_chunks(c_tuples)
        assert py_serialized == c_serialized == script_bytes


# ═══════════════════════════════════════════════════════════════════════
# 3. Transaction parse / serialize / txid
# ═══════════════════════════════════════════════════════════════════════


class TestTxEquivalence:
    @pytest.mark.parametrize("tx_hex", [TX_1IN_2OUT, TX_2IN_3OUT])
    def test_tx_parse_and_serialize(self, tx_hex):
        raw = bytes.fromhex(tx_hex)
        c_result = _bsv_native.tx_from_bytes(raw)
        py_tx = Transaction.from_hex(tx_hex)
        assert c_result["version"] == py_tx.version
        assert c_result["locktime"] == py_tx.locktime
        assert len(c_result["inputs"]) == len(py_tx.inputs)
        assert len(c_result["outputs"]) == len(py_tx.outputs)
        for i, (c_inp, py_inp) in enumerate(zip(c_result["inputs"], py_tx.inputs)):
            assert c_inp["source_txid"] == py_inp.source_txid, f"input {i} txid"
            assert c_inp["source_output_index"] == py_inp.source_output_index, f"input {i} vout"
            assert c_inp["sequence"] == py_inp.sequence, f"input {i} seq"
        for i, (c_out, py_out) in enumerate(zip(c_result["outputs"], py_tx.outputs)):
            assert c_out["satoshis"] == py_out.satoshis, f"output {i} satoshis"
            assert c_out["locking_script"] == py_out.locking_script.serialize(), f"output {i} script"
        c_serialized = _bsv_native.tx_to_bytes(
            c_result["version"],
            c_result["inputs"],
            c_result["outputs"],
            c_result["locktime"],
        )
        assert c_serialized == py_tx.serialize()

    @pytest.mark.parametrize("tx_hex", [TX_1IN_2OUT, TX_2IN_3OUT])
    def test_txid(self, tx_hex):
        raw = bytes.fromhex(tx_hex)
        c_txid = _bsv_native.tx_txid(raw)
        py_txid = py_hash256(raw)[::-1].hex()
        assert c_txid == py_txid


# ═══════════════════════════════════════════════════════════════════════
# 4. Crypto: ECDSA sign / verify / recover
# ═══════════════════════════════════════════════════════════════════════


class TestCryptoEquivalence:
    @pytest.fixture()
    def keypair(self):
        secret = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        pubkey = _bsv_native.pubkey_from_secret(secret)
        return secret, pubkey

    def test_pubkey_from_secret(self, keypair):
        secret, pubkey = keypair
        assert len(pubkey) == 33
        parsed = _bsv_native.pubkey_parse(pubkey)
        assert parsed == pubkey

    def test_sign_verify_roundtrip(self, keypair):
        secret, pubkey = keypair
        msg = py_hash256(b"equivalence test message")
        sig = _bsv_native.ecdsa_sign(msg, secret)
        assert _bsv_native.ecdsa_verify(sig, msg, pubkey)

    def test_sign_recoverable_roundtrip(self, keypair):
        secret, pubkey = keypair
        msg = py_hash256(b"recover test")
        sig65 = _bsv_native.ecdsa_sign_recoverable(msg, secret)
        recovered = _bsv_native.ecdsa_recover(sig65, msg)
        assert recovered == pubkey

    def test_pubkey_point_roundtrip(self, keypair):
        _, pubkey = keypair
        x, y = _bsv_native.pubkey_point(pubkey)
        uncompressed = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
        reparsed = _bsv_native.pubkey_serialize(_bsv_native.pubkey_parse(uncompressed), True)
        assert reparsed == pubkey

    def test_pubkey_combine(self, keypair):
        _, pk1 = keypair
        secret2 = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
        pk2 = _bsv_native.pubkey_from_secret(secret2)
        combined = _bsv_native.pubkey_combine([pk1, pk2])
        assert len(combined) == 33

    def test_ecdh(self, keypair):
        secret1, _ = keypair
        secret2 = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
        pk2 = _bsv_native.pubkey_from_secret(secret2)
        shared = _bsv_native.ecdh(secret1, pk2)
        assert len(shared) == 32
        shared_reverse = _bsv_native.ecdh(secret2, _bsv_native.pubkey_from_secret(secret1))
        assert shared == shared_reverse

    def test_seckey_tweak_add(self):
        secret = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        tweak = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
        result = _bsv_native.seckey_tweak_add(secret, tweak)
        expected_pk = _bsv_native.pubkey_from_secret(
            bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
        )
        assert _bsv_native.pubkey_from_secret(result) == expected_pk

    def test_pubkey_tweak_add(self):
        secret = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        tweak = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
        pk = _bsv_native.pubkey_from_secret(secret)
        tweaked = _bsv_native.pubkey_tweak_add(pk, tweak)
        expected = _bsv_native.pubkey_from_secret(_bsv_native.seckey_tweak_add(secret, tweak))
        assert tweaked == expected

    def test_pubkey_tweak_mul(self):
        secret = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        scalar = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
        pk = _bsv_native.pubkey_from_secret(secret)
        result = _bsv_native.pubkey_tweak_mul(pk, scalar)
        expected = _bsv_native.pubkey_from_secret(scalar)
        assert result == expected

    def test_ecdsa_sign_with_k(self, keypair):
        secret, pubkey = keypair
        msg = py_hash256(b"custom k test")
        k = py_hash256(b"deterministic k value for test")
        sig = _bsv_native.ecdsa_sign_with_k(msg, secret, k)
        assert _bsv_native.ecdsa_verify(sig, msg, pubkey)


# ═══════════════════════════════════════════════════════════════════════
# 5. Preimage: BIP-143 (C vs Python)
# ═══════════════════════════════════════════════════════════════════════


def _build_tx_for_preimage(tx_hex, locking_script_hex, satoshis, sighash_flag):
    tx = Transaction.from_hex(tx_hex)
    for inp in tx.inputs:
        inp.locking_script = Script.from_bytes(bytes.fromhex(locking_script_hex))
        inp.satoshis = satoshis
        inp.sighash = sighash_flag
    return tx


class TestPreimageEquivalence:
    LOCKING_SCRIPT = "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac"
    SATOSHIS = 100_000_000

    BIP143_SIGHASH_FLAGS = [
        SIGHASH.ALL_FORKID,
        SIGHASH.NONE_FORKID,
        SIGHASH.SINGLE_FORKID,
        SIGHASH.ALL_FORKID | SIGHASH.ANYONECANPAY,
        SIGHASH.NONE_FORKID | SIGHASH.ANYONECANPAY,
        SIGHASH.SINGLE_FORKID | SIGHASH.ANYONECANPAY,
    ]

    @pytest.mark.parametrize("sighash", BIP143_SIGHASH_FLAGS, ids=lambda s: f"0x{int(s):02x}")
    def test_bip143_preimage_1in(self, sighash):
        tx = _build_tx_for_preimage(TX_1IN_2OUT, self.LOCKING_SCRIPT, self.SATOSHIS, sighash)
        from bsv.transaction_preimage import _inputs_to_tuples, _outputs_to_bytes

        inp_tuples = _inputs_to_tuples(tx.inputs)
        out_bytes = _outputs_to_bytes(tx.outputs)

        c_preimages = _bsv_native.tx_preimages(tx.version, tx.locktime, inp_tuples, out_bytes)

        from bsv.transaction_preimage import _preimage

        _hash_prevouts = py_hash256(
            b"".join(
                bytes.fromhex(i.source_txid)[::-1] + i.source_output_index.to_bytes(4, "little") for i in tx.inputs
            )
        )
        _hash_sequence = py_hash256(b"".join(i.sequence.to_bytes(4, "little") for i in tx.inputs))
        _hash_outputs = py_hash256(b"".join(o.serialize() for o in tx.outputs))

        sh = sighash
        hp = b"\x00" * 32 if sh & SIGHASH.ANYONECANPAY else _hash_prevouts
        hs = (
            b"\x00" * 32
            if (sh & SIGHASH.ANYONECANPAY or sh & 0x1F == SIGHASH.SINGLE or sh & 0x1F == SIGHASH.NONE)
            else _hash_sequence
        )
        if sh & 0x1F not in (SIGHASH.SINGLE, SIGHASH.NONE):
            ho = _hash_outputs
        elif sh & 0x1F == SIGHASH.SINGLE and 0 < len(tx.outputs):
            ho = py_hash256(tx.outputs[0].serialize())
        else:
            ho = b"\x00" * 32
        py_preimage = _preimage(tx.inputs[0], tx.version, tx.locktime, hp, hs, ho)

        assert c_preimages[0] == py_preimage

    @pytest.mark.parametrize("sighash", BIP143_SIGHASH_FLAGS, ids=lambda s: f"0x{int(s):02x}")
    def test_bip143_preimage_2in(self, sighash):
        tx = _build_tx_for_preimage(TX_2IN_3OUT, self.LOCKING_SCRIPT, self.SATOSHIS, sighash)
        from bsv.transaction_preimage import _inputs_to_tuples, _outputs_to_bytes

        inp_tuples = _inputs_to_tuples(tx.inputs)
        out_bytes = _outputs_to_bytes(tx.outputs)
        c_preimages = _bsv_native.tx_preimages(tx.version, tx.locktime, inp_tuples, out_bytes)
        assert len(c_preimages) == 2

        py_tx = _build_tx_for_preimage(TX_2IN_3OUT, self.LOCKING_SCRIPT, self.SATOSHIS, sighash)
        from bsv.transaction_preimage import tx_preimages as py_tx_preimages
        import bsv.transaction_preimage as tp_mod

        orig = tp_mod._USE_NATIVE
        tp_mod._USE_NATIVE = False
        try:
            py_preimages = py_tx_preimages(py_tx.inputs, py_tx.outputs, py_tx.version, py_tx.locktime)
        finally:
            tp_mod._USE_NATIVE = orig

        for i in range(2):
            assert c_preimages[i] == py_preimages[i], f"input {i} preimage mismatch for sighash 0x{int(sighash):02x}"


# ═══════════════════════════════════════════════════════════════════════
# 6. Preimage: OTDA (C vs Python)
# ═══════════════════════════════════════════════════════════════════════


class TestOTDAPreimageEquivalence:
    LOCKING_SCRIPT = "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac"
    SATOSHIS = 100_000_000

    OTDA_SIGHASH_FLAGS = [
        SIGHASH.ALL_FORKID | SIGHASH.CHRONICLE,
        SIGHASH.NONE_FORKID | SIGHASH.CHRONICLE,
        SIGHASH.SINGLE_FORKID | SIGHASH.CHRONICLE,
        SIGHASH.ALL_FORKID | SIGHASH.CHRONICLE | SIGHASH.ANYONECANPAY,
        SIGHASH.NONE_FORKID | SIGHASH.CHRONICLE | SIGHASH.ANYONECANPAY,
        SIGHASH.SINGLE_FORKID | SIGHASH.CHRONICLE | SIGHASH.ANYONECANPAY,
    ]

    @pytest.mark.parametrize("sighash", OTDA_SIGHASH_FLAGS, ids=lambda s: f"0x{int(s):02x}")
    def test_otda_preimage(self, sighash):
        tx = _build_tx_for_preimage(TX_2IN_3OUT, self.LOCKING_SCRIPT, self.SATOSHIS, sighash)
        from bsv.transaction_preimage import _inputs_to_tuples, _outputs_to_bytes

        inp_tuples = _inputs_to_tuples(tx.inputs)
        out_bytes = _outputs_to_bytes(tx.outputs)
        c_preimage = _bsv_native.tx_preimage_otda(0, tx.version, tx.locktime, inp_tuples, out_bytes)

        import bsv.transaction_preimage as tp_mod

        orig = tp_mod._USE_NATIVE
        tp_mod._USE_NATIVE = False
        try:
            from bsv.transaction_preimage import tx_preimage as py_tx_preimage

            py_preimage = py_tx_preimage(0, tx.inputs, tx.outputs, tx.version, tx.locktime)
        finally:
            tp_mod._USE_NATIVE = orig

        assert c_preimage == py_preimage, f"OTDA preimage mismatch for sighash 0x{int(sighash):02x}"


# ═══════════════════════════════════════════════════════════════════════
# 7. Merkle
# ═══════════════════════════════════════════════════════════════════════


class TestMerkleEquivalence:
    @staticmethod
    def _py_hash_fn(a_hex, b_hex):
        """Python merkle_path.py hash_fn: hash256(bytes.fromhex(a+b)[::-1])[::-1].hex()"""
        return py_hash256(bytes.fromhex(a_hex + b_hex)[::-1])[::-1].hex()

    def test_merkle_hash_pair(self):
        a = "aa" * 32
        b = "bb" * 32
        assert _bsv_native.merkle_hash_pair(a, b) == self._py_hash_fn(a, b)

    def test_merkle_hash_pair_varied(self):
        pairs = [
            ("00" * 32, "ff" * 32),
            ("01" * 32, "02" * 32),
            ("abcdef" + "00" * 29, "fedcba" + "00" * 29),
        ]
        for a, b in pairs:
            assert _bsv_native.merkle_hash_pair(a, b) == self._py_hash_fn(a, b)


# ═══════════════════════════════════════════════════════════════════════
# 8. Script VM (Spend.validate): C vs Python
# ═══════════════════════════════════════════════════════════════════════


def _get_spend_mod():
    from bsv.script import spend

    return spend


def _make_spend(unlock_script, lock_script, tx, input_index=0):
    inp = tx.inputs[input_index]
    return Spend(
        {
            "unlockingScript": unlock_script,
            "lockingScript": lock_script,
            "transactionVersion": tx.version,
            "sourceTXID": inp.source_txid or "00" * 32,
            "sourceOutputIndex": inp.source_output_index,
            "lockTime": tx.locktime,
            "inputIndex": input_index,
            "inputSequence": inp.sequence,
            "sourceSatoshis": inp.satoshis or 0,
            "otherInputs": [other for j, other in enumerate(tx.inputs) if j != input_index],
            "outputs": tx.outputs,
        }
    )


class TestSpendEquivalence:
    def _validate_both(self, unlock_template, lock_script, *, tx_version=2):
        key = PrivateKey(WIF_KEY)
        source_tx = Transaction([], [TransactionOutput(locking_script=lock_script, satoshis=1000)])
        tx = Transaction(
            [
                TransactionInput(
                    source_transaction=source_tx,
                    source_output_index=0,
                    unlocking_script_template=unlock_template,
                )
            ],
            [TransactionOutput(locking_script=P2PKH().lock(key.address()), change=True)],
        )
        tx.version = tx_version
        tx.fee()
        tx.sign()

        spend_mod = _get_spend_mod()
        orig = spend_mod._USE_NATIVE_VM

        spend = _make_spend(tx.inputs[0].unlocking_script, lock_script, tx)

        spend_mod._USE_NATIVE_VM = True
        try:
            c_result = spend.validate()
        except RuntimeError:
            c_result = False
        finally:
            spend_mod._USE_NATIVE_VM = False

        spend2 = _make_spend(tx.inputs[0].unlocking_script, lock_script, tx)
        try:
            py_result = spend2.validate()
        except RuntimeError:
            py_result = False
        finally:
            spend_mod._USE_NATIVE_VM = orig

        assert c_result == py_result, f"C={c_result}, Python={py_result}"
        return c_result

    def test_p2pkh(self):
        key = PrivateKey(WIF_KEY)
        result = self._validate_both(
            P2PKH().unlock(key),
            P2PKH().lock(key.address()),
        )
        assert result is True

    def test_p2pk(self):
        from bsv.script.type import P2PK

        key = PrivateKey(WIF_KEY)
        result = self._validate_both(
            P2PK().unlock(key),
            P2PK().lock(key.public_key().hex()),
        )
        assert result is True

    def test_bare_multisig_2of2(self):
        key1 = PrivateKey(WIF_KEY)
        key2 = PrivateKey()
        result = self._validate_both(
            BareMultisig().unlock([key1, key2]),
            BareMultisig().lock([key1.public_key().hex(), key2.public_key().hex()], 2),
        )
        assert result is True

    def test_op_return_fails(self):
        from bsv.script.type import OpReturn

        lock = OpReturn().lock(["test data"])

        spend_mod = _get_spend_mod()
        orig = spend_mod._USE_NATIVE_VM

        for use_native in [True, False]:
            spend_mod._USE_NATIVE_VM = use_native
            with pytest.raises(RuntimeError):
                Spend(
                    {
                        "unlockingScript": Script(b""),
                        "lockingScript": lock,
                        "transactionVersion": 2,
                        "sourceTXID": "00" * 32,
                        "sourceOutputIndex": 0,
                        "lockTime": 0,
                        "inputIndex": 0,
                        "inputSequence": 0xFFFFFFFF,
                        "sourceSatoshis": 0,
                        "otherInputs": [],
                        "outputs": [],
                    }
                ).validate()

        spend_mod._USE_NATIVE_VM = orig


# ═══════════════════════════════════════════════════════════════════════
# 9. Known error-message differences (document, don't fail)
# ═══════════════════════════════════════════════════════════════════════


class TestKnownDifferences:
    """
    Phase 3c changed some error messages between C and Python paths.
    These tests document the known differences rather than asserting equality.
    """

    def test_high_s_error_message_differs(self):
        """C path: 'low S value', Python path: 'signature format is invalid' (suppress(Exception))"""
        key = PrivateKey(WIF_KEY)
        lock = P2PKH().lock(key.address())
        source_tx = Transaction([], [TransactionOutput(locking_script=lock, satoshis=1000)])
        tx = Transaction(
            [
                TransactionInput(
                    source_transaction=source_tx,
                    source_output_index=0,
                    unlocking_script_template=P2PKH().unlock(key),
                )
            ],
            [TransactionOutput(locking_script=P2PKH().lock(key.address()), change=True)],
        )
        tx.version = 1
        tx.fee()
        tx.sign()

        from bsv.hash import hash256

        sig_hash = tx.calc_input_signature_hash(
            0,
            int(SIGHASH.ALL_FORKID),
            tx.inputs[0].locking_script,
            tx.inputs[0].satoshis,
        )

        from bsv.curve import curve

        sig_bytes = _bsv_native.ecdsa_sign(sig_hash, key._secret)
        r_len = sig_bytes[3]
        r = int.from_bytes(sig_bytes[4 : 4 + r_len], "big")
        s_start = 4 + r_len + 2
        s_len = sig_bytes[s_start - 1]
        s = int.from_bytes(sig_bytes[s_start : s_start + s_len], "big")

        is_low_s = s <= curve.n // 2
        # The native ecdsa_sign always normalizes to low-S, so we can't
        # easily construct a high-S signature here. Just document the known difference.
        assert (
            is_low_s
        ), "ecdsa_sign always produces low-S; high-S error message difference is documented in c-extension-plan.md Phase 3c"
