"""
Benchmarks: C (_bsv_native) vs Python fallback performance.

Measures every dispatch point that has both C and Python paths.
Run: pytest tests/bsv/native/test_benchmark_native.py --benchmark-only -v
"""

import pytest

import _bsv_native
from bsv.constants import SIGHASH
from bsv.hash import hash256 as py_hash256, sha256 as py_sha256
from bsv.keys import PrivateKey
from bsv.merkle_path import MerklePath
from bsv.script.script import Script
from bsv.script.spend import Spend
from bsv.script.type import P2PKH
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
from bsv.utils.script_chunks import _parse_script_bytes, serialize_chunks

WIF_KEY = "L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9"

TX_1IN_2OUT = (
    "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff"
    "02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888ac"
    "de94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000"
)

P2PKH_SCRIPT_HEX = "76a9146a176cd51593e00542b8e1958b7da2be97452d0588ac"


def _build_large_tx(num_inputs, num_outputs):
    dummy_txid = "93a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651"
    from bsv.utils import Writer

    w = Writer()
    w.write_uint32_le(1)
    w.write_var_int_num(num_inputs)
    for i in range(num_inputs):
        w.write_bytes(bytes.fromhex(dummy_txid)[::-1])
        w.write_uint32_le(i)
        unlock = b"\x48" + b"\x30" * 72
        w.write_var_int_num(len(unlock))
        w.write_bytes(unlock)
        w.write_uint32_le(0xFFFFFFFF)
    w.write_var_int_num(num_outputs)
    for _ in range(num_outputs):
        w.write_uint64_le(50000)
        script = bytes.fromhex(P2PKH_SCRIPT_HEX)
        w.write_var_int_num(len(script))
        w.write_bytes(script)
    w.write_uint32_le(0)
    return w.to_bytes()


def _build_merkle_path(height):
    import os

    txid = os.urandom(32).hex()
    path = []
    for h in range(height):
        sibling_offset = 1 if h == 0 else (0 >> h) ^ 1
        pair_hash = os.urandom(32).hex()
        if h == 0:
            path.append(
                [
                    {"offset": 0, "hash_str": txid},
                    {"offset": 1, "hash_str": pair_hash},
                ]
            )
        else:
            offset = (0 >> h) ^ 1
            path.append([{"offset": offset, "hash_str": pair_hash}])
    mp = MerklePath.__new__(MerklePath)
    mp.block_height = 800000
    mp.path = path
    return mp, txid


def _build_p2pkh_spend():
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
    tx.fee()
    tx.sign()
    return tx, lock


# ═══════════════════════════════════════════════════════════════════════
# 1. Hash functions
# ═══════════════════════════════════════════════════════════════════════


class TestBenchHash:
    DATA_32 = b"\xab\xcd" * 16
    DATA_1K = b"\xfe" * 1024

    def test_sha256_c(self, benchmark):
        benchmark(_bsv_native.sha256, self.DATA_32)

    def test_sha256_python(self, benchmark):
        benchmark(py_sha256, self.DATA_32)

    def test_hash256_c(self, benchmark):
        benchmark(_bsv_native.hash256, self.DATA_32)

    def test_hash256_python(self, benchmark):
        benchmark(py_hash256, self.DATA_32)

    def test_hash256_1k_c(self, benchmark):
        benchmark(_bsv_native.hash256, self.DATA_1K)

    def test_hash256_1k_python(self, benchmark):
        benchmark(py_hash256, self.DATA_1K)


# ═══════════════════════════════════════════════════════════════════════
# 2. Script chunk parse / serialize
# ═══════════════════════════════════════════════════════════════════════


class TestBenchScriptChunks:
    P2PKH_BYTES = bytes.fromhex(P2PKH_SCRIPT_HEX)
    LARGE_SCRIPT = bytes.fromhex("6a" + "4c" + "ff" + "aa" * 255) * 10

    def test_parse_p2pkh_c(self, benchmark):
        benchmark(_bsv_native.parse_script_chunks, self.P2PKH_BYTES)

    def test_parse_p2pkh_python(self, benchmark):
        benchmark(_parse_script_bytes, self.P2PKH_BYTES)

    def test_parse_large_c(self, benchmark):
        benchmark(_bsv_native.parse_script_chunks, self.LARGE_SCRIPT)

    def test_parse_large_python(self, benchmark):
        benchmark(_parse_script_bytes, self.LARGE_SCRIPT)

    def test_serialize_p2pkh_c(self, benchmark):
        chunks = _bsv_native.parse_script_chunks(self.P2PKH_BYTES)
        benchmark(_bsv_native.serialize_script_chunks, chunks)

    def test_serialize_p2pkh_python(self, benchmark):
        chunks = _parse_script_bytes(self.P2PKH_BYTES)
        benchmark(serialize_chunks, chunks)


# ═══════════════════════════════════════════════════════════════════════
# 3. Transaction parse / serialize / txid
# ═══════════════════════════════════════════════════════════════════════


class TestBenchTx:
    TX_SMALL = bytes.fromhex(TX_1IN_2OUT)
    TX_100IN = _build_large_tx(100, 2)

    def test_tx_parse_1in_c(self, benchmark):
        benchmark(_bsv_native.tx_from_bytes, self.TX_SMALL)

    def test_tx_parse_1in_python(self, benchmark):
        benchmark(Transaction.from_hex, TX_1IN_2OUT)

    def test_tx_parse_100in_c(self, benchmark):
        benchmark(_bsv_native.tx_from_bytes, self.TX_100IN)

    def test_tx_parse_100in_python(self, benchmark):
        hex_data = self.TX_100IN.hex()
        benchmark(Transaction.from_hex, hex_data)

    def test_txid_c(self, benchmark):
        benchmark(_bsv_native.tx_txid, self.TX_SMALL)

    def test_txid_python(self, benchmark):
        def _py_txid():
            return py_hash256(self.TX_SMALL)[::-1].hex()

        benchmark(_py_txid)

    def test_tx_serialize_c(self, benchmark):
        parsed = _bsv_native.tx_from_bytes(self.TX_SMALL)
        benchmark(
            _bsv_native.tx_to_bytes,
            parsed["version"],
            parsed["inputs"],
            parsed["outputs"],
            parsed["locktime"],
        )

    def test_tx_serialize_python(self, benchmark):
        tx = Transaction.from_hex(TX_1IN_2OUT)
        benchmark(tx.serialize)


# ═══════════════════════════════════════════════════════════════════════
# 4. ECDSA sign / verify
# ═══════════════════════════════════════════════════════════════════════


class TestBenchCrypto:
    SECRET = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
    PUBKEY = _bsv_native.pubkey_from_secret(SECRET)
    MSG = py_hash256(b"benchmark message")
    SIG = _bsv_native.ecdsa_sign(MSG, SECRET)

    def test_ecdsa_sign_c(self, benchmark):
        benchmark(_bsv_native.ecdsa_sign, self.MSG, self.SECRET)

    def test_ecdsa_verify_c(self, benchmark):
        benchmark(_bsv_native.ecdsa_verify, self.SIG, self.MSG, self.PUBKEY)

    def test_pubkey_from_secret_c(self, benchmark):
        benchmark(_bsv_native.pubkey_from_secret, self.SECRET)


# ═══════════════════════════════════════════════════════════════════════
# 5. Preimage (BIP-143)
# ═══════════════════════════════════════════════════════════════════════


class TestBenchPreimage:
    @staticmethod
    def _setup_preimage():
        tx = Transaction.from_hex(TX_1IN_2OUT)
        ls = "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac"
        for inp in tx.inputs:
            inp.locking_script = Script.from_bytes(bytes.fromhex(ls))
            inp.satoshis = 100_000_000
            inp.sighash = SIGHASH.ALL_FORKID
        return tx

    def test_preimage_c(self, benchmark):
        tx = self._setup_preimage()
        from bsv.transaction_preimage import _inputs_to_tuples, _outputs_to_bytes

        inp_tuples = _inputs_to_tuples(tx.inputs)
        out_bytes = _outputs_to_bytes(tx.outputs)
        benchmark(
            _bsv_native.tx_preimages,
            tx.version,
            tx.locktime,
            inp_tuples,
            out_bytes,
        )

    def test_preimage_python(self, benchmark):
        tx = self._setup_preimage()
        import bsv.transaction_preimage as tp_mod

        orig = tp_mod._USE_NATIVE
        tp_mod._USE_NATIVE = False
        try:
            benchmark(
                tp_mod.tx_preimages,
                tx.inputs,
                tx.outputs,
                tx.version,
                tx.locktime,
            )
        finally:
            tp_mod._USE_NATIVE = orig


# ═══════════════════════════════════════════════════════════════════════
# 6. Merkle root computation
# ═══════════════════════════════════════════════════════════════════════


class TestBenchMerkle:
    def test_merkle_hash_pair_c(self, benchmark):
        a, b = "aa" * 32, "bb" * 32
        benchmark(_bsv_native.merkle_hash_pair, a, b)

    def test_merkle_hash_pair_python(self, benchmark):
        a, b = "aa" * 32, "bb" * 32

        def _py():
            return py_hash256(bytes.fromhex(a + b)[::-1])[::-1].hex()

        benchmark(_py)

    def test_merkle_root_h10_c(self, benchmark):
        import bsv.merkle_path as mp_mod

        mp, txid = _build_merkle_path(10)
        orig = mp_mod._USE_NATIVE
        mp_mod._USE_NATIVE = True
        try:
            benchmark(mp.compute_root, txid)
        finally:
            mp_mod._USE_NATIVE = orig

    def test_merkle_root_h10_python(self, benchmark):
        import bsv.merkle_path as mp_mod

        mp, txid = _build_merkle_path(10)
        orig = mp_mod._USE_NATIVE
        mp_mod._USE_NATIVE = False
        try:
            benchmark(mp.compute_root, txid)
        finally:
            mp_mod._USE_NATIVE = orig


# ═══════════════════════════════════════════════════════════════════════
# 7. Spend VM (P2PKH validate)
# ═══════════════════════════════════════════════════════════════════════


class TestBenchSpend:
    @staticmethod
    def _setup():
        return _build_p2pkh_spend()

    def test_spend_validate_c(self, benchmark):
        tx, lock = self._setup()
        from bsv.script import spend as spend_mod

        orig = spend_mod._USE_NATIVE_VM

        def run():
            spend_mod._USE_NATIVE_VM = True
            s = Spend(
                {
                    "unlockingScript": tx.inputs[0].unlocking_script,
                    "lockingScript": lock,
                    "transactionVersion": tx.version,
                    "sourceTXID": tx.inputs[0].source_txid or "00" * 32,
                    "sourceOutputIndex": tx.inputs[0].source_output_index,
                    "lockTime": tx.locktime,
                    "inputIndex": 0,
                    "inputSequence": tx.inputs[0].sequence,
                    "sourceSatoshis": tx.inputs[0].satoshis or 0,
                    "otherInputs": [],
                    "outputs": tx.outputs,
                }
            )
            return s.validate()

        try:
            benchmark(run)
        finally:
            spend_mod._USE_NATIVE_VM = orig

    def test_spend_validate_python(self, benchmark):
        tx, lock = self._setup()
        from bsv.script import spend as spend_mod

        orig = spend_mod._USE_NATIVE_VM

        def run():
            spend_mod._USE_NATIVE_VM = False
            s = Spend(
                {
                    "unlockingScript": tx.inputs[0].unlocking_script,
                    "lockingScript": lock,
                    "transactionVersion": tx.version,
                    "sourceTXID": tx.inputs[0].source_txid or "00" * 32,
                    "sourceOutputIndex": tx.inputs[0].source_output_index,
                    "lockTime": tx.locktime,
                    "inputIndex": 0,
                    "inputSequence": tx.inputs[0].sequence,
                    "sourceSatoshis": tx.inputs[0].satoshis or 0,
                    "otherInputs": [],
                    "outputs": tx.outputs,
                }
            )
            return s.validate()

        try:
            benchmark(run)
        finally:
            spend_mod._USE_NATIVE_VM = orig
