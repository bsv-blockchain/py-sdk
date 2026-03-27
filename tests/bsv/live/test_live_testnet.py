"""Live testnet broadcast tests.

Builds real transactions, validates them via Spend, and broadcasts to BSV testnet.
All test txs are funded from a single fan-out tx that splits one UTXO into many.

Requires: FUNDED_TESTNET_WIF env var set to a funded testnet private key WIF.
Run with: pytest tests/bsv/live/test_live_testnet.py -v -m testnet
"""

import pytest

from bsv.constants import SIGHASH
from bsv.fee_models import SatoshisPerKilobyte
from bsv.script.script import Script
from bsv.script.type import P2PKH, P2PK, BareMultisig
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.utils import encode_pushdata

from .conftest import (
    FUNDED_TESTNET_WIF,
    UTXOManager,
    custom_unlock,
    p2pkh_lock_with_prefix,
    validate_all_inputs,
)


# ---------------------------------------------------------------------------
# Skip entire module if no funded key
# ---------------------------------------------------------------------------

pytestmark = [
    pytest.mark.testnet,
    pytest.mark.skipif(not FUNDED_TESTNET_WIF, reason="FUNDED_TESTNET_WIF not set"),
]


# ---------------------------------------------------------------------------
# Sighash flag sets
# ---------------------------------------------------------------------------

FORKID_SIGHASHES = [
    SIGHASH.ALL_FORKID,
    SIGHASH.NONE_FORKID,
    SIGHASH.SINGLE_FORKID,
    SIGHASH.ALL_ANYONECANPAY_FORKID,
    SIGHASH.NONE_ANYONECANPAY_FORKID,
    SIGHASH.SINGLE_ANYONECANPAY_FORKID,
]

CHRONICLE_SIGHASHES = [
    SIGHASH.ALL_FORKID_CHRONICLE,
    SIGHASH.NONE_FORKID_CHRONICLE,
    SIGHASH.SINGLE_FORKID_CHRONICLE,
    SIGHASH.ALL_ANYONECANPAY_FORKID_CHRONICLE,
    SIGHASH.NONE_ANYONECANPAY_FORKID_CHRONICLE,
    SIGHASH.SINGLE_ANYONECANPAY_FORKID_CHRONICLE,
]

ALL_SIGHASHES = FORKID_SIGHASHES + CHRONICLE_SIGHASHES
TX_VERSIONS = [1, 2]

# All broadcastable sighash x version combos
SIGHASH_VERSION_COMBOS = [
    pytest.param(sh, v, id=f"{sh.name}_v{v}")
    for sh in ALL_SIGHASHES
    for v in TX_VERSIONS
]

# Representative subset for opcode tests (BIP143 v1 + OTDA v2)
OPCODE_SIGHASH_VERSIONS = [
    pytest.param(SIGHASH.ALL_FORKID, 1, id="BIP143_v1"),
    pytest.param(SIGHASH.ALL_FORKID_CHRONICLE, 2, id="OTDA_v2"),
]

FEE_MODEL = SatoshisPerKilobyte(500)


# ---------------------------------------------------------------------------
# Helper: build a testnet tx from a UTXO
# ---------------------------------------------------------------------------


def build_testnet_tx(
    source_tx: Transaction,
    source_vout: int,
    locking_script: Script,
    unlock_template,
    change_key,
    sighash: int = SIGHASH.ALL_FORKID,
    tx_version: int = 1,
) -> Transaction:
    """Build a transaction spending a real UTXO, with fee calculation and change."""
    p2pkh = P2PKH()
    inp = TransactionInput(
        source_transaction=source_tx,
        source_output_index=source_vout,
        unlocking_script_template=unlock_template,
        sequence=0xFFFFFFFF,
        sighash=SIGHASH(sighash),
    )
    outputs = [
        TransactionOutput(
            locking_script=p2pkh.lock(change_key.address()),
            change=True,
        ),
    ]
    tx = Transaction([inp], outputs, version=tx_version)
    tx.fee(FEE_MODEL)
    tx.sign(bypass=False)
    validate_all_inputs(tx)
    return tx


# ---------------------------------------------------------------------------
# Count total tests to size the fan-out
# ---------------------------------------------------------------------------

# P2PKH: 24, P2PK: 24, Multisig: 24, Chronicle opcodes: 20, Standard opcodes: ~25
TOTAL_TEST_UTXOS = 130  # with some buffer


# ---------------------------------------------------------------------------
# Session-scoped UTXO manager fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
async def utxo_mgr(funded_key, testnet_broadcaster):
    """Fan-out the funded UTXO into individual test UTXOs."""
    mgr = UTXOManager(funded_key, testnet_broadcaster)
    await mgr.fan_out(TOTAL_TEST_UTXOS, satoshis_each=3_000)
    return mgr


# ---------------------------------------------------------------------------
# P2PKH sighash matrix
# ---------------------------------------------------------------------------


class TestTestnetP2PKH:
    """P2PKH transactions across all sighash flags on testnet."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSION_COMBOS)
    async def test_p2pkh(self, funded_key, utxo_mgr, sighash, tx_version):
        p2pkh = P2PKH()
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(
            source_tx, vout,
            p2pkh.lock(funded_key.address()),
            p2pkh.unlock(funded_key),
            funded_key,
            sighash=sighash,
            tx_version=tx_version,
        )
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"


# ---------------------------------------------------------------------------
# P2PK sighash matrix
# ---------------------------------------------------------------------------


class TestTestnetP2PK:
    """P2PK transactions across all sighash flags on testnet."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSION_COMBOS)
    async def test_p2pk(self, funded_key, utxo_mgr, sighash, tx_version):
        p2pk = P2PK()
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(
            source_tx, vout,
            p2pk.lock(funded_key.public_key().serialize()),
            p2pk.unlock(funded_key),
            funded_key,
            sighash=sighash,
            tx_version=tx_version,
        )
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"


# ---------------------------------------------------------------------------
# Multisig sighash matrix
# ---------------------------------------------------------------------------


class TestTestnetMultisig:
    """2-of-3 BareMultisig across all sighash flags on testnet."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSION_COMBOS)
    async def test_multisig_2of3(self, funded_key, utxo_mgr, sighash, tx_version):
        from bsv.keys import PrivateKey

        # Generate extra keys for multisig (only funded_key signs)
        pk2 = PrivateKey("L32Mf2qU7BLmPmnbs943EYWRv4EUpqnFxkViinPMYesxWLnL6DTA")
        pk3 = PrivateKey("L1DkuXRTu3cGZAmJCDw2TWAoEaRKesq2sZUGzUmbYExgDwhQWe5T")

        multisig = BareMultisig()
        pubkeys = [
            funded_key.public_key().serialize(),
            pk2.public_key().serialize(),
            pk3.public_key().serialize(),
        ]
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(
            source_tx, vout,
            multisig.lock(pubkeys, threshold=2),
            multisig.unlock([funded_key, pk2]),
            funded_key,
            sighash=sighash,
            tx_version=tx_version,
        )
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"


# ---------------------------------------------------------------------------
# Chronicle opcodes
# ---------------------------------------------------------------------------


class TestTestnetChronicleOpcodes:
    """Chronicle opcodes in real testnet transactions."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_ver(self, funded_key, utxo_mgr, sighash, tx_version):
        expected_ver = str(tx_version)
        lock = p2pkh_lock_with_prefix(f"OP_VER OP_{expected_ver} OP_NUMEQUALVERIFY", funded_key)
        unlock = custom_unlock(funded_key)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_2mul(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_4 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_2")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_2div(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_2DIV OP_5 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_10")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_substr(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_SUBSTR 6263 OP_EQUALVERIFY", funded_key)
        data = Script(
            encode_pushdata(bytes.fromhex("6162636465"))
            + Script.from_asm("OP_1 OP_2").serialize()
        )
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_left(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_LEFT 6162 OP_EQUALVERIFY", funded_key)
        data = Script(
            encode_pushdata(bytes.fromhex("6162636465"))
            + Script.from_asm("OP_2").serialize()
        )
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_right(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_RIGHT 6465 OP_EQUALVERIFY", funded_key)
        data = Script(
            encode_pushdata(bytes.fromhex("6162636465"))
            + Script.from_asm("OP_2").serialize()
        )
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_lshiftnum(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_LSHIFTNUM OP_8 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_1 OP_3")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_rshiftnum(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_RSHIFTNUM OP_2 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_8 OP_2")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_verif(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_VERIF", funded_key)
        lock = Script(
            lock.serialize()
            + Script.from_asm("OP_ELSE OP_FALSE OP_ENDIF").serialize()
        )
        ver_bytes = tx_version.to_bytes(4, "little")
        data = Script(encode_pushdata(ver_bytes))
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"


# ---------------------------------------------------------------------------
# Standard opcodes (representative subset)
# ---------------------------------------------------------------------------


class TestTestnetStandardOpcodes:
    """Representative standard opcodes on testnet."""

    @pytest.mark.asyncio
    async def test_add(self, funded_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_ADD OP_7 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_3 OP_4")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_sub(self, funded_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_SUB OP_4 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_7 OP_3")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_mul(self, funded_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_MUL OP_12 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_3 OP_4")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_cat(self, funded_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_CAT 61626364 OP_EQUALVERIFY", funded_key)
        data = Script(encode_pushdata(b"\x61\x62") + encode_pushdata(b"\x63\x64"))
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_hash160(self, funded_key, utxo_mgr):
        from bsv.hash import hash160

        data_bytes = b"hello"
        expected = hash160(data_bytes)
        lock = p2pkh_lock_with_prefix(
            f"OP_HASH160 {expected.hex()} OP_EQUALVERIFY", funded_key
        )
        data = Script(encode_pushdata(data_bytes))
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_if_else(self, funded_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix(
            "OP_IF OP_5 OP_ELSE OP_6 OP_ENDIF OP_5 OP_NUMEQUALVERIFY", funded_key
        )
        data = Script.from_asm("OP_TRUE")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_checksigverify(self, funded_key, utxo_mgr):
        from bsv.constants import OpCode
        from bsv.hash import hash160

        pkh = hash160(funded_key.public_key().serialize())
        lock = Script(
            OpCode.OP_DUP
            + OpCode.OP_HASH160
            + encode_pushdata(pkh)
            + OpCode.OP_EQUALVERIFY
            + OpCode.OP_CHECKSIGVERIFY
            + OpCode.OP_TRUE
        )
        unlock = custom_unlock(funded_key)
        source_tx, vout, _ = utxo_mgr.take_utxo()
        tx = build_testnet_tx(source_tx, vout, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


class TestTestnetSummary:
    """Print broadcast summary at the end."""

    @pytest.mark.asyncio
    async def test_summary(self, utxo_mgr):
        remaining = len(utxo_mgr.utxos)
        print(f"\n{'='*60}")
        print(f"Testnet broadcast summary:")
        print(f"  Total broadcasts: {utxo_mgr.broadcast_count}")
        print(f"  Remaining UTXOs: {remaining}")
        print(f"{'='*60}")
        assert utxo_mgr.broadcast_count > 0
