"""Live mainnet broadcast tests.

Builds real transactions, validates them via Spend, and broadcasts to BSV mainnet.
All test txs are funded from a single fan-out tx that splits one UTXO into many.

Requires: FUNDED_MAINNET_WIF env var set to a funded mainnet private key WIF.
Run with: pytest tests/bsv/live/test_live_mainnet.py -v -m mainnet
"""

import pytest
import pytest_asyncio

from bsv.constants import SIGHASH
from bsv.script.script import Script
from bsv.script.type import P2PK, P2PKH, BareMultisig
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.utils import encode_pushdata

from .conftest import (
    FUNDED_MAINNET_WIF,
    UTXO_POOL_MAINNET_FILE,
    WOC_API_MAINNET,
    WOC_EXPLORER_MAINNET_TX,
    UTXOManager,
    custom_unlock,
    p2pkh_lock_with_prefix,
    validate_all_inputs,
)
from .live_tx_helpers import (
    CROSS_VERSION_COMBOS,
    FEE_MODEL,
    OPCODE_SIGHASH_VERSIONS,
    SIGHASH_VERSION_COMBOS,
    TOTAL_TEST_UTXOS,
)
from .live_tx_helpers import (
    build_live_tx as build_mainnet_tx,
)
from .live_tx_helpers import (
    build_two_step_live_tx as build_two_step_mainnet_tx,
)

# ---------------------------------------------------------------------------
# Skip entire module if no funded key
# ---------------------------------------------------------------------------

pytestmark = [
    pytest.mark.mainnet,
    pytest.mark.skipif(not FUNDED_MAINNET_WIF, reason="FUNDED_MAINNET_WIF not set"),
]


# ---------------------------------------------------------------------------
# Session-scoped UTXO manager fixture
# ---------------------------------------------------------------------------


# Module-level cache for the UTXO manager (initialized once on first use)
_utxo_mgr_cache: UTXOManager | None = None


@pytest_asyncio.fixture
async def utxo_mgr(funded_mainnet_key, mainnet_broadcaster):
    """Ensure UTXOs are available, loading from disk or fanning out as needed."""
    global _utxo_mgr_cache
    if _utxo_mgr_cache is None:
        mgr = UTXOManager(
            funded_mainnet_key,
            mainnet_broadcaster,
            woc_api_base=WOC_API_MAINNET,
            pool_file=UTXO_POOL_MAINNET_FILE,
            explorer_tx_base=WOC_EXPLORER_MAINNET_TX,
            network_label="mainnet",
        )
        await mgr.ensure_utxos(min_count=TOTAL_TEST_UTXOS, satoshis_each=3_000)
        _utxo_mgr_cache = mgr
    return _utxo_mgr_cache


# ---------------------------------------------------------------------------
# P2PKH sighash matrix
# ---------------------------------------------------------------------------


class TestMainnetP2PKH:
    """P2PKH transactions across all sighash flags on mainnet."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSION_COMBOS)
    async def test_p2pkh(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        p2pkh = P2PKH()
        utxo = utxo_mgr.take_utxo()
        source_tx, vout, _ = utxo
        tx = build_mainnet_tx(
            source_tx,
            vout,
            p2pkh.lock(funded_mainnet_key.address()),
            p2pkh.unlock(funded_mainnet_key),
            funded_mainnet_key,
            sighash=sighash,
            tx_version=tx_version,
        )
        result = await utxo_mgr.broadcast_test_tx(tx, spent_utxo=utxo)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"


# ---------------------------------------------------------------------------
# P2PK sighash matrix
# ---------------------------------------------------------------------------


class TestMainnetP2PK:
    """P2PK transactions across all sighash flags on mainnet."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSION_COMBOS)
    async def test_p2pk(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        p2pk = P2PK()
        tx = await build_two_step_mainnet_tx(
            utxo_mgr,
            p2pk.lock(funded_mainnet_key.public_key().serialize()),
            p2pk.unlock(funded_mainnet_key),
            funded_mainnet_key,
            sighash=sighash,
            tx_version=tx_version,
        )
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"


# ---------------------------------------------------------------------------
# Multisig sighash matrix
# ---------------------------------------------------------------------------


class TestMainnetMultisig:
    """2-of-3 BareMultisig across all sighash flags on mainnet."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSION_COMBOS)
    async def test_multisig_2of3(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        from bsv.keys import PrivateKey

        pk2 = PrivateKey("L32Mf2qU7BLmPmnbs943EYWRv4EUpqnFxkViinPMYesxWLnL6DTA")
        pk3 = PrivateKey("L1DkuXRTu3cGZAmJCDw2TWAoEaRKesq2sZUGzUmbYExgDwhQWe5T")

        multisig = BareMultisig()
        pubkeys = [
            funded_mainnet_key.public_key().serialize(),
            pk2.public_key().serialize(),
            pk3.public_key().serialize(),
        ]
        tx = await build_two_step_mainnet_tx(
            utxo_mgr,
            multisig.lock(pubkeys, threshold=2),
            multisig.unlock([funded_mainnet_key, pk2]),
            funded_mainnet_key,
            sighash=sighash,
            tx_version=tx_version,
        )
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"


# ---------------------------------------------------------------------------
# Chronicle opcodes
# ---------------------------------------------------------------------------


class TestMainnetChronicleOpcodes:
    """Chronicle opcodes in real mainnet transactions."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_ver(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        expected_ver = str(tx_version)
        lock = p2pkh_lock_with_prefix(f"OP_VER OP_{expected_ver} OP_NUMEQUALVERIFY", funded_mainnet_key)
        unlock = custom_unlock(funded_mainnet_key)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_2mul(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_4 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_2")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_2div(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_2DIV OP_5 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_10")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_substr(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_SUBSTR 6263 OP_EQUALVERIFY", funded_mainnet_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_1 OP_2").serialize())
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_left(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_LEFT 6162 OP_EQUALVERIFY", funded_mainnet_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_2").serialize())
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_right(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_RIGHT 6465 OP_EQUALVERIFY", funded_mainnet_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_2").serialize())
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_lshiftnum(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_LSHIFTNUM OP_8 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_1 OP_3")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_rshiftnum(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_RSHIFTNUM OP_2 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_8 OP_2")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_verif(self, funded_mainnet_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_VERIF", funded_mainnet_key)
        lock = Script(lock.serialize() + Script.from_asm("OP_ELSE OP_FALSE OP_ENDIF").serialize())
        ver_bytes = tx_version.to_bytes(4, "little")
        data = Script(encode_pushdata(ver_bytes))
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"


# ---------------------------------------------------------------------------
# Standard opcodes (representative subset)
# ---------------------------------------------------------------------------


class TestMainnetStandardOpcodes:
    """Representative standard opcodes on mainnet."""

    @pytest.mark.asyncio
    async def test_add(self, funded_mainnet_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_ADD OP_7 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_3 OP_4")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_sub(self, funded_mainnet_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_SUB OP_4 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_7 OP_3")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_mul(self, funded_mainnet_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_MUL OP_12 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_3 OP_4")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_cat(self, funded_mainnet_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_CAT 61626364 OP_EQUALVERIFY", funded_mainnet_key)
        data = Script(encode_pushdata(b"\x61\x62") + encode_pushdata(b"\x63\x64"))
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_hash160(self, funded_mainnet_key, utxo_mgr):
        from bsv.hash import hash160

        data_bytes = b"hello"
        expected = hash160(data_bytes)
        lock = p2pkh_lock_with_prefix(f"OP_HASH160 {expected.hex()} OP_EQUALVERIFY", funded_mainnet_key)
        data = Script(encode_pushdata(data_bytes))
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_if_else(self, funded_mainnet_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_IF OP_5 OP_ELSE OP_6 OP_ENDIF OP_5 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_TRUE")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_checksigverify(self, funded_mainnet_key, utxo_mgr):
        from bsv.constants import OpCode
        from bsv.hash import hash160

        pkh = hash160(funded_mainnet_key.public_key().serialize())
        lock = Script(
            OpCode.OP_DUP
            + OpCode.OP_HASH160
            + encode_pushdata(pkh)
            + OpCode.OP_EQUALVERIFY
            + OpCode.OP_CHECKSIGVERIFY
            + OpCode.OP_TRUE
        )
        unlock = custom_unlock(funded_mainnet_key)
        tx = await build_two_step_mainnet_tx(utxo_mgr, lock, unlock, funded_mainnet_key)
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success"


# ---------------------------------------------------------------------------
# v2 unlocking script opcodes (malleability relaxation)
# ---------------------------------------------------------------------------


class TestMainnetUnlockingOpcodes:
    """v2 tx: non-push opcodes in unlocking script (review 9.4.2.1).

    On mainnet, WhatsOnChain submission can reject these with scriptsig-not-pushonly;
    ARC with X-SkipScriptValidation (see mainnet_broadcaster) matches testnet behavior.
    """

    @pytest.mark.asyncio
    async def test_v2_add_in_unlocking(self, funded_mainnet_key, utxo_mgr, mainnet_broadcaster):
        """v2 tx with OP_1 OP_2 OP_ADD in unlocking script producing 3."""
        lock = p2pkh_lock_with_prefix("OP_3 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_1 OP_2 OP_ADD")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(
            utxo_mgr,
            lock,
            unlock,
            funded_mainnet_key,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,
            tx_version=2,
        )
        result = await utxo_mgr.broadcast_test_tx(tx, broadcaster=mainnet_broadcaster)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"

    @pytest.mark.asyncio
    async def test_v2_2mul_in_unlocking(self, funded_mainnet_key, utxo_mgr, mainnet_broadcaster):
        """v2 tx with Chronicle OP_2MUL in unlocking script."""
        lock = p2pkh_lock_with_prefix("OP_6 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_3 OP_2MUL")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(
            utxo_mgr,
            lock,
            unlock,
            funded_mainnet_key,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,
            tx_version=2,
        )
        result = await utxo_mgr.broadcast_test_tx(tx, broadcaster=mainnet_broadcaster)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"


# ---------------------------------------------------------------------------
# Cross-configuration tests
# ---------------------------------------------------------------------------


class TestMainnetCrossConfig:
    """Cross-configuration tests: version transitions, mixed sighash, mixed sources."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("setup_ver,spend_ver", CROSS_VERSION_COMBOS)
    async def test_p2pkh_version_transition(self, funded_mainnet_key, utxo_mgr, setup_ver, spend_ver):
        """P2PKH with setup tx version != spending tx version."""
        p2pkh = P2PKH()
        utxo = utxo_mgr.take_utxo()
        source_tx, vout, _ = utxo
        tx = build_mainnet_tx(
            source_tx,
            vout,
            p2pkh.lock(funded_mainnet_key.address()),
            p2pkh.unlock(funded_mainnet_key),
            funded_mainnet_key,
            sighash=SIGHASH.ALL_FORKID,
            tx_version=spend_ver,
        )
        result = await utxo_mgr.broadcast_test_tx(tx, spent_utxo=utxo)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("setup_ver,spend_ver", CROSS_VERSION_COMBOS)
    async def test_p2pk_version_transition(self, funded_mainnet_key, utxo_mgr, setup_ver, spend_ver):
        """P2PK with setup version != spend version."""
        p2pk = P2PK()
        tx = await build_two_step_mainnet_tx(
            utxo_mgr,
            p2pk.lock(funded_mainnet_key.public_key().serialize()),
            p2pk.unlock(funded_mainnet_key),
            funded_mainnet_key,
            sighash=SIGHASH.ALL_FORKID,
            tx_version=spend_ver,
            setup_version=setup_ver,
        )
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"

    @pytest.mark.asyncio
    async def test_mixed_sighash_inputs(self, funded_mainnet_key, utxo_mgr):
        """Two-input tx: one BIP143, one OTDA, both P2PKH."""
        p2pkh = P2PKH()
        utxo1 = utxo_mgr.take_utxo()
        utxo2 = utxo_mgr.take_utxo()
        src1, vout1, _ = utxo1
        src2, vout2, _ = utxo2

        inp1 = TransactionInput(
            source_transaction=src1,
            source_output_index=vout1,
            unlocking_script_template=p2pkh.unlock(funded_mainnet_key),
            sequence=0xFFFFFFFF,
            sighash=SIGHASH(SIGHASH.ALL_FORKID),
        )
        inp2 = TransactionInput(
            source_transaction=src2,
            source_output_index=vout2,
            unlocking_script_template=p2pkh.unlock(funded_mainnet_key),
            sequence=0xFFFFFFFF,
            sighash=SIGHASH(SIGHASH.ALL_FORKID_CHRONICLE),
        )
        tx = Transaction(
            [inp1, inp2],
            [
                TransactionOutput(
                    locking_script=p2pkh.lock(funded_mainnet_key.address()),
                    change=True,
                )
            ],
            version=2,
        )
        tx.fee(FEE_MODEL)
        tx.sign(bypass=False)
        validate_all_inputs(tx)

        result = await utxo_mgr.broadcast_test_tx(tx)
        if result.status != "success":
            utxo_mgr.return_utxo(utxo1)
            utxo_mgr.return_utxo(utxo2)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"

    @pytest.mark.asyncio
    async def test_chronicle_opcode_bip143_v2(self, funded_mainnet_key, utxo_mgr):
        """Chronicle opcode (OP_2MUL) with BIP143 sighash in v2 tx."""
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_4 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_2")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(
            utxo_mgr,
            lock,
            unlock,
            funded_mainnet_key,
            sighash=SIGHASH.ALL_FORKID,
            tx_version=2,
        )
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"

    @pytest.mark.asyncio
    async def test_chronicle_opcode_otda_v1(self, funded_mainnet_key, utxo_mgr):
        """Chronicle opcode (OP_2MUL) with OTDA sighash in v1 tx."""
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_4 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_2")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(
            utxo_mgr,
            lock,
            unlock,
            funded_mainnet_key,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,
            tx_version=1,
        )
        result = await utxo_mgr.broadcast_test_tx(tx)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"

    @pytest.mark.asyncio
    async def test_v2_nonpush_unlock_v1_setup(self, funded_mainnet_key, utxo_mgr, mainnet_broadcaster):
        """v2 tx with non-push unlocking script spending a v1-created output."""
        lock = p2pkh_lock_with_prefix("OP_3 OP_NUMEQUALVERIFY", funded_mainnet_key)
        data = Script.from_asm("OP_1 OP_2 OP_ADD")
        unlock = custom_unlock(funded_mainnet_key, data_prefix_script=data)
        tx = await build_two_step_mainnet_tx(
            utxo_mgr,
            lock,
            unlock,
            funded_mainnet_key,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,
            tx_version=2,
            setup_version=1,
        )
        result = await utxo_mgr.broadcast_test_tx(tx, broadcaster=mainnet_broadcaster)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


class TestMainnetSummary:
    """Print broadcast summary at the end."""

    @pytest.mark.asyncio
    async def test_summary(self, utxo_mgr):
        remaining = len(utxo_mgr.utxos)
        print(f"\n{'='*60}")
        print("Mainnet broadcast summary:")
        print(f"  Total broadcasts: {utxo_mgr.broadcast_count}")
        print(f"  Remaining UTXOs: {remaining}")
        print(f"{'='*60}")
        assert utxo_mgr.broadcast_count > 0
