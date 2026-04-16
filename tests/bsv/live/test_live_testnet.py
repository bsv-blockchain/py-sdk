"""Live testnet broadcast tests.

Builds real transactions, validates them via Spend, and broadcasts to BSV testnet.
All test txs are funded from a single fan-out tx that splits one UTXO into many.

Requires: FUNDED_TESTNET_WIF env var set to a funded testnet private key WIF.
Run with: pytest tests/bsv/live/test_live_testnet.py -v -m testnet

Default chain guarantee — SEEN_ON_NETWORK (not mined):
  For each ARC broadcast (fan-out + test txs), tests use X-WaitForStatus: 8 and, if the
  POST body still shows an earlier txStatus, poll GET until SEEN_ON_NETWORK (or MINED if
  reached first). This is the default live wait.

Optional — wait for mined (slow):
  LIVE_REQUIRE_MINED=1 — after that, also poll until ARC reports MINED or WoC confirmations.
  LIVE_TX_CONFIRM_TIMEOUT_SEC — Max seconds for that mined wait (default 300).

ARC tuning:
  LIVE_ARC_SKIP_WAIT_FOR_SEEN=1 — disable SEEN_ON_NETWORK headers and GET enforcement (faster, weaker).
  ARC_X_MAX_TIMEOUT / ARC_SEEN_POLL_TIMEOUT_SEC — HTTP POST bound (default 5s) and GET poll (default 3s).
  LIVE_FANOUT_SEEN_POLL_TIMEOUT_SEC — fan-out visibility wait (default: max(30s, ARC_SEEN poll)); WoC POST /tx/raw accepts already-in-mempool.

The ARC broadcaster also fails the HTTP broadcast step when ARC returns a terminal
txStatus in the POST body (e.g. REJECTED), not only on non-2xx responses.

Self-healing: pooled P2PKH spends use ``UTXOManager.broadcast_test_tx_retry_on_spent``; two-step
flows use ``broadcast_test_tx_resilient`` (re-runs the async builder when the final broadcast
reports a spent input). The shared ``build_two_step_live_tx`` setup step retries setup broadcast via
``broadcast_test_tx_retry_on_spent``. Mixed two-input tests retry up to three times on spent-type
errors. WoC pool pruning and ``LIVE_UTXO_SKIP_WOC_PRUNE`` are documented in ``tests/bsv/live/conftest.py``.

ARC may return ``DOUBLE_SPEND_ATTEMPTED`` on POST while WhatsOnChain still sees the tx; :meth:`UTXOManager.broadcast_test_tx` can accept success after a WoC mempool/indexer probe (same idea as ``WOC_MEMPOOL_POST`` in ``arc_verify``).

WhatsOnChain JSON audit (Apr 2026):
  For each explorer txid printed in a full live run, GET
  https://api.whatsonchain.com/v1/bsv/test/tx/{txid} was checked. 182/188 txids
  returned 404 (or a body without txid/hash); six txids returned 200. Only three
  tests had all their printed txids return 200; 104 node IDs had at least one miss
  (see _testnet_woc_xfail_nodeids.py).   Those node IDs are listed in _testnet_woc_xfail_nodeids.py. Set
  LIVE_WOC_JSON_XFAIL_AUDIT=1 to apply pytest.mark.xfail(strict=True) to them (a
  successful broadcast is then reported as an XPASS failure). By default live
  tests behave as before. A 404 on this API does not prove the tx was not mined;
  default live wait is SEEN_ON_NETWORK only; use LIVE_REQUIRE_MINED=1 for mined polling.
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
    FUNDED_TESTNET_WIF,
    UTXOManager,
    broadcast_failure_indicates_spent_input,
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
    build_live_tx as build_testnet_tx,
)
from .live_tx_helpers import (
    build_two_step_live_tx as build_two_step_testnet_tx,
)

# ---------------------------------------------------------------------------
# Skip entire module if no funded key
# ---------------------------------------------------------------------------

pytestmark = [
    pytest.mark.testnet,
    pytest.mark.skipif(not FUNDED_TESTNET_WIF, reason="FUNDED_TESTNET_WIF not set"),
]


# ---------------------------------------------------------------------------
# Session-scoped UTXO manager fixture
# ---------------------------------------------------------------------------


# Module-level cache for the UTXO manager (initialized once on first use)
_utxo_mgr_cache: UTXOManager | None = None


@pytest_asyncio.fixture
async def utxo_mgr(funded_key, testnet_broadcaster):
    """Ensure UTXOs are available, loading from disk or fanning out as needed."""
    global _utxo_mgr_cache
    if _utxo_mgr_cache is None:
        mgr = UTXOManager(funded_key, testnet_broadcaster)
        await mgr.ensure_utxos(min_count=TOTAL_TEST_UTXOS, satoshis_each=3_000)
        _utxo_mgr_cache = mgr
    return _utxo_mgr_cache


# ---------------------------------------------------------------------------
# P2PKH sighash matrix
# ---------------------------------------------------------------------------


class TestTestnetP2PKH:
    """P2PKH transactions across all sighash flags on testnet."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSION_COMBOS)
    async def test_p2pkh(self, funded_key, utxo_mgr, sighash, tx_version):
        p2pkh = P2PKH()

        def _spend(u):
            source_tx, vout, _ = u
            return build_testnet_tx(
                source_tx,
                vout,
                p2pkh.unlock(funded_key),
                funded_key,
                sighash=sighash,
                tx_version=tx_version,
            )

        result, _ = await utxo_mgr.broadcast_test_tx_retry_on_spent(_spend)
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
        async def _final():
            return await build_two_step_testnet_tx(
            utxo_mgr,
            p2pk.lock(funded_key.public_key().serialize()),
            p2pk.unlock(funded_key),
            funded_key,
            sighash=sighash,
            tx_version=tx_version,
        )
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
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

        pk2 = PrivateKey("L32Mf2qU7BLmPmnbs943EYWRv4EUpqnFxkViinPMYesxWLnL6DTA")
        pk3 = PrivateKey("L1DkuXRTu3cGZAmJCDw2TWAoEaRKesq2sZUGzUmbYExgDwhQWe5T")

        multisig = BareMultisig()
        pubkeys = [
            funded_key.public_key().serialize(),
            pk2.public_key().serialize(),
            pk3.public_key().serialize(),
        ]
        async def _final():
            return await build_two_step_testnet_tx(
            utxo_mgr,
            multisig.lock(pubkeys, threshold=2),
            multisig.unlock([funded_key, pk2]),
            funded_key,
            sighash=sighash,
            tx_version=tx_version,
        )
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"


# ---------------------------------------------------------------------------
# Chronicle opcodes
# ---------------------------------------------------------------------------


class TestTestnetChronicleOpcodes:
    """Chronicle opcodes in real testnet transactions."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_ver(self, funded_key, utxo_mgr, sighash, tx_version):
        # OP_VER pushes 4-byte LE nVersion; OP_NUMEQUALVERIFY rejects non-minimal encodings on network.
        ver_le_hex = tx_version.to_bytes(4, "little").hex()
        lock = p2pkh_lock_with_prefix(f"OP_VER {ver_le_hex} OP_EQUALVERIFY", funded_key)
        unlock = custom_unlock(funded_key)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_2mul(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_4 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_2")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_2div(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_2DIV OP_5 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_10")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_substr(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_SUBSTR 6263 OP_EQUALVERIFY", funded_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_1 OP_2").serialize())
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_left(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_LEFT 6162 OP_EQUALVERIFY", funded_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_2").serialize())
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_right(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_RIGHT 6465 OP_EQUALVERIFY", funded_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_2").serialize())
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_lshiftnum(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_LSHIFTNUM OP_8 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_1 OP_3")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_rshiftnum(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_RSHIFTNUM OP_2 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_8 OP_2")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sighash,tx_version", OPCODE_SIGHASH_VERSIONS)
    async def test_op_verif(self, funded_key, utxo_mgr, sighash, tx_version):
        lock = p2pkh_lock_with_prefix("OP_VERIF", funded_key)
        lock = Script(lock.serialize() + Script.from_asm("OP_ELSE OP_FALSE OP_ENDIF").serialize())
        ver_bytes = tx_version.to_bytes(4, "little")
        data = Script(encode_pushdata(ver_bytes))
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key, sighash, tx_version)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
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
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_sub(self, funded_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_SUB OP_4 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_7 OP_3")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_mul(self, funded_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_MUL OP_12 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_3 OP_4")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_cat(self, funded_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_CAT 61626364 OP_EQUALVERIFY", funded_key)
        data = Script(encode_pushdata(b"\x61\x62") + encode_pushdata(b"\x63\x64"))
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_hash160(self, funded_key, utxo_mgr):
        from bsv.hash import hash160

        data_bytes = b"hello"
        expected = hash160(data_bytes)
        lock = p2pkh_lock_with_prefix(f"OP_HASH160 {expected.hex()} OP_EQUALVERIFY", funded_key)
        data = Script(encode_pushdata(data_bytes))
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_if_else(self, funded_key, utxo_mgr):
        lock = p2pkh_lock_with_prefix("OP_IF OP_5 OP_ELSE OP_6 OP_ENDIF OP_5 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_TRUE")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
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
        async def _final():
            return await build_two_step_testnet_tx(utxo_mgr, lock, unlock, funded_key)
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success"


# ---------------------------------------------------------------------------
# v2 unlocking script opcodes (malleability relaxation)
# ---------------------------------------------------------------------------


class TestTestnetUnlockingOpcodes:
    """v2 tx: non-push opcodes in unlocking script (review 9.4.2.1).

    Step 1 (setup) is always ARC with X-SkipScriptValidation (testnet_broadcaster). The same
    setup tx is relayed to WoC (relay_setup_to_woc) so their node has it for step 2; we do
    not rely on GET /tx/hex for 0-conf (often 404 on testnet).
    Step 2 is WoC because ARC rejects non-push unlocking scripts (error 463).
    """

    @pytest.mark.asyncio
    async def test_v2_add_in_unlocking(
        self, funded_key, utxo_mgr, testnet_broadcaster, woc_testnet_broadcaster
    ):
        """v2 tx with OP_1 OP_2 OP_ADD in unlocking script producing 3."""
        lock = p2pkh_lock_with_prefix("OP_3 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_1 OP_2 OP_ADD")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(
            utxo_mgr,
            lock,
            unlock,
            funded_key,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,
            tx_version=2,
            setup_broadcaster=testnet_broadcaster,
            sync_setup_to_woc=True,
            relay_setup_to_woc=woc_testnet_broadcaster,
        )
        result = await utxo_mgr.broadcast_test_tx_resilient(_final, broadcaster=woc_testnet_broadcaster)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"

    @pytest.mark.asyncio
    async def test_v2_2mul_in_unlocking(
        self, funded_key, utxo_mgr, testnet_broadcaster, woc_testnet_broadcaster
    ):
        """v2 tx with Chronicle OP_2MUL in unlocking script."""
        lock = p2pkh_lock_with_prefix("OP_6 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_3 OP_2MUL")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(
            utxo_mgr,
            lock,
            unlock,
            funded_key,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,
            tx_version=2,
            setup_broadcaster=testnet_broadcaster,
            sync_setup_to_woc=True,
            relay_setup_to_woc=woc_testnet_broadcaster,
        )
        result = await utxo_mgr.broadcast_test_tx_resilient(_final, broadcaster=woc_testnet_broadcaster)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"


# ---------------------------------------------------------------------------
# Cross-configuration tests
# ---------------------------------------------------------------------------


class TestTestnetCrossConfig:
    """Cross-configuration tests: version transitions, mixed sighash, mixed sources."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("setup_ver,spend_ver", CROSS_VERSION_COMBOS)
    async def test_p2pkh_version_transition(self, funded_key, utxo_mgr, setup_ver, spend_ver):
        """P2PKH with setup tx version != spending tx version."""
        p2pkh = P2PKH()

        def _spend(u):
            source_tx, vout, _ = u
            return build_testnet_tx(
                source_tx,
                vout,
                p2pkh.unlock(funded_key),
                funded_key,
                sighash=SIGHASH.ALL_FORKID,
                tx_version=spend_ver,
            )

        result, _ = await utxo_mgr.broadcast_test_tx_retry_on_spent(_spend)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("setup_ver,spend_ver", CROSS_VERSION_COMBOS)
    async def test_p2pk_version_transition(self, funded_key, utxo_mgr, setup_ver, spend_ver):
        """P2PK with setup version != spend version."""
        p2pk = P2PK()
        async def _final():
            return await build_two_step_testnet_tx(
            utxo_mgr,
            p2pk.lock(funded_key.public_key().serialize()),
            p2pk.unlock(funded_key),
            funded_key,
            sighash=SIGHASH.ALL_FORKID,
            tx_version=spend_ver,
            setup_version=setup_ver,
        )
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"

    @pytest.mark.asyncio
    async def test_mixed_sighash_inputs(self, funded_key, utxo_mgr):
        """Two-input tx: one BIP143, one OTDA, both P2PKH."""
        p2pkh = P2PKH()
        last = None
        for _ in range(3):
            if len(utxo_mgr.utxos) < 2:
                await utxo_mgr.ensure_utxos(2, satoshis_each=3_000)
            utxo1 = utxo_mgr.take_utxo()
            utxo2 = utxo_mgr.take_utxo()
            src1, vout1, _ = utxo1
            src2, vout2, _ = utxo2

            inp1 = TransactionInput(
                source_transaction=src1,
                source_output_index=vout1,
                unlocking_script_template=p2pkh.unlock(funded_key),
                sequence=0xFFFFFFFF,
                sighash=SIGHASH(SIGHASH.ALL_FORKID),
            )
            inp2 = TransactionInput(
                source_transaction=src2,
                source_output_index=vout2,
                unlocking_script_template=p2pkh.unlock(funded_key),
                sequence=0xFFFFFFFF,
                sighash=SIGHASH(SIGHASH.ALL_FORKID_CHRONICLE),
            )
            tx = Transaction(
                [inp1, inp2],
                [
                    TransactionOutput(
                        locking_script=p2pkh.lock(funded_key.address()),
                        change=True,
                    )
                ],
                version=2,
            )
            tx.fee(FEE_MODEL)
            tx.sign(bypass=False)
            validate_all_inputs(tx)

            last = await utxo_mgr.broadcast_test_tx(tx)
            if last.status == "success":
                break
            if broadcast_failure_indicates_spent_input(last):
                continue
            utxo_mgr.return_utxo(utxo2)
            utxo_mgr.return_utxo(utxo1)
            break
        assert last is not None and last.status == "success", (
            f"Broadcast failed: {getattr(last, 'description', '')}"
        )

    @pytest.mark.asyncio
    async def test_chronicle_opcode_bip143_v2(self, funded_key, utxo_mgr):
        """Chronicle opcode (OP_2MUL) with BIP143 sighash in v2 tx."""
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_4 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_2")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(
            utxo_mgr,
            lock,
            unlock,
            funded_key,
            sighash=SIGHASH.ALL_FORKID,
            tx_version=2,
        )
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"

    @pytest.mark.asyncio
    async def test_chronicle_opcode_otda_v1(self, funded_key, utxo_mgr):
        """Chronicle opcode (OP_2MUL) with OTDA sighash in v1 tx."""
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_4 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_2")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(
            utxo_mgr,
            lock,
            unlock,
            funded_key,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,
            tx_version=1,
        )
        result = await utxo_mgr.broadcast_test_tx_resilient(_final)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"

    @pytest.mark.asyncio
    async def test_v2_nonpush_unlock_v1_setup(
        self, funded_key, utxo_mgr, testnet_broadcaster, woc_testnet_broadcaster
    ):
        """v2 tx with non-push unlocking script spending a v1-created output."""
        lock = p2pkh_lock_with_prefix("OP_3 OP_NUMEQUALVERIFY", funded_key)
        data = Script.from_asm("OP_1 OP_2 OP_ADD")
        unlock = custom_unlock(funded_key, data_prefix_script=data)
        async def _final():
            return await build_two_step_testnet_tx(
            utxo_mgr,
            lock,
            unlock,
            funded_key,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,
            tx_version=2,
            setup_version=1,
            setup_broadcaster=testnet_broadcaster,
            sync_setup_to_woc=True,
            relay_setup_to_woc=woc_testnet_broadcaster,
        )
        result = await utxo_mgr.broadcast_test_tx_resilient(_final, broadcaster=woc_testnet_broadcaster)
        assert result.status == "success", f"Broadcast failed: {getattr(result, 'description', '')}"


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


class TestTestnetSummary:
    """Print broadcast summary at the end."""

    @pytest.mark.asyncio
    async def test_summary(self, utxo_mgr):
        remaining = len(utxo_mgr.utxos)
        print(f"\n{'='*60}")
        print("Testnet broadcast summary:")
        print(f"  Total broadcasts: {utxo_mgr.broadcast_count}")
        print(f"  Remaining UTXOs: {remaining}")
        print(f"{'='*60}")
        assert utxo_mgr.broadcast_count > 0
