"""Shared sighash matrices and tx builders for live mainnet/testnet broadcast tests."""

import pytest

from bsv.broadcasters.broadcaster import Broadcaster
from bsv.constants import SIGHASH
from bsv.fee_models import SatoshisPerKilobyte
from bsv.script.script import Script
from bsv.script.type import P2PKH
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput

from .conftest import validate_all_inputs

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

SIGHASH_VERSION_COMBOS = [pytest.param(sh, v, id=f"{sh.name}_v{v}") for sh in ALL_SIGHASHES for v in TX_VERSIONS]

OPCODE_SIGHASH_VERSIONS = [
    pytest.param(SIGHASH.ALL_FORKID, 1, id="BIP143_v1"),
    pytest.param(SIGHASH.ALL_FORKID_CHRONICLE, 2, id="OTDA_v2"),
]

FEE_MODEL = SatoshisPerKilobyte(100)

# P2PKH: 24, P2PK: 24, Multisig: 24, Chronicle opcodes: 20, Standard opcodes: ~25, Unlocking: 2, CrossConfig: ~15
TOTAL_TEST_UTXOS = 155  # with some buffer

CROSS_VERSION_COMBOS = [
    pytest.param(1, 2, id="setup_v1_spend_v2"),
    pytest.param(2, 1, id="setup_v2_spend_v1"),
]

# WoC POST /tx/raw accepts into the node's mempool, but GET /tx/{id}/hex (used by
# wait_until_woc_sees_txid) often stays 404 for unconfirmed txs on testnet. Treat relay
# success or "already have this tx" as sufficient for a follow-up WoC spend.
_WOC_RELAY_DUP_MARKERS = (
    "already",
    "duplicate",
    "exists",
    "txn-already",
    "same txn",
    "rejecting txn",
    "already in mempool",
    "already known",
)


def _woc_relay_ready_for_spend(relay_result) -> bool:
    if getattr(relay_result, "status", None) == "success":
        return True
    desc = (getattr(relay_result, "description", None) or "").lower()
    return any(m in desc for m in _WOC_RELAY_DUP_MARKERS)


def build_live_tx(
    source_tx: Transaction,
    source_vout: int,
    unlock_template,
    change_key,
    sighash: int = SIGHASH.ALL_FORKID,
    tx_version: int = 1,
) -> Transaction:
    """Build a tx spending a pooled P2PKH UTXO (lock is taken from source_tx), with fee and change."""
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


async def build_two_step_live_tx(
    utxo_mgr,
    test_lock_script: Script,
    test_unlock_template,
    funded_key,
    sighash: int = SIGHASH.ALL_FORKID,
    tx_version: int = 1,
    *,
    setup_broadcaster=None,
    setup_version: int = 1,
    sync_setup_to_woc: bool = False,
    relay_setup_to_woc: Broadcaster | None = None,
):
    """Two-step tx for non-P2PKH script types (P2PK, Multisig, custom opcodes).

    Step 1: Spend P2PKH fan-out UTXO → create output locked with test script
    Step 2: Spend that output with the test unlock template + sighash
    Returns step2_tx for caller to broadcast.

    Args:
        setup_broadcaster: Optional broadcaster for step 1. Default is utxo_mgr's
            broadcaster (typically ARC). Avoid WoC here for pool UTXOs funded via ARC —
            WoC may return missing-inputs until the fan-out is visible on its node.
        setup_version: Version of the setup (step 1) transaction (default 1).
        sync_setup_to_woc: If True, ensure WoC's node can see the setup tx before step 2 is
            broadcast there. With relay_setup_to_woc, we POST the pool parent tx then the setup
            tx to WoC (ARC-only fan-out is often missing there) and require relay success —
            we do not poll GET /tx/.../hex (unreliable for 0-conf). Without relay, we only poll.
        relay_setup_to_woc: WhatsOnChain broadcaster: seed parent + setup txs after ARC.
    """
    p2pkh = P2PKH()

    utxo = utxo_mgr.take_utxo()
    source_tx, vout, _ = utxo
    setup_tx = Transaction(
        [
            TransactionInput(
                source_transaction=source_tx,
                source_output_index=vout,
                unlocking_script_template=p2pkh.unlock(funded_key),
                sequence=0xFFFFFFFF,
            )
        ],
        [TransactionOutput(locking_script=test_lock_script, change=True)],
        version=setup_version,
    )
    setup_tx.fee(FEE_MODEL)
    setup_tx.sign()

    result = await utxo_mgr.broadcast_test_tx(setup_tx, spent_utxo=utxo, broadcaster=setup_broadcaster)
    if result.status != "success":
        raise RuntimeError(f"Setup tx failed: {getattr(result, 'description', '')}")

    if sync_setup_to_woc:
        setup_txid = result.txid or setup_tx.txid()
        if relay_setup_to_woc is None:
            await utxo_mgr.wait_until_woc_sees_txid(setup_txid)
        else:
            await relay_setup_to_woc.broadcast(source_tx)
            relay_result = await relay_setup_to_woc.broadcast(setup_tx)
            if not _woc_relay_ready_for_spend(relay_result):
                raise RuntimeError(
                    "WoC setup relay failed after POSTing the pool parent tx; "
                    "GET /tx/hex is not used for 0-conf sync. "
                    f"setup_txid={setup_txid} relay={getattr(relay_result, 'description', relay_result)!r}"
                )

    test_tx = Transaction(
        [
            TransactionInput(
                source_transaction=setup_tx,
                source_output_index=0,
                unlocking_script_template=test_unlock_template,
                sequence=0xFFFFFFFF,
                sighash=SIGHASH(sighash),
            )
        ],
        [
            TransactionOutput(
                locking_script=p2pkh.lock(funded_key.address()),
                change=True,
            )
        ],
        version=tx_version,
    )
    test_tx.fee(FEE_MODEL)
    test_tx.sign(bypass=False)
    validate_all_inputs(test_tx)
    return test_tx
