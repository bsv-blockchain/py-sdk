"""Shared sighash matrices and tx builders for live mainnet/testnet broadcast tests."""

import pytest

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


def build_live_tx(
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
):
    """Two-step tx for non-P2PKH script types (P2PK, Multisig, custom opcodes).

    Step 1: Spend P2PKH fan-out UTXO → create output locked with test script
    Step 2: Spend that output with the test unlock template + sighash
    Returns step2_tx for caller to broadcast.

    Args:
        setup_broadcaster: Optional broadcaster for step 1 (e.g. WoC when the
            spending node must see the parent via the same endpoint as step 2).
        setup_version: Version of the setup (step 1) transaction (default 1).
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
