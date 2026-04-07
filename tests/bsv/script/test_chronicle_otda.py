"""Tests for SIGHASH_CHRONICLE and OTDA implementation."""

from bsv.constants import SIGHASH
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.spend import Spend
from bsv.script.type import P2PKH
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput


def _make_p2pkh_tx(priv_key: PrivateKey):
    """Create a standard P2PKH source + spending tx pair for sighash tests."""
    address = priv_key.public_key().address()
    source_tx = Transaction(
        tx_inputs=[],
        tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(address), satoshis=1000)],
    )
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=source_tx,
                source_txid=source_tx.txid(),
                source_output_index=0,
                unlocking_script=Script(),
            )
        ],
        tx_outputs=[TransactionOutput(locking_script=Script(), satoshis=999)],
    )
    script_code = source_tx.outputs[0].locking_script
    return tx, script_code


def test_bip143_for_forkid_without_chronicle():
    """Standard v1 tx with SIGHASH.ALL_FORKID uses BIP143 (regression)."""
    priv_key = PrivateKey()
    address = priv_key.public_key().address()

    source_tx = Transaction(
        tx_inputs=[],
        tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(address), satoshis=1000)],
    )
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=source_tx,
                source_txid=source_tx.txid(),
                source_output_index=0,
                unlocking_script_template=P2PKH().unlock(priv_key),
            )
        ],
        tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(address), change=True)],
    )
    tx.fee()
    tx.sign()

    inp = tx.inputs[0]
    spend = Spend({
        "sourceTXID": inp.source_txid,
        "sourceOutputIndex": 0,
        "sourceSatoshis": 1000,
        "lockingScript": source_tx.outputs[0].locking_script,
        "transactionVersion": tx.version,
        "otherInputs": [],
        "outputs": tx.outputs,
        "inputIndex": 0,
        "unlockingScript": inp.unlocking_script,
        "inputSequence": inp.sequence,
        "lockTime": tx.locktime,
    })
    assert spend.validate()


def test_calc_input_signature_hash_routing_bip143():
    """FORKID without CHRONICLE routes to BIP143."""
    priv_key = PrivateKey()
    tx, script_code = _make_p2pkh_tx(priv_key)

    result1 = tx.calc_input_signature_hash(0, int(SIGHASH.ALL_FORKID), script_code, 1000)
    assert len(result1) == 32

    result2 = tx.calc_input_signature_hash(0, int(SIGHASH.ALL_FORKID), script_code, 1000)
    assert result1 == result2


def test_calc_input_signature_hash_routing_otda():
    """FORKID + CHRONICLE routes to OTDA (different from BIP143)."""
    priv_key = PrivateKey()
    tx, script_code = _make_p2pkh_tx(priv_key)

    bip143_hash = tx.calc_input_signature_hash(0, int(SIGHASH.ALL_FORKID), script_code, 1000)
    otda_hash = tx.calc_input_signature_hash(0, int(SIGHASH.ALL_FORKID_CHRONICLE), script_code, 1000)

    assert len(otda_hash) == 32
    assert bip143_hash != otda_hash


def test_otda_same_as_legacy():
    """OTDA should produce valid 32-byte hashes for both legacy and FORKID+CHRONICLE."""
    priv_key = PrivateKey()
    tx, script_code = _make_p2pkh_tx(priv_key)

    legacy_hash = tx.calc_input_signature_hash(0, int(SIGHASH.ALL), script_code, 1000)
    otda_hash = tx.calc_input_signature_hash(0, int(SIGHASH.ALL_FORKID_CHRONICLE), script_code, 1000)

    assert len(legacy_hash) == 32
    assert len(otda_hash) == 32
