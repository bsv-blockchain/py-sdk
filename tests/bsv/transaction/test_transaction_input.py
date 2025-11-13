"""
TransactionInput専用テスト
GO SDKのinput_test.goとtxoutput_test.goを参考に実装
"""
import pytest
from bsv.transaction import TransactionInput
from bsv.script.script import Script
from bsv.utils import Reader


def test_new_input_from_reader_valid():
    """Test creating TransactionInput from reader (GO: TestNewInputFromReader)"""
    # Valid transaction input hex from GO SDK test
    raw_hex = "4c6ec863cf3e0284b407a1a1b8138c76f98280812cb9653231f385a0305fc76f010000006b483045022100f01c1a1679c9437398d691c8497f278fa2d615efc05115688bf2c3335b45c88602201b54437e54fb53bc50545de44ea8c64e9e583952771fcc663c8687dc2638f7854121037e87bbd3b680748a74372640628a8f32d3a841ceeef6f75626ab030c1a04824fffffffff"
    raw_bytes = bytes.fromhex(raw_hex)
    
    tx_input = TransactionInput.from_hex(raw_bytes)
    
    assert tx_input is not None
    assert tx_input.source_output_index == 1
    assert tx_input.unlocking_script is not None
    assert len(tx_input.unlocking_script.serialize()) == 107
    assert tx_input.sequence == 0xFFFFFFFF


def test_new_input_from_reader_empty_bytes():
    """Test creating TransactionInput from empty bytes (GO: TestNewInputFromReader)"""
    tx_input = TransactionInput.from_hex(b"")
    assert tx_input is None


def test_new_input_from_reader_invalid_too_short():
    """Test creating TransactionInput from invalid data (GO: TestNewInputFromReader)"""
    tx_input = TransactionInput.from_hex(b"invalid")
    assert tx_input is None


def test_input_string():
    """Test TransactionInput string representation (GO: TestInput_String)"""
    raw_hex = "4c6ec863cf3e0284b407a1a1b8138c76f98280812cb9653231f385a0305fc76f010000006b483045022100f01c1a1679c9437398d691c8497f278fa2d615efc05115688bf2c3335b45c88602201b54437e54fb53bc50545de44ea8c64e9e583952771fcc663c8687dc2638f7854121037e87bbd3b680748a74372640628a8f32d3a841ceeef6f75626ab030c1a04824fffffffff"
    raw_bytes = bytes.fromhex(raw_hex)
    
    tx_input = TransactionInput.from_hex(raw_bytes)
    assert tx_input is not None
    
    # Test string representation
    str_repr = str(tx_input)
    assert "TransactionInput" in str_repr or "outpoint" in str_repr.lower()
    assert tx_input.source_txid in str_repr or str(tx_input.source_output_index) in str_repr


def test_input_serialize():
    """Test TransactionInput serialization"""
    source_txid = "aa" * 32
    tx_input = TransactionInput(
        source_txid=source_txid,
        source_output_index=0,
        unlocking_script=Script(b"\x51"),
        sequence=0xFFFFFFFF
    )
    
    serialized = tx_input.serialize()
    assert len(serialized) > 0
    
    # Verify it can be deserialized
    deserialized = TransactionInput.from_hex(serialized)
    assert deserialized is not None
    assert deserialized.source_output_index == tx_input.source_output_index
    assert deserialized.sequence == tx_input.sequence


def test_input_with_source_transaction():
    """Test TransactionInput with source transaction"""
    from bsv.transaction import Transaction, TransactionOutput
    
    # Create source transaction
    source_tx = Transaction()
    source_tx.outputs = [TransactionOutput(locking_script=Script(b"\x51"), satoshis=1000)]
    
    # Create input referencing source transaction
    tx_input = TransactionInput(
        source_transaction=source_tx,
        source_output_index=0,
        unlocking_script=Script(b"\x52")
    )
    
    assert tx_input.source_transaction == source_tx
    assert tx_input.source_txid == source_tx.txid()
    assert tx_input.satoshis == 1000
    assert tx_input.locking_script == source_tx.outputs[0].locking_script


def test_input_auto_txid():
    """Test TransactionInput automatically sets txid from source transaction"""
    from bsv.transaction import Transaction, TransactionOutput
    
    source_tx = Transaction()
    source_tx.outputs = [TransactionOutput(locking_script=Script(b"\x51"), satoshis=1000)]
    
    tx_input = TransactionInput(
        source_transaction=source_tx,
        source_output_index=0
    )
    
    assert tx_input.source_txid == source_tx.txid()
    assert tx_input.source_txid is not None

