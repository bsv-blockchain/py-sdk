import pytest

from bsv.constants import OpCode
from bsv.script.spend import Spend
from bsv.script.script import Script
from bsv.script.type import OpCat
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
from bsv.utils import encode_pushdata


def test_op_cat_template():
    """Test OP_CAT script template functionality"""

    # Test locking script creation
    expected_data = b"hello world"
    locking_script = OpCat().lock(expected_data)
    expected_locking_script = Script(OpCode.OP_CAT + encode_pushdata(expected_data) + OpCode.OP_EQUAL)
    assert locking_script == expected_locking_script

    # Test with string data
    expected_data_str = "hello world"
    locking_script_str = OpCat().lock(expected_data_str)
    assert locking_script_str == expected_locking_script

    # Test unlocking script creation
    data1 = b"hello "
    data2 = b"world"
    unlocking_template = OpCat().unlock(data1, data2)
    expected_unlocking_script = Script(encode_pushdata(data1) + encode_pushdata(data2))

    # Create a mock transaction to test signing
    class MockTx:
        pass

    mock_tx = MockTx()
    actual_unlocking_script = unlocking_template.sign(mock_tx, 0)
    assert actual_unlocking_script == expected_unlocking_script

    # Test estimated byte length
    estimated_length = unlocking_template.estimated_unlocking_byte_length()
    actual_length = len(expected_unlocking_script.serialize())
    assert estimated_length == actual_length

    # Test with string data for unlocking
    data1_str = "hello "
    data2_str = "world"
    unlocking_template_str = OpCat().unlock(data1_str, data2_str)
    actual_unlocking_script_str = unlocking_template_str.sign(mock_tx, 0)
    assert actual_unlocking_script_str == expected_unlocking_script


def test_op_cat_end_to_end():
    """Test complete OP_CAT transaction flow"""

    # Create a source transaction with OP_CAT locking script
    expected_data = b"hello world"
    locking_script = OpCat().lock(expected_data)

    source_tx = Transaction(
        [],
        [
            TransactionOutput(
                locking_script=locking_script,
                satoshis=1000
            )
        ]
    )

    # Create a spending transaction
    tx = Transaction([
        TransactionInput(
            source_transaction=source_tx,
            source_output_index=0,
            unlocking_script_template=OpCat().unlock(b"hello ", b"world")
        )
    ], [
        TransactionOutput(
            locking_script=OpCat().lock(b"test data"),  # Change to another OP_CAT output
            change=True
        )
    ])

    tx.fee()
    tx.sign()

    # Verify the unlocking script is correct
    unlocking_script = tx.inputs[0].unlocking_script
    expected_unlocking_script = Script(encode_pushdata(b"hello ") + encode_pushdata(b"world"))
    assert unlocking_script == expected_unlocking_script

    # Test script evaluation with Spend
    spend = Spend({
        'sourceTXID': tx.inputs[0].source_txid,
        'sourceOutputIndex': tx.inputs[0].source_output_index,
        'sourceSatoshis': source_tx.outputs[0].satoshis,
        'lockingScript': source_tx.outputs[0].locking_script,
        'transactionVersion': tx.version,
        'otherInputs': [],
        'inputIndex': 0,
        'unlockingScript': tx.inputs[0].unlocking_script,
        'outputs': tx.outputs,
        'inputSequence': tx.inputs[0].sequence,
        'lockTime': tx.locktime,
    })
    assert spend.validate()


def test_op_cat_edge_cases():
    """Test OP_CAT with various data types and edge cases"""

    # Test with empty strings
    locking_script = OpCat().lock("")
    expected_locking = Script(OpCode.OP_CAT + encode_pushdata(b"") + OpCode.OP_EQUAL)
    assert locking_script == expected_locking

    unlocking_template = OpCat().unlock("", "")
    expected_unlocking = Script(encode_pushdata(b"") + encode_pushdata(b""))
    assert unlocking_template.sign(None, 0) == expected_unlocking

    # Test with larger data
    large_data = b"x" * 100
    locking_script_large = OpCat().lock(large_data)
    expected_locking_large = Script(OpCode.OP_CAT + encode_pushdata(large_data) + OpCode.OP_EQUAL)
    assert locking_script_large == expected_locking_large

    # Test with unicode strings
    unicode_data = "héllo wörld 🌍"
    locking_script_unicode = OpCat().lock(unicode_data)
    expected_unicode_bytes = unicode_data.encode("utf-8")
    expected_locking_unicode = Script(OpCode.OP_CAT + encode_pushdata(expected_unicode_bytes) + OpCode.OP_EQUAL)
    assert locking_script_unicode == expected_locking_unicode


def test_op_cat_type_errors():
    """Test that OpCat raises appropriate TypeErrors for invalid inputs"""

    # Test invalid locking script data type
    with pytest.raises(TypeError, match=r"unsupported type for OpCat locking script data"):
        OpCat().lock(123)

    # Test invalid unlocking script data types
    with pytest.raises(TypeError, match=r"unsupported type for first OpCat unlocking data"):
        OpCat().unlock(123, b"world")

    with pytest.raises(TypeError, match=r"unsupported type for second OpCat unlocking data"):
        OpCat().unlock(b"hello", 456)