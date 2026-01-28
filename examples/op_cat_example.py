#!/usr/bin/env python3
"""
OP_CAT Example

This example demonstrates how to create and spend an output locked with OP_CAT.
The OP_CAT opcode concatenates two pieces of data on the stack and compares
the result with an expected value.

In this example:
- Locking script: OP_CAT <expected_data> OP_EQUAL
- Unlocking script: <data_piece_1> <data_piece_2>

When executed, the unlocking script pushes data_piece_1 and data_piece_2 onto the stack,
OP_CAT concatenates them, and OP_EQUAL checks if the result matches expected_data.
"""

from bsv import (
    Transaction,
    TransactionInput,
    TransactionOutput,
    PrivateKey,
    OpCat,
    P2PKH,
)


def validate_transaction(tx, source_tx, input_index=0):
    """Helper function to validate a transaction using Spend."""
    from bsv import Spend
    return Spend({
        'sourceTXID': tx.inputs[input_index].source_txid,
        'sourceOutputIndex': tx.inputs[input_index].source_output_index,
        'sourceSatoshis': source_tx.outputs[0].satoshis,
        'lockingScript': source_tx.outputs[0].locking_script,
        'transactionVersion': tx.version,
        'otherInputs': [],
        'inputIndex': input_index,
        'unlockingScript': tx.inputs[input_index].unlocking_script,
        'outputs': tx.outputs,
        'inputSequence': tx.inputs[input_index].sequence,
        'lockTime': tx.locktime,
    }).validate()


def main():
    print("OP_CAT Example")
    print("=" * 50)

    # Create a private key for the change output
    private_key = PrivateKey()

    # Define the data we want to concatenate
    expected_data = b"hello world"
    data_piece_1 = b"hello "
    data_piece_2 = b"world"

    print(f"Expected concatenated data: {expected_data}")
    print(f"Data piece 1: {data_piece_1}")
    print(f"Data piece 2: {data_piece_2}")
    print()

    # Create the locking script using OpCat template
    locking_script = OpCat().lock(expected_data)
    print(f"Locking script: {locking_script.to_asm()}")
    print(f"Locking script (hex): {locking_script.hex()}")
    print()

    # Create a source transaction with the OP_CAT output
    # In a real scenario, this would come from a previous transaction
    # For this example, we'll create a mock source transaction
    source_tx = Transaction(
        [],  # No inputs for coinbase-like transaction
        [
            TransactionOutput(
                locking_script=locking_script,
                satoshis=1000  # 1000 satoshis
            )
        ]
    )

    print("Created source transaction with OP_CAT output")
    print(f"Source TXID: {source_tx.txid()}")
    print(f"Output value: {source_tx.outputs[0].satoshis} satoshis")
    print()

    # Now create a transaction that spends the OP_CAT output
    print("Creating spending transaction...")

    tx = Transaction(
        [
            TransactionInput(
                source_transaction=source_tx,
                source_txid=source_tx.txid(),
                source_output_index=0,
                unlocking_script_template=OpCat().unlock(data_piece_1, data_piece_2)
            )
        ],
        [
            # Send 500 satoshis to a P2PKH address
            TransactionOutput(
                locking_script=P2PKH().lock(private_key.address()),
                satoshis=500
            ),
            # Change back to another OP_CAT output with different data
            TransactionOutput(
                locking_script=OpCat().lock(b"new concatenated data"),
                change=True
            ),
        ]
    )

    # Calculate fees and sign the transaction
    tx.fee()
    tx.sign()

    print("Transaction created and signed")
    print(f"TXID: {tx.txid()}")
    print()

    # Display the unlocking script
    unlocking_script = tx.inputs[0].unlocking_script
    print(f"Unlocking script: {unlocking_script.to_asm()}")
    print(f"Unlocking script (hex): {unlocking_script.hex()}")
    print()

    # Verify the transaction would be valid
    is_valid = validate_transaction(tx, source_tx)
    print(f"Transaction validation: {'PASS' if is_valid else 'FAIL'}")
    print()

    # Demonstrate with different data combinations
    print("Demonstrating different data combinations:")
    print("-" * 40)

    test_cases = [
        (b"foo", b"bar", b"foobar"),
        ("hello ", "world", b"hello world"),
        (b"", b"empty", b"empty"),
        (b"test", b"", b"test"),
    ]

    for data1, data2, expected in test_cases:
        print(f"Data1: {data1!r}, Data2: {data2!r} -> Expected: {expected!r}")

        # Create locking script
        lock_script = OpCat().lock(expected)

        # Create mock transaction to test
        mock_source = Transaction([], [TransactionOutput(locking_script=lock_script, satoshis=100)])

        mock_tx = Transaction([
            TransactionInput(
                source_transaction=mock_source,
                source_output_index=0,
                unlocking_script_template=OpCat().unlock(data1, data2)
            )
        ], [
            TransactionOutput(locking_script=P2PKH().lock(private_key.address()), change=True)
        ])

        mock_tx.fee()
        mock_tx.sign()

        # Validate
        valid = validate_transaction(mock_tx, mock_source)
        print(f"  Validation: {'✓ PASS' if valid else '✗ FAIL'}")
        print()

    print("OP_CAT example completed!")


if __name__ == "__main__":
    main()