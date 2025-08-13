from idlelib.configdialog import changes
import asyncio

from bsv import (
    Transaction,
    TransactionInput,
    TransactionOutput,
    PrivateKey,
    P2PKH,
    BroadcastResponse,
    ARC
)

"""
Simple example of synchronous ARC broadcasting and status checking.
"""

def main():

    # Setup ARC broadcaster
    arc = ARC('https://api.taal.com/arc', "mainnet_2e3a7d0f845a5049b_________98fc4271")

    # Create a simple transaction
    private_key = PrivateKey("Kzpr5a6TmrXNw2NxSzt6GUonvc---------dGEjxCufyxGMo9xV")
    public_key = private_key.public_key()

    source_tx = Transaction.from_hex(
        "01000000013462125ff05a9150c25693bbb474a----------ab265e746f523791e01462000000006a4730440220447ac5232e8eb25db0e004bc704a19bc33c9c7ef86070781078bce74e089be44022029195e8cc392bf7c5577dc477a90d157be0356d8fbb52eb66521f4eabe00dcf9412103e23c79a29b5e5f20127ec2286413510662d0e6befa29d669a623035122753d3affffffff013d000000000000001976a914047f8e69ca8eadec1b327d1b232cdaaffa200d1688ac00000000"
    )

    tx = Transaction(
        [
            TransactionInput(
                source_transaction=source_tx,
                source_txid=source_tx.txid(),
                source_output_index=0,
                unlocking_script_template=P2PKH().unlock(private_key),
            )
        ],
        [
            TransactionOutput(
                locking_script=P2PKH().lock("1QnWY1---------3DDeWUC2VLn"),
                change=True
            )
        ],
    )

    tx.fee()
    tx.sign()
    txid = tx.txid()
    txhex = tx.hex()
    print(f"Transaction ID: {txid}")
    print(f"Transaction hex: {txhex}")
    # Broadcast transaction

    result = arc.sync_broadcast(tx)

    if isinstance(result, BroadcastResponse):
        print(f"Broadcast successful: {result.txid}")

        # Check status
        status = arc.check_transaction_status(result.txid)
        print(f"Status: {status.get('txStatus', 'Unknown')}")

        # Categorize status
        category = arc.categorize_transaction_status(status)
        print(f"Category: {category.get('status_category')}")

    else:
        print(f"Broadcast failed: {result.description}")


if __name__ == "__main__":
    main()

