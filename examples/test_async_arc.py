import pytest
pytest.skip("Skipping examples in automated test run", allow_module_level=True)
import asyncio

from bsv import (
    Transaction,
    TransactionInput,
    TransactionOutput,
    PrivateKey,
    P2PKH,
    BroadcastResponse,
)
from bsv.broadcasters.default import gorillapool_broadcaster, taal_broadcaster, default_broadcaster
from bsv.broadcasters.arc import ARC

"""
Simple example of synchronous ARC broadcasting and status checking.
"""

async def main():
# def main():

    # arc = default_broadcaster()
    # arc = taal_broadcaster()
    arc = gorillapool_broadcaster()
    # Setup ARC broadcaster


    # Create a simple transaction
    private_key = PrivateKey("Kzpr5a6T-------------------dGEjxCufyxGMo9xV")
    public_key = private_key.public_key()

    source_tx = Transaction.from_hex(
        "0100000001d2e9a---------------------2aa43d541d38a94851700b6bb50348a8757cf0f318b4232aa1a6121a02203bc71f132461a046de661c33e0a0c93032dc085cb9591c8522b9eb0b296efcc9412103e23c79a29b5e5f20127ec2286413510662d0e6befa29d669a623035122753d3affffffff0134000000000000001976a914047f8e69ca8eadec1b327d1b232cdaaffa200d1688ac00000000"
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
                locking_script=P2PKH().lock("1KkyAC-----------pSUSx6QCPJ"),
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
    result = await arc.broadcast(tx)


    # Check status


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
    # main()
    asyncio.run(main())
