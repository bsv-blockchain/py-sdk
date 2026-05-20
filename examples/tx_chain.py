import asyncio

from bsv import (
    P2PKH,
    BroadcastResponse,
    PrivateKey,
    Transaction,
    TransactionInput,
    TransactionOutput,
    WhatsOnChainBroadcaster,
)


async def main():
    private_key = PrivateKey("L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9")
    private_key_2 = PrivateKey("L1eCvvbFn4EXgE5iRjTMQNWn1h3ktgTNm9jrR2eoymYnsZvfcL2R")

    public_key = private_key.public_key()
    public_key_2 = private_key_2.public_key()

    source_tx = Transaction.from_hex(
        "010000000130dd2d15d52dd782f75f6548a4c369cacaaaf85e920c4fc2ec3b8eba20826b95010000006a47304402204ee2653343403ba35516e43871b545f33e6cb49ba1dfde61f8ea5c2e3571ee4b02207c8524e744e99cff84820471313d32876c15cb0c71a0ad6c44281974618f511fc1210359b25103c255f3a9c2fbcd11a6ec842b21e6cb1bb9c27d2e8a3322aae0e6e8a0ffffffff02f4010000000000001976a9147610cb8647332db7bb7f526360fde5f7842fa57988ac967b0100000000001976a9147610cb8647332db7bb7f526360fde5f7842fa57988ac00000000"
    )

    tx1 = Transaction(
        [
            TransactionInput(
                source_transaction=source_tx,
                source_txid=source_tx.txid(),
                source_output_index=0,
                unlocking_script_template=P2PKH().unlock(private_key),
            )
        ],
        [
            TransactionOutput(locking_script=P2PKH().lock(public_key_2.address()), satoshis=300),
            TransactionOutput(locking_script=P2PKH().lock(public_key.address()), change=True),
        ],
    )

    tx1.fee()
    tx1.sign()

    res = await tx1.broadcast(WhatsOnChainBroadcaster("test"))

    if isinstance(res, BroadcastResponse):
        print("Tx1 has been broadcast:", res.txid)
    else:
        print("Broadcast failed. Error:", res.description)

    tx2 = Transaction(
        [
            TransactionInput(
                source_transaction=tx1,
                source_txid=tx1.txid(),
                source_output_index=0,
                unlocking_script_template=P2PKH().unlock(private_key_2),
            )
        ],
        [
            TransactionOutput(locking_script=P2PKH().lock(public_key.address()), change=True),
        ],
    )

    tx2.fee()
    tx2.sign()

    res = await tx2.broadcast(WhatsOnChainBroadcaster("test"))

    if isinstance(res, BroadcastResponse):
        print("Tx2 has been broadcast:", res.txid)
    else:
        print("Broadcast failed. Error:", res.description)


asyncio.run(main())
