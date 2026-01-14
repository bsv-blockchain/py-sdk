import asyncio

from bsv import ARC, P2PKH, ARCConfig, BroadcastResponse, PrivateKey, Transaction, TransactionInput, TransactionOutput

arc_broadcaster = ARC(url="https://api.taal.com/arc", config=ARCConfig(api_key="mainnet_xxxxx..."))


async def main():
    private_key = PrivateKey("L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9")
    private_key_2 = PrivateKey("L1eCvvbFn4EXgE5iRjTMQNWn1h3ktgTNm9jrR2eoymYnsZvfcL2R")

    public_key = private_key.public_key()
    public_key_2 = private_key_2.public_key()

    source_tx = Transaction.from_hex(
        "0100000001eeb21380e84020930b11e1c589cfdf9fc2ffa6d92eb1472248a11cd130ccf4ee000000006a47304402206d39bcb757c43a58e21891cf5d0e7af8f99a3305b8e355bff5596f12df52db160220618e76c695959d89e259d5bb6cbeede899cdcc168d3344735b2250a266dd37a8c1210359b25103c255f3a9c2fbcd11a6ec842b21e6cb1bb9c27d2e8a3322aae0e6e8a0ffffffff02f4010000000000001976a9147610cb8647332db7bb7f526360fde5f7842fa57988ac76753c00000000001976a9147610cb8647332db7bb7f526360fde5f7842fa57988ac00000000"
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

    res = await tx1.broadcast(arc_broadcaster)

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

    res = await tx2.broadcast(arc_broadcaster)

    if isinstance(res, BroadcastResponse):
        print("Tx2 has been broadcast:", res.txid)
    else:
        print("Broadcast failed. Error:", res.description)


asyncio.run(main())
