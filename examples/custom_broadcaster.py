import asyncio
from typing import Union

from bsv import (
    P2PKH,
    Broadcaster,
    BroadcastFailure,
    BroadcastResponse,
    HttpClient,
    PrivateKey,
    Transaction,
    TransactionInput,
    TransactionOutput,
    default_http_client,
)


class WOC(Broadcaster):
    def __init__(self, network: str = "main", http_client: HttpClient = None):
        """
        Constructs an instance of the WOC broadcaster.

        :param network: which network to use (test or main)
        :param http_client: HTTP client to use. If None, will use default.
        """
        self.network = network
        self.URL = f"https://api.whatsonchain.com/v1/bsv/{network}/tx/raw"
        self.http_client = http_client if http_client else default_http_client()

    async def broadcast(self, tx: Transaction) -> Union[BroadcastResponse, BroadcastFailure]:
        """
        Broadcasts a transaction via WOC.

        :param tx: The transaction to be broadcasted as a serialized hex string.
        :returns: BroadcastResponse or BroadcastFailure.
        """
        request_options = {
            "method": "POST",
            "headers": {"Content-Type": "application/json", "Accept": "text/plain"},
            "data": {"txhex": tx.hex()},
        }

        try:
            response = await self.http_client.fetch(self.URL, request_options)
            if response.ok:
                txid = response.json()["data"]
                return BroadcastResponse(status="success", txid=txid, message="broadcast successful")
            else:
                return BroadcastFailure(
                    status="error",
                    code=str(response.status_code),
                    description=response.json()["data"],
                )
        except Exception as error:
            return BroadcastFailure(
                status="error",
                code="500",
                description=(str(error) if str(error) else "Internal Server Error"),
            )


async def main():
    # Example usage of out custom broadcaster:
    private_key = PrivateKey("L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9")
    public_key = private_key.public_key()

    source_tx = Transaction.from_hex(
        "0100000001d43b53af268f65ca069f74d136114649e0eaf937c670952b70c5ecbb0ad7ba01010000006b48304502210097930e1a4b7e4be3d3ee3f61f19ed1066bb02967f008eff35800d0a840c2e8b60220152ec14f254e666b1b22f4c9e87226c811b4e87f19158bfd2d06329fefffaf53c1210359b25103c255f3a9c2fbcd11a6ec842b21e6cb1bb9c27d2e8a3322aae0e6e8a0ffffffff0278000000000000001976a9147610cb8647332db7bb7f526360fde5f7842fa57988acbb7f0100000000001976a9147610cb8647332db7bb7f526360fde5f7842fa57988ac00000000"
    )

    tx = Transaction()

    tx.add_input(
        TransactionInput(
            source_transaction=source_tx,
            source_txid=source_tx.txid(),
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(private_key),
        )
    )

    tx.add_output(TransactionOutput(locking_script=P2PKH().lock(public_key.address()), satoshis=100))

    tx.sign()

    res = await tx.broadcast(WOC("test"))

    if isinstance(res, BroadcastResponse):
        print("Tx has been broadcast:", res.txid)
    else:
        print("Broadcast failed. Error:", res.description)


asyncio.run(main())
