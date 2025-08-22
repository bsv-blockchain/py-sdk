from typing import Union, TYPE_CHECKING

from ..broadcaster import Broadcaster, BroadcastFailure, BroadcastResponse
from ..http_client import HttpClient, default_http_client
from ..constants import Network

if TYPE_CHECKING:
    from ..transaction import Transaction

class WhatsOnChainBroadcaster(Broadcaster):
    def __init__(self, network: Union[Network, str] = Network.MAINNET, http_client: HttpClient = None):
        """
        Initialize WhatsOnChainBroadcaster.
        
        :param network: Network to broadcast to. Can be either Network enum or string ('main'/'test')
        :param http_client: Optional HTTP client to use for requests
        """
        if isinstance(network, str):
            network_str = network.lower()
            if network_str in ['main', 'mainnet']:
                self.network = 'main'
            elif network_str in ['test', 'testnet']:
                self.network = 'test'
            else:
                raise ValueError(f"Invalid network string: {network}. Must be 'main' or 'test'")
        else:
            self.network = 'main' if network == Network.MAINNET else 'test'
            
        self.URL = f"https://api.whatsonchain.com/v1/bsv/{self.network}/tx/raw"
        self.http_client = http_client if http_client else default_http_client()

    async def broadcast(
        self, tx: 'Transaction'
    ) -> Union[BroadcastResponse, BroadcastFailure]:
        request_options = {
            "method": "POST",
            "headers": {"Content-Type": "application/json", "Accept": "text/plain"},
            "data": {"txhex": tx.hex()},
        }

        try:
            response = await self.http_client.fetch(self.URL, request_options)
            if response.ok:
                txid = response.json()["data"]
                return BroadcastResponse(
                    status="success", txid=txid, message="broadcast successful"
                )
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
