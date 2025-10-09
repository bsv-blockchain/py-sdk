from typing import Union, TYPE_CHECKING, Optional, Dict, Any
import time
from ..http_client import HttpClient, default_http_client
from ..constants import Network
from .broadcaster import Broadcaster, BroadcastResponse, BroadcastFailure

if TYPE_CHECKING:
    from ..transaction import Transaction


class WhatsOnChainBroadcaster(Broadcaster):
    """
    Asynchronous WhatsOnChain broadcaster using HttpClient.
    """
    def __init__(self, network: Union[Network, str] = Network.MAINNET, http_client: HttpClient = None):
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


class WhatsOnChainBroadcasterSync:
    """
    Synchronous WhatsOnChain broadcaster using requests, with retry/backoff and error classification.
    """
    def __init__(self, *, api_key: Optional[str] = None, network: str = "main"):
        self.api_key = api_key or ""
        self.network = network

    def broadcast(self, tx_hex: str, *, api_key: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:
        import requests
        key = api_key or self.api_key
        headers = {}
        if key:
            headers["Authorization"] = key
            headers["woc-api-key"] = key
        url = f"https://api.whatsonchain.com/v1/bsv/{self.network}/tx/raw"
        last_err: Optional[Exception] = None
        for attempt in range(3):
            try:
                resp = requests.post(url, json={"txhex": tx_hex}, headers=headers, timeout=timeout)
                if resp.status_code >= 500:
                    raise RuntimeError(f"woc server error {resp.status_code}")
                resp.raise_for_status()
                data = resp.text or ""  # WOC returns plain text txid
                return {"accepted": True, "txid": data}
            except Exception as e:  # noqa: PERF203
                last_err = e
                try:
                    time.sleep(0.25 * (2 ** attempt))
                except Exception:
                    pass
        msg = str(last_err or "broadcast failed")
        code = "network" if "server error" in msg or "timeout" in msg.lower() else "client"
        return {"accepted": False, "code": code, "error": f"WOC broadcast failed: {msg}"}


__all__ = [
    "WhatsOnChainBroadcaster",
    "WhatsOnChainBroadcasterSync",
]