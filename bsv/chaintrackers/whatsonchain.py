from typing import Optional, Dict
from typing import Any

from bsv.chaintracker import ChainTracker
from bsv.http_client import HttpClient, default_http_client


class WhatsOnChainTracker(ChainTracker):
    def __init__(
            self,
            network: str = "main",
            api_key: Optional[str] = None,
            http_client: Optional[HttpClient] = None,
    ):
        self.network = network
        self.URL = f"https://api.whatsonchain.com/v1/bsv/{network}"
        self.http_client = (
            http_client if http_client else default_http_client()
        )
        self.api_key = api_key

    async def is_valid_root_for_height(self, root: str, height: int) -> bool:
        # NOTE:
        #   Use the base class' get_headers implementation directly to avoid
        #   being affected by subclasses that may overload `get_headers`
        #   with a different signature (e.g. wallet-toolbox's Chaintracks
        #   adapter, which adds height/count parameters).
        #   Calling WhatsOnChainTracker.get_headers(self) guarantees we
        #   always get the HTTP header dict expected here.
        request_options = {
            "method": "GET",
            "headers": WhatsOnChainTracker.get_headers(self),
        }

        response = await self.http_client.fetch(
            f"{self.URL}/block/{height}/header", request_options
        )
        if response.ok:
            merkleroot = response.json()['data'].get("merkleroot")
            return merkleroot == root
        elif response.status_code == 404:
            return False
        else:
            raise RuntimeError(
                f"Failed to verify merkleroot for height {height} because of an error: {response.json()}"
            )

    async def current_height(self) -> int:
        """Get current blockchain height from WhatsOnChain API.
        
        Implements ChainTracker.current_height() from SDK.
        """
        # See note in is_valid_root_for_height(): we intentionally call the
        # base-class implementation of get_headers() so that subclasses
        # are free to introduce their own Chaintracks-style `get_headers`
        # without breaking this SDK tracker.
        request_options = {
            "method": "GET",
            "headers": WhatsOnChainTracker.get_headers(self),
        }

        response = await self.http_client.fetch(f"{self.URL}/chain/info", request_options)
        if response.ok:
            data = response.json()
            return data.get("blocks", 0)
        else:
            raise RuntimeError(f"Failed to get current height: {response.json()}")

    def get_headers(self) -> Dict[str, str]:
        headers = {}
        if self.api_key:
            headers["Authorization"] = self.api_key
        return headers

    def query_tx(self, txid: str, *, api_key: Optional[str] = None, network: str = "main", timeout: int = 10) -> Dict[str, Any]:
        import requests
        key = api_key or self.api_key
        net = network or self.network
        url = f"https://api.whatsonchain.com/v1/bsv/{net}/tx/{txid}/info"
        headers = {}
        if key:
            headers["Authorization"] = key
            headers["woc-api-key"] = key
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 404:
                return {"known": False}
            resp.raise_for_status()
            data = resp.json() or {}
            conf = data.get("confirmations")
            return {"known": True, "confirmations": conf or 0}
        except Exception as e:  # noqa: PERF203
            return {"known": False, "error": str(e)}


