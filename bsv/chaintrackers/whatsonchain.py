from typing import Optional, Dict

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
        request_options = {"method": "GET", "headers": self.get_headers()}

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

    def get_headers(self) -> Dict[str, str]:
        headers = {}
        if self.api_key:
            headers["Authorization"] = self.api_key
        return headers
