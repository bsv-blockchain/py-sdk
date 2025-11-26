from __future__ import annotations

import os
from typing import Optional

import requests


class WOCClient:
    """WhatsOnChain client (minimal) for mainnet.

    - Supports fetching raw tx hex by txid
    - Honors WOC_API_KEY environment variable if present
    - Simple, blocking HTTP calls appropriate for tooling and examples
    """

    def __init__(self, api_key: Optional[str] = None, network: str = "main") -> None:
        self.network = network
        self.api_key = api_key or os.environ.get("WOC_API_KEY") or ""

    def get_tx_hex(self, txid: str, timeout: int = 10) -> Optional[str]:
        url = f"https://api.whatsonchain.com/v1/bsv/{self.network}/tx/raw/{txid}"
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = self.api_key
            headers["woc-api-key"] = self.api_key
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        rawtx = data.get("rawtx") or data.get("hex")
        return rawtx if isinstance(rawtx, str) else None


