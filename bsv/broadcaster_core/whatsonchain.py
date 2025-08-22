import os
import requests

class WhatsOnChainBroadcaster:
    """
    Broadcasts a raw transaction to the Bitcoin SV network via WhatsOnChain API.
    Usage:
        broadcaster = WhatsOnChainBroadcaster("main")
        result = broadcaster.broadcast(tx_hex)
    """
    def __init__(self, network="main"):
        self.network = network
        self.api_key = os.environ.get("WOC_API_KEY", "")
        self.url = f"https://api.whatsonchain.com/v1/bsv/{self.network}/tx/raw"

    def broadcast(self, tx_hex: str) -> dict:
        headers = {"woc-api-key": self.api_key} if self.api_key else {}
        try:
            resp = requests.post(self.url, json={"txhex": tx_hex}, headers=headers, timeout=10)
            resp.raise_for_status()
            try:
                data = resp.json()
                return {"txid": data.get("txid") or data.get("data")}
            except Exception:
                # If not JSON, treat as raw txid string
                return {"txid": resp.text.strip()}
        except Exception as e:
            return {"error": str(e), "response": getattr(resp, 'text', None)}
