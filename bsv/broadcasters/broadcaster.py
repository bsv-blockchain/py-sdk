from abc import ABC, abstractmethod
from typing import Union, Dict, Any, TYPE_CHECKING
from ..http_client import HttpClient, default_http_client
from ..constants import Network

if TYPE_CHECKING:
    from ..transaction import Transaction


class BroadcastResponse:
    def __init__(self, status: str, txid: str, message: str):
        self.status = status
        self.txid = txid
        self.message = message


class BroadcastFailure:
    def __init__(
            self,
            status: str,
            code: str,
            description: str,
            txid: str = None,
            more: Dict[str, Any] = None,
    ):
        self.status = status
        self.code = code
        self.txid = txid
        self.description = description
        self.more = more


class Broadcaster(ABC):
    def __init__(self):
        self.URL = None

    @abstractmethod
    async def broadcast(
            self, transaction: 'Transaction'
    ) -> Union[BroadcastResponse, BroadcastFailure]:
        pass


def is_broadcast_response(r: Union[BroadcastResponse, BroadcastFailure]) -> bool:
    return r.status == "success"


def is_broadcast_failure(r: Union[BroadcastResponse, BroadcastFailure]) -> bool:
    return r.status == "error"

class MAPIClientBroadcaster(BroadcasterInterface):
    """mAPI (Merchant API) broadcaster for BSV miners."""
    def __init__(self, *, api_url: str, api_key: Optional[str] = None, network: str = "main"):
        self.api_url = api_url
        self.api_key = api_key or ""
        self.network = network

    def broadcast(self, tx_hex: str, *, api_key: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:
        import requests
        key = api_key or self.api_key
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = key
        url = self.api_url
        last_err: Optional[Exception] = None
        for attempt in range(3):
            try:
                resp = requests.post(url, json={"rawtx": tx_hex}, headers=headers, timeout=timeout)
                if resp.status_code >= 500:
                    raise RuntimeError(f"mAPI server error {resp.status_code}")
                resp.raise_for_status()
                data = resp.json() or {}
                txid = data.get("txid") or data.get("payload", {}).get("txid") or ""
                if data.get("returnResult") == "success" or data.get("payload", {}).get("returnResult") == "success":
                    return {"accepted": True, "txid": txid}
                return {"accepted": False, "error": data.get("resultDescription", "broadcast failed"), "txid": txid}
            except Exception as e:
                last_err = e
                try:
                    time.sleep(0.25 * (2 ** attempt))
                except Exception:
                    pass
        msg = str(last_err or "broadcast failed")
        code = "network" if "server error" in msg or "timeout" in msg.lower() else "client"
        return {"accepted": False, "code": code, "error": f"mAPI broadcast failed: {msg}"}

class CustomNodeBroadcaster(BroadcasterInterface):
    """Custom node broadcaster (e.g., direct to bitcoind REST)."""
    def __init__(self, *, api_url: str, api_key: Optional[str] = None):
        self.api_url = api_url
        self.api_key = api_key or ""

    def broadcast(self, tx_hex: str, *, api_key: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:
        import requests
        key = api_key or self.api_key
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = key
        url = self.api_url
        last_err: Optional[Exception] = None
        for attempt in range(3):
            try:
                resp = requests.post(url, json={"hex": tx_hex}, headers=headers, timeout=timeout)
                if resp.status_code >= 500:
                    raise RuntimeError(f"custom node server error {resp.status_code}")
                resp.raise_for_status()
                data = resp.json() or {}
                txid = data.get("txid") or data.get("result") or ""
                if txid:
                    return {"accepted": True, "txid": txid}
                return {"accepted": False, "error": data.get("error", "broadcast failed"), "txid": txid}
            except Exception as e:
                last_err = e
                try:
                    time.sleep(0.25 * (2 ** attempt))
                except Exception:
                    pass
        msg = str(last_err or "broadcast failed")
        code = "network" if "server error" in msg or "timeout" in msg.lower() else "client"
        return {"accepted": False, "code": code, "error": f"Custom node broadcast failed: {msg}"}



__all__ = [
    "BroadcastResponse",
    "BroadcastFailure",
    "Broadcaster",
    "default_broadcaster",
    "is_broadcast_response",
    "is_broadcast_failure",
]
