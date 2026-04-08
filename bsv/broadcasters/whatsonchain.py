import time
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from ..constants import Network
from ..http_client import HttpClient, default_http_client
from .broadcaster import Broadcaster, BroadcastFailure, BroadcastResponse

if TYPE_CHECKING:
    from ..transaction import Transaction


def _woc_parse_success_txid(body) -> str:
    """Normalize WoC /tx/raw success body to a txid string (HttpClient wraps once as {"data": ...})."""
    if isinstance(body, str):
        s = body.strip()
        if s:
            return s
    if isinstance(body, dict):
        inner = body.get("data")
        if inner is not None and inner is not body:
            return _woc_parse_success_txid(inner)
    raise ValueError(f"cannot read txid from WoC response: {body!r}")


def _woc_parse_error_description(body) -> str:
    if body is None:
        return "empty response body"
    if isinstance(body, str):
        return body
    if isinstance(body, dict):
        err = body.get("data")
        if isinstance(err, str):
            return err
        return str(body.get("message") or body)
    return str(body)


def _woc_desc_means_already_broadcast(desc: str) -> bool:
    """WoC sometimes returns non-2xx (e.g. 500) with a body that means accept (tx already in mempool)."""
    d = desc.lower()
    return (
        "already in the mempool" in d
        or "already in mempool" in d
        or "txn-already-in-mempool" in d
        or "transaction already in" in d
        or "already known" in d
        or "duplicate" in d
    )


class WhatsOnChainBroadcaster(Broadcaster):
    """
    Asynchronous WhatsOnChain broadcaster using HttpClient.
    """

    def __init__(self, network: Union[Network, str] = Network.MAINNET, http_client: HttpClient = None):
        if isinstance(network, str):
            network_str = network.lower()
            if network_str in ["main", "mainnet"]:
                self.network = "main"
            elif network_str in ["test", "testnet"]:
                self.network = "test"
            else:
                raise ValueError(f"Invalid network string: {network}. Must be 'main' or 'test'")
        else:
            self.network = "main" if network == Network.MAINNET else "test"
        self.URL = f"https://api.whatsonchain.com/v1/bsv/{self.network}/tx/raw"
        self.http_client = http_client if http_client else default_http_client()

    async def broadcast(self, tx: "Transaction") -> Union[BroadcastResponse, BroadcastFailure]:
        request_options = {
            "method": "POST",
            "headers": {"Content-Type": "application/json", "Accept": "text/plain"},
            "data": {"txhex": tx.hex()},
        }
        try:
            response = await self.http_client.fetch(self.URL, request_options)
            body = response.json().get("data")
            if response.ok:
                try:
                    txid = _woc_parse_success_txid(body)
                except ValueError as e:
                    return BroadcastFailure(status="error", code=str(response.status_code), description=str(e))
                return BroadcastResponse(status="success", txid=txid, message="broadcast successful")
            desc = _woc_parse_error_description(body)
            if _woc_desc_means_already_broadcast(desc):
                return BroadcastResponse(
                    status="success",
                    txid=tx.txid(),
                    message="already in mempool (WhatsOnChain)",
                )
            return BroadcastFailure(status="error", code=str(response.status_code), description=desc)
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

    def broadcast(self, tx_hex: str, *, api_key: Optional[str] = None, timeout: int = 10) -> dict[str, Any]:
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
            except Exception as e:
                last_err = e
                try:
                    time.sleep(0.25 * (2**attempt))
                except Exception:
                    pass
        msg = str(last_err or "broadcast failed")
        code = "network" if "server error" in msg or "timeout" in msg.lower() else "client"
        return {"accepted": False, "code": code, "error": f"WOC broadcast failed: {msg}"}


__all__ = [
    "WhatsOnChainBroadcaster",
    "WhatsOnChainBroadcasterSync",
]
