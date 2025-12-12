from abc import ABC, abstractmethod
from typing import Union, Dict, Any, TYPE_CHECKING, Optional
from ..http_client import HttpClient
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
    

class BroadcasterInterface:
    """Abstract broadcaster interface.

    Implementations should return a dict with either:
      {"accepted": True, "txid": "..."}
    or {"accepted": False, "code": "network|client", "error": "..."}
    """

    def broadcast(self, tx_hex: str, *, api_key: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:  # noqa: D401
        raise NotImplementedError


__all__ = [
    "BroadcastResponse",
    "BroadcastFailure",
    "Broadcaster",
    "BroadcasterInterface",
    "is_broadcast_response",
    "is_broadcast_failure",
]