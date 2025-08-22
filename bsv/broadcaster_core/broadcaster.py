from abc import ABC, abstractmethod
from typing import Union, Dict, Any, TYPE_CHECKING


if TYPE_CHECKING:
    from .transaction import Transaction

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
