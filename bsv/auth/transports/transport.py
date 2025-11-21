 
from abc import ABC, abstractmethod
from typing import Callable, Any, Optional


class Transport(ABC):
    """
    Transport interface for the auth protocol (mirrors Go interface semantics).
    Implementations must provide send and on_data.
    """

    @abstractmethod
    def send(self, ctx: Any, message: Any) -> Optional[Exception]:
        """Send an AuthMessage to the counterparty. Return an Exception on failure, else None."""
        raise NotImplementedError

    @abstractmethod
    def on_data(self, callback: Callable[[Any, Any], Optional[Exception]]) -> Optional[Exception]:
        """Register a data handler invoked on message receipt. Return an Exception on failure, else None."""
        raise NotImplementedError 


