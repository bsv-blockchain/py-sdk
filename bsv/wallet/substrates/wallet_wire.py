from abc import ABC, abstractmethod
from typing import Any

class WalletWire(ABC):
    """
    Python port of Go's WalletWire interface.
    Abstraction over a raw transport medium for sending/receiving binary data to/from a wallet.
    """
    @abstractmethod
    def transmit_to_wallet(self, ctx: Any, message: bytes) -> bytes:
        """
        Send a binary message to the wallet and return the binary response.
        """
        pass
