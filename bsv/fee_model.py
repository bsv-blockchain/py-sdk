from abc import ABC, abstractmethod
from typing import Awaitable


class FeeModel(ABC):
    """
    Represents the interface for a transaction fee model.
    This interface defines a standard method for computing a fee when given a transaction.

    @interface
    @property {function} computeFee - A function that takes a Transaction object and returns an integer representing the number of satoshis the transaction should cost.
    """

    @abstractmethod
    def compute_fee(self, transaction) -> int:
        pass
