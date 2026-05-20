from abc import ABC, abstractmethod

from .script import Script


class UnlockingScriptTemplate(ABC):
    @staticmethod
    @abstractmethod
    def sign(tx, input_index) -> Script:
        pass

    @staticmethod
    @abstractmethod
    def estimated_unlocking_byte_length() -> int:
        pass
