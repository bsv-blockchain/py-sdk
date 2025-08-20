from abc import ABC, abstractmethod
from typing import Any, Dict

class WalletInterface(ABC):
    """
    Python port of Go's wallet.Interface (core wallet operations for transaction creation, signing, querying, and cryptographic operations).
    All methods raise NotImplementedError by default.
    """

    # --- KeyOperations ---
    @abstractmethod
    def get_public_key(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def encrypt(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def create_hmac(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def verify_hmac(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def create_signature(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def verify_signature(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    # --- Core wallet operations ---
    @abstractmethod
    def create_action(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def sign_action(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def abort_action(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def list_actions(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def internalize_action(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def list_outputs(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def relinquish_output(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def reveal_counterparty_key_linkage(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def reveal_specific_key_linkage(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def acquire_certificate(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def list_certificates(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def prove_certificate(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def relinquish_certificate(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def discover_by_identity_key(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def discover_by_attributes(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def is_authenticated(self, ctx: Any, args: Any, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def wait_for_authentication(self, ctx: Any, args: Any, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def get_height(self, ctx: Any, args: Any, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def get_header_for_height(self, ctx: Any, args: Dict, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def get_network(self, ctx: Any, args: Any, originator: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def get_version(self, ctx: Any, args: Any, originator: str) -> Any:
        raise NotImplementedError