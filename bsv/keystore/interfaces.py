from __future__ import annotations

"""
interfaces.py (Python port of go-sdk/kvstore/interfaces.go)

This module defines the public interfaces, configuration structures and error
classes for a blockchain-backed key–value store that is built on top of the
`WalletInterface`.  The full on-chain implementation lives in
`local_kv_store.py`.  At the moment only an in-memory prototype is provided so
that higher-level code can begin integrating against the same API while the
transaction logic is still under construction.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, List, Optional

# NOTE: We purposely import inside type-checking blocks to avoid a run-time
# dependency cycle — `bsv.wallet` already depends on parts of `bsv.keystore` for
# encryption structures.  `WalletInterface` is only required for type hints.
try:
    from bsv.wallet.WalletInterface import WalletInterface  # pragma: no cover
except (ImportError, ModuleNotFoundError):  # pragma: no cover
    WalletInterface = Any  # Fallback during early bootstrap


# ---------------------------------------------------------------------------
# Errors (mirrors go-sdk/kvstore/interfaces.go)
# ---------------------------------------------------------------------------

class KVStoreError(Exception):
    """Base-class for all KV-Store related exceptions."""


class ErrInvalidWallet(KVStoreError):
    pass


class ErrEmptyContext(KVStoreError):
    pass


class ErrKeyNotFound(KVStoreError):
    pass


class ErrCorruptedState(KVStoreError):
    pass


class ErrWalletOperation(KVStoreError):
    pass


class ErrTransactionCreate(KVStoreError):
    pass


class ErrTransactionSign(KVStoreError):
    pass


class ErrEncryption(KVStoreError):
    pass


class ErrDataParsing(KVStoreError):
    pass


class ErrInvalidRetentionPeriod(KVStoreError):
    pass


class ErrInvalidOriginator(KVStoreError):
    pass


class ErrInvalidBasketName(KVStoreError):
    pass


class ErrInvalidKey(KVStoreError):
    pass


class ErrInvalidValue(KVStoreError):
    pass


# ---------------------------------------------------------------------------
# Data structures / configuration
# ---------------------------------------------------------------------------

@dataclass
class KVStoreConfig:
    """Configuration required to create a new key-value store instance."""

    wallet: WalletInterface  # Wallet abstraction used for signing/creating txs
    context: str             # Developer-supplied logical namespace (basket)
    originator: str = ""     # Name/id of the app using the store (optional)
    encrypt: bool = False    # Whether to encrypt values before storage


@dataclass
class NewLocalKVStoreOptions:
    """Extended configuration mirroring `NewLocalKVStoreOptions` in Go."""

    wallet: WalletInterface
    originator: str
    context: str
    retention_period: int = 0  # seconds / blocks – semantics TBD
    basket_name: str = ""
    encrypt: bool = False


@dataclass
class KeyValue:
    """Simple key–value pair container (useful for testing/mocking)."""

    key: str
    value: str


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class KVStoreInterface(ABC):
    """Python equivalent of `kvstore.KVStoreInterface` in the Go SDK."""

    # We purposefully keep the `ctx` parameter as *Any* for maximum flexibility —
    # both `asyncio` and synchronous code can pass through whatever context
    # object they deem appropriate.

    @abstractmethod
    def get(self, ctx: Any, key: str, default_value: str = "") -> str:  # noqa: N802
        """Retrieve a value for *key* or *default_value* if not found."""

    @abstractmethod
    def set(self, ctx: Any, key: str, value: str) -> str:  # noqa: N802
        """Store *value* under *key* – returns the out-point reference."""

    @abstractmethod
    def remove(self, ctx: Any, key: str) -> List[str]:  # noqa: N802
        """Delete *key* from the store – returns txids that performed removal."""

