from dataclasses import dataclass, field
from typing import Any, List, Optional

from ..keys import PrivateKey, PublicKey


# Protocol and SecurityLevel (ported from go-sdk)
class SecurityLevel:
    SILENT = 0
    EVERY_APP = 1
    EVERY_APP_AND_COUNTERPARTY = 2


@dataclass
class Protocol:
    security_level: int = SecurityLevel.SILENT
    protocol: str = ""  # NOSONAR - Field names match protocol specification


# CounterpartyType and Counterparty (ported from go-sdk)
class CounterpartyType:
    UNINITIALIZED = 0
    ANYONE = 1
    SELF = 2
    OTHER = 3


@dataclass
class Counterparty:
    type: int = CounterpartyType.UNINITIALIZED
    counterparty: Optional[PublicKey] = None  # NOSONAR - Field names match protocol specification


# EncryptionArgs (common cryptographic parameters)
@dataclass
class EncryptionArgs:
    protocol_id: Protocol = field(default_factory=Protocol)
    key_id: str = ""
    counterparty: Counterparty = field(default_factory=Counterparty)
    privileged: bool = False
    privileged_reason: str = ""
    seek_permission: bool = False


# BytesList is just bytes or List[bytes] in Python
BytesList = bytes  # For now, use bytes; can be List[bytes] if needed


# EncryptArgs (extends EncryptionArgs)
@dataclass
class EncryptArgs(EncryptionArgs):
    plaintext: BytesList = b""


# DecryptArgs (extends EncryptionArgs)
@dataclass
class DecryptArgs(EncryptionArgs):
    ciphertext: BytesList = b""


# EncryptResult
@dataclass
class EncryptResult:
    ciphertext: BytesList


# DecryptResult
@dataclass
class DecryptResult:
    plaintext: BytesList


# Placeholder for future cryptographic operations (to be implemented)
def encrypt(args: EncryptArgs, private_key: PrivateKey) -> EncryptResult:
    """Encrypt data using ECIES/BIE1 encryption scheme (not yet implemented)."""
    raise NotImplementedError("Encryption operation is not yet implemented.")


def decrypt(args: DecryptArgs, private_key: PrivateKey) -> DecryptResult:
    """Decrypt data using ECIES/BIE1 decryption scheme (not yet implemented)."""
    raise NotImplementedError("Decryption operation is not yet implemented.")


# ---------------------------------------------------------------------------
# Public re-exports – makes `bsv.keystore` a convenient facade.
# ---------------------------------------------------------------------------
from .interfaces import (
    KeyValue,
    KVStoreConfig,
    KVStoreInterface,
    NewLocalKVStoreOptions,
)
from .local_kv_store import LocalKVStore

__all__ = [
    "Counterparty",
    "CounterpartyType",
    "DecryptArgs",
    "DecryptResult",
    "EncryptArgs",
    "EncryptResult",
    "EncryptionArgs",
    "KVStoreConfig",
    # kv-store API
    "KVStoreInterface",
    "KeyValue",
    "LocalKVStore",
    "NewLocalKVStoreOptions",
    # encryption helpers
    "Protocol",
    "SecurityLevel",
    "decrypt",
    "encrypt",
]
