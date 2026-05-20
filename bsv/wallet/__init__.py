from .cached_key_deriver import CachedKeyDeriver
from .key_deriver import Counterparty, CounterpartyType, KeyDeriver, Protocol
from .wallet_impl import ProtoWallet
from .wallet_interface import WalletInterface

# WalletImpl is a deprecated alias for ProtoWallet (backward compatibility)
# Use ProtoWallet for new code - matches TS/Go SDK naming
WalletImpl = ProtoWallet

__all__ = [
    "CachedKeyDeriver",
    "Counterparty",
    "CounterpartyType",
    "KeyDeriver",
    "ProtoWallet",
    "Protocol",
    "WalletImpl",
    "WalletInterface",
]
