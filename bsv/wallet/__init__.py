from .key_deriver import KeyDeriver, Protocol, Counterparty, CounterpartyType
from .cached_key_deriver import CachedKeyDeriver
from .wallet_impl import ProtoWallet
from .wallet_interface import WalletInterface

# WalletImpl is a deprecated alias for ProtoWallet (backward compatibility)
# Use ProtoWallet for new code - matches TS/Go SDK naming
WalletImpl = ProtoWallet

__all__ = [
    'KeyDeriver', 'Protocol', 'Counterparty', 'CounterpartyType',
    'CachedKeyDeriver', 'ProtoWallet', 'WalletImpl', 'WalletInterface'
]
