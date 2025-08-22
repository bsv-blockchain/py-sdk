"""
address.py - Utilities for address and WIF decoding/validation.
"""
import re
from typing import Tuple, Optional
from ..constants import Network, ADDRESS_PREFIX_NETWORK_DICT, WIF_PREFIX_NETWORK_DICT
from .base58_utils import from_base58_check

def decode_address(address: str) -> Tuple[bytes, Network]:
    if not re.match(r'^[1mn][a-km-zA-HJ-NP-Z1-9]{24,33}$', address):
        raise ValueError(f'invalid P2PKH address {address}')
    from ..base58 import base58check_decode
    decoded = base58check_decode(address)
    prefix = decoded[:1]
    network = ADDRESS_PREFIX_NETWORK_DICT.get(prefix)
    return decoded[1:], network

def validate_address(address: str, network: Optional[Network] = None) -> bool:
    from contextlib import suppress
    with suppress(Exception):
        _, _network = decode_address(address)
        if network is not None:
            return _network == network
        return True
    return False

def address_to_public_key_hash(address: str) -> bytes:
    return decode_address(address)[0]

def decode_wif(wif: str) -> Tuple[bytes, bool, Network]:
    from ..base58 import base58check_decode
    decoded = base58check_decode(wif)
    prefix = decoded[:1]
    network = WIF_PREFIX_NETWORK_DICT.get(prefix)
    if not network:
        raise ValueError(f'unknown WIF prefix {prefix.hex()}')
    if len(wif) == 52 and decoded[-1] == 1:
        return decoded[1:-1], True, network
    return decoded[1:], False, network