"""
BIP276 encoding/decoding for Bitcoin scripts.

BIP276 proposes a scheme for encoding typed bitcoin related data in a user-friendly way.
See https://github.com/moneybutton/bips/blob/master/bip-0276.mediawiki

Ported from go-sdk/script/bip276.go
"""

import re
from dataclasses import dataclass
from typing import Optional
from bsv.hash import hash256


# Prefixes
PREFIX_SCRIPT = "bitcoin-script"
PREFIX_TEMPLATE = "bitcoin-template"

# Version
CURRENT_VERSION = 1

# Networks
NETWORK_MAINNET = 1
NETWORK_TESTNET = 2


class BIP276Error(Exception):
    """Base exception for BIP276 errors."""
    pass


class InvalidBIP276Format(BIP276Error):
    """Raised when BIP276 format is invalid."""
    pass


class InvalidChecksum(BIP276Error):
    """Raised when BIP276 checksum is invalid."""
    pass


@dataclass
class BIP276:
    """
    BIP276 represents encoded Bitcoin data with prefix, version, network, and data.
    """
    prefix: str
    version: int
    network: int
    data: bytes


# Regex pattern for validating BIP276 format
# Format: prefix:VVNN<data><checksum>
# VV = version (2 hex digits), NN = network (2 hex digits)
# data = hex encoded data (can be empty), checksum = 8 hex digits (4 bytes)
VALID_BIP276_PATTERN = re.compile(r'^(.+?):(\d{2})(\d{2})([0-9A-Fa-f]*)([0-9A-Fa-f]{8})$')


def encode_bip276(script: BIP276) -> str:
    """
    Encode a BIP276 object into a BIP276 formatted string.
    
    Args:
        script: BIP276 object to encode
        
    Returns:
        BIP276 formatted string
        
    Raises:
        ValueError: If version or network is out of valid range (1-255)
    """
    if script.version == 0 or script.version > 255:
        raise ValueError(f"Invalid version: {script.version}. Must be between 1 and 255.")
    if script.network == 0 or script.network > 255:
        raise ValueError(f"Invalid network: {script.network}. Must be between 1 and 255.")
    
    payload, checksum = _create_bip276_parts(script)
    return payload + checksum


def _create_bip276_parts(script: BIP276) -> tuple[str, str]:
    """
    Create the payload and checksum parts of a BIP276 string.
    
    Args:
        script: BIP276 object
        
    Returns:
        Tuple of (payload, checksum) strings
    """
    # Format: prefix:VVNN<hex_data>
    # VV = network (2 hex digits), NN = version (2 hex digits)
    # Note: Go SDK has network first, then version
    payload = f"{script.prefix}:{script.network:02x}{script.version:02x}{script.data.hex()}"
    
    # Checksum is first 4 bytes of double SHA256 of payload
    checksum_bytes = hash256(payload.encode('utf-8'))[:4]
    checksum = checksum_bytes.hex()
    
    return payload, checksum


def decode_bip276(text: str) -> BIP276:
    """
    Decode a BIP276 formatted string into a BIP276 object.
    
    Args:
        text: BIP276 formatted string
        
    Returns:
        BIP276 object
        
    Raises:
        InvalidBIP276Format: If the format doesn't match BIP276 specification
        InvalidChecksum: If the checksum doesn't match
    """
    # Match the regex pattern
    match = VALID_BIP276_PATTERN.match(text)
    
    if not match:
        raise InvalidBIP276Format(f"Text does not match BIP276 format: {text}")
    
    # Extract components
    prefix = match.group(1)
    network_str = match.group(2)
    version_str = match.group(3)
    data_hex = match.group(4)
    provided_checksum = match.group(5)
    
    # Parse version and network
    try:
        network = int(network_str)
        version = int(version_str)
    except ValueError as e:
        raise InvalidBIP276Format(f"Invalid version or network format: {e}")
    
    # Decode data
    try:
        data = bytes.fromhex(data_hex)
    except ValueError as e:
        raise InvalidBIP276Format(f"Invalid hex data: {e}")
    
    # Create BIP276 object and verify checksum
    script = BIP276(
        prefix=prefix,
        version=version,
        network=network,
        data=data
    )
    
    _, expected_checksum = _create_bip276_parts(script)
    
    if provided_checksum.lower() != expected_checksum.lower():
        raise InvalidChecksum(
            f"Checksum mismatch. Expected: {expected_checksum}, got: {provided_checksum}"
        )
    
    return script


# Convenience functions for common use cases

def encode_script(data: bytes, network: int = NETWORK_MAINNET, version: int = CURRENT_VERSION) -> str:
    """
    Encode script data as BIP276 with bitcoin-script prefix.
    
    Args:
        data: Script bytes to encode
        network: Network identifier (default: mainnet)
        version: Version number (default: 1)
        
    Returns:
        BIP276 formatted string
    """
    script = BIP276(
        prefix=PREFIX_SCRIPT,
        version=version,
        network=network,
        data=data
    )
    return encode_bip276(script)


def encode_template(data: bytes, network: int = NETWORK_MAINNET, version: int = CURRENT_VERSION) -> str:
    """
    Encode template data as BIP276 with bitcoin-template prefix.
    
    Args:
        data: Template bytes to encode
        network: Network identifier (default: mainnet)
        version: Version number (default: 1)
        
    Returns:
        BIP276 formatted string
    """
    script = BIP276(
        prefix=PREFIX_TEMPLATE,
        version=version,
        network=network,
        data=data
    )
    return encode_bip276(script)


def decode_script(text: str) -> bytes:
    """
    Decode a BIP276 formatted script string and return the data.
    
    Args:
        text: BIP276 formatted string
        
    Returns:
        Decoded script bytes
        
    Raises:
        InvalidBIP276Format: If format is invalid or prefix is not bitcoin-script
    """
    script = decode_bip276(text)
    if script.prefix != PREFIX_SCRIPT:
        raise InvalidBIP276Format(f"Expected prefix '{PREFIX_SCRIPT}', got '{script.prefix}'")
    return script.data


def decode_template(text: str) -> bytes:
    """
    Decode a BIP276 formatted template string and return the data.
    
    Args:
        text: BIP276 formatted string
        
    Returns:
        Decoded template bytes
        
    Raises:
        InvalidBIP276Format: If format is invalid or prefix is not bitcoin-template
    """
    script = decode_bip276(text)
    if script.prefix != PREFIX_TEMPLATE:
        raise InvalidBIP276Format(f"Expected prefix '{PREFIX_TEMPLATE}', got '{script.prefix}'")
    return script.data

