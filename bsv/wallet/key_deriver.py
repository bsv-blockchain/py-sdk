from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
import re
import hmac
import hashlib
import os

from bsv.keys import PrivateKey, PublicKey
from bsv.hash import hmac_sha256
from bsv.curve import curve, curve_add, curve_multiply, Point  # Elliptic helpers

# secp256k1 curve order (same as coincurve.curve.n)
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass
class Protocol:  # NOSONAR - Field names match protocol specification
    security_level: int  # 0,1,2
    protocol: str  # NOSONAR - Field names match protocol specification
    
    def __init__(self, security_level: int, protocol: str):
        # Allow 3-400 characters to match TS/Go (e.g., "ctx" is valid in tests)
        # This matches _validate_protocol() behavior
        if not isinstance(protocol, str) or len(protocol) < 3 or len(protocol) > 400:
            raise ValueError("protocol names must be 3-400 characters")
        self.security_level = security_level
        self.protocol = protocol


class CounterpartyType:
    """
    Counterparty type constants matching Go SDK implementation.
    
    Go SDK reference:
    - CounterpartyUninitialized = 0
    - CounterpartyTypeAnyone    = 1
    - CounterpartyTypeSelf      = 2
    - CounterpartyTypeOther     = 3
    """
    UNINITIALIZED = 0  # Uninitialized/default state
    ANYONE = 1         # Special constant for "anyone" counterparty
    SELF = 2           # Derive vs self
    OTHER = 3          # Explicit pubkey provided


@dataclass
class Counterparty:  # NOSONAR - Field names match protocol specification
    type: int
    counterparty: Optional[PublicKey] = None  # NOSONAR - Field names match protocol specification

    def to_public_key(self, self_pub: PublicKey) -> PublicKey:
        if self.type == CounterpartyType.SELF:
            return self_pub
        if self.type == CounterpartyType.ANYONE:
            # Anyone is represented by the constant PublicKey derived from PrivateKey(1)
            return PrivateKey(1).public_key()
        if self.type == CounterpartyType.OTHER and self.counterparty:
            return self.counterparty
        raise ValueError("Invalid counterparty configuration")


class KeyDeriver:
    """key derivation (deterministic, HMAC-SHA256 + elliptic add)"""

    def __init__(self, root_private_key: PrivateKey):
        self._root_private_key = root_private_key
        self._root_public_key = root_private_key.public_key()

    # ---------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------
    def _validate_protocol(self, protocol: Protocol):
        if protocol.security_level not in (0, 1, 2):
            raise ValueError("protocol security level must be 0, 1, or 2")
        # Allow shorter protocol names to match TS/Go usage in tests (e.g., "ctx")
        if not (3 <= len(protocol.protocol) <= 400):
            raise ValueError("protocol names must be 3-400 characters")
        if '  ' in protocol.protocol:
            raise ValueError("protocol names cannot contain multiple consecutive spaces")
        if not re.match(r'^[A-Za-z0-9 ]+$', protocol.protocol):
            raise ValueError("protocol names can only contain letters, numbers and spaces")
        if protocol.protocol.endswith(" protocol"):
            raise ValueError('no need to end your protocol name with " protocol"')

    def _validate_key_id(self, key_id: str):
        if not (1 <= len(key_id) <= 800):
            raise ValueError("key IDs must be 1-800 characters")

    # ------------------------------------------------------------------
    # Derivation core
    # ------------------------------------------------------------------
    def _branch_scalar(self, invoice_number: str, cp_pub: PublicKey) -> int:
        """Deterministic branch scalar from HMAC(ECDH_x(self_priv, cp_pub), invoice_number).
        ECDH_x uses the 32-byte x-coordinate of the shared point (TS/Go parity).
        
        This implementation now matches TypeScript/Go SDK behavior by using invoiceNumber
        directly instead of generating a seed internally.
        """
        invoice_number_bin = invoice_number.encode('utf-8')
        shared = cp_pub.derive_shared_secret(self._root_private_key)
        # Our derive_shared_secret returns compressed public key (33 bytes). Take x-coordinate.
        if isinstance(shared, (bytes, bytearray)) and len(shared) >= 33:
            shared_key = bytes(shared)[1:33]
        else:
            shared_key = shared
        branch = hmac_sha256(shared_key, invoice_number_bin)
        scalar = int.from_bytes(branch, 'big') % CURVE_ORDER
        if os.getenv("BSV_DEBUG", "0") == "1":
            try:
                print(f"[DEBUG KeyDeriver._branch_scalar] invoice_number={invoice_number} shared_len={len(shared_key)} scalar={scalar:x}")
            except Exception:
                print(f"[DEBUG KeyDeriver._branch_scalar] scalar={scalar:x}")
        return scalar

    # ------------------------------------------------------------------
    # Public / Private / Symmetric derivations
    # ------------------------------------------------------------------
    def derive_private_key(self, protocol: Protocol, key_id: str, counterparty: Counterparty) -> PrivateKey:
        """Derives a private key based on protocol ID, key ID, and counterparty.
        
        This implementation now matches TypeScript/Go SDK behavior:
        1. Generate invoiceNumber using compute_invoice_number
        2. Normalize counterparty
        3. Call _branch_scalar with invoiceNumber
        4. Compute derived key as (root + branch_scalar) mod N
        """
        invoice_number = self.compute_invoice_number(protocol, key_id)
        cp_pub = counterparty.to_public_key(self._root_public_key)
        branch_k = self._branch_scalar(invoice_number, cp_pub)

        derived_int = (self._root_private_key.int() + branch_k) % CURVE_ORDER
        return PrivateKey(derived_int)

    def derive_public_key(
        self,
        protocol: Protocol,
        key_id: str,
        counterparty: Counterparty,
        for_self: bool = False,
    ) -> PublicKey:
        """Derives a public key based on protocol ID, key ID, and counterparty.
        
        This implementation now matches TypeScript/Go SDK behavior by using invoiceNumber.
        """
        invoice_number = self.compute_invoice_number(protocol, key_id)
        # Determine counterparty pub used for tweak
        cp_pub = counterparty.to_public_key(self._root_public_key) if not for_self else self._root_public_key
        delta = self._branch_scalar(invoice_number, cp_pub)
        # tweaked public = cp_pub + delta*G
        delta_point = curve_multiply(delta, curve.g)
        new_point = curve_add(cp_pub.point(), delta_point)
        return PublicKey(new_point)

    def derive_symmetric_key(self, protocol: Protocol, key_id: str, counterparty: Counterparty) -> bytes:
        """Symmetric 32-byte key: HMAC-SHA256(ECDH(self_root_priv, counterparty_pub), invoice_number).
        
        This implementation now matches TypeScript/Go SDK behavior by using invoiceNumber.
        """
        invoice_number = self.compute_invoice_number(protocol, key_id)
        invoice_number_bin = invoice_number.encode('utf-8')
        cp_pub = counterparty.to_public_key(self._root_public_key)
        shared = cp_pub.derive_shared_secret(self._root_private_key)
        if isinstance(shared, (bytes, bytearray)) and len(shared) >= 33:
            shared_key = bytes(shared)[1:33]
        else:
            shared_key = shared
        return hmac_sha256(shared_key, invoice_number_bin)

    # Identity key (root public)
    def identity_key(self) -> PublicKey:
        return self._root_public_key

    # ------------------------------------------------------------------
    # Additional helpers required by tests / higher layers
    # ------------------------------------------------------------------
    def compute_invoice_number(self, protocol: Protocol, key_id: str) -> str:
        """Return a string invoice number: "<security>-<protocol>-<key_id>" with validation."""
        self._validate_protocol(protocol)
        self._validate_key_id(key_id)
        return f"{protocol.security_level}-{protocol.protocol}-{key_id}"

    def normalize_counterparty(self, cp: Any) -> PublicKey:
        """Normalize various counterparty representations to a PublicKey.

        Accepted forms:
        - Counterparty(SELF/ANYONE/OTHER)
        - PublicKey
        - hex string
        """
        if isinstance(cp, Counterparty):
            return cp.to_public_key(self._root_public_key)
        if isinstance(cp, PublicKey):
            return cp
        if isinstance(cp, (bytes, str)):
            return PublicKey(cp)
        raise ValueError("Invalid counterparty configuration")
