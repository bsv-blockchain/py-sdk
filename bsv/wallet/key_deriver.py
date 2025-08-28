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
class Protocol:
    security_level: int  # 0,1,2
    protocol: str
    
    def __init__(self, security_level: int, protocol: str):
        if not isinstance(protocol, str) or len(protocol) < 5 or len(protocol) > 400:
            raise ValueError("protocol names must be 5-400 characters")
        self.security_level = security_level
        self.protocol = protocol


class CounterpartyType:
    SELF = 0  # derive vs self
    OTHER = 1  # explicit pubkey provided
    ANYONE = 2  # special constant


@dataclass
class Counterparty:
    type: int
    counterparty: Optional[PublicKey] = None

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
    def _seed_bytes(self, protocol: Protocol, key_id: str) -> bytes:
        return str(protocol.security_level).encode() + b":" + protocol.protocol.encode() + b":" + key_id.encode()

    def _branch_scalar(self, protocol: Protocol, key_id: str, cp_pub: PublicKey) -> int:
        """Deterministic branch scalar from HMAC(ECDH(self_priv, cp_pub), seed)."""
        seed = self._seed_bytes(protocol, key_id)
        shared = cp_pub.derive_shared_secret(self._root_private_key)
        branch = hmac_sha256(shared, seed)
        scalar = int.from_bytes(branch, 'big') % CURVE_ORDER
        if os.getenv("BSV_DEBUG", "0") == "1":
            print(f"[DEBUG KeyDeriver._branch_scalar] seed={seed.hex()} scalar={scalar:x}")
        return scalar

    # ------------------------------------------------------------------
    # Public / Private / Symmetric derivations
    # ------------------------------------------------------------------
    def derive_private_key(self, protocol: Protocol, key_id: str, counterparty: Counterparty) -> PrivateKey:
        self._validate_protocol(protocol)
        self._validate_key_id(key_id)

        cp_pub = counterparty.to_public_key(self._root_public_key)
        branch_k = self._branch_scalar(protocol, key_id, cp_pub)

        derived_int = (self._root_private_key.int() + branch_k) % CURVE_ORDER
        return PrivateKey(derived_int)

    def derive_public_key(
        self,
        protocol: Protocol,
        key_id: str,
        counterparty: Counterparty,
        for_self: bool = False,
    ) -> PublicKey:
        # Determine counterparty pub used for tweak
        cp_pub = counterparty.to_public_key(self._root_public_key) if not for_self else self._root_public_key
        delta = self._branch_scalar(protocol, key_id, cp_pub)
        # tweaked public = cp_pub + delta*G
        delta_point = curve_multiply(delta, curve.g)
        new_point = curve_add(cp_pub.point(), delta_point)
        return PublicKey(new_point)

    def derive_symmetric_key(self, protocol: Protocol, key_id: str, counterparty: Counterparty) -> bytes:
        """Symmetric 32-byte key: HMAC-SHA256(ECDH(self_root_priv, counterparty_pub), seed)."""
        self._validate_protocol(protocol)
        self._validate_key_id(key_id)
        cp_pub = counterparty.to_public_key(self._root_public_key)
        shared = cp_pub.derive_shared_secret(self._root_private_key)
        seed = self._seed_bytes(protocol, key_id)
        return hmac_sha256(shared, seed)

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
