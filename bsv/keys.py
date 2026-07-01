import hashlib
import hmac
import os
from base64 import b64decode, b64encode
from typing import Callable, Optional, Tuple, Union

from .aes_cbc import aes_decrypt_with_iv, aes_encrypt_with_iv
from .base58 import base58check_encode
from .constants import NETWORK_ADDRESS_PREFIX_DICT, NETWORK_WIF_PREFIX_DICT, PUBLIC_KEY_COMPRESSED_PREFIX_LIST, Network
from .curve import Point, curve, curve_add, curve_multiply
from .hash import hash160, hash256, hmac_sha256, hmac_sha512
from .polynomial import KeyShares, PointInFiniteField, Polynomial
from .utils import (
    decode_wif,
    deserialize_ecdsa_recoverable,
    serialize_ecdsa_der,
    stringify_ecdsa_recoverable,
    text_digest,
    unstringify_ecdsa_recoverable,
)

# ---------------------------------------------------------------------------
# Crypto backend: _bsv_native (direct libsecp256k1) → coincurve (CFFI)
# ---------------------------------------------------------------------------
_CRYPTO_BACKEND = None

try:
    import _bsv_native

    _CRYPTO_BACKEND = "native"
except ImportError:
    try:
        from coincurve import PrivateKey as CcPrivateKey
        from coincurve import PublicKey as CcPublicKey

        _CRYPTO_BACKEND = "coincurve"
    except ImportError:
        raise ImportError(
            "bsv-sdk requires either _bsv_native (recommended) or coincurve. "
            "Install with: pip install bsv-sdk  (includes pre-built binaries)"
        )


class PublicKey:
    def __init__(self, public_key: Union[str, bytes, Point, "PublicKey"]):
        """
        create public key from serialized hex string or bytes, or curve point, or another PublicKey
        """
        self.compressed: bool = True

        if isinstance(public_key, Point):
            x_bytes = public_key.x.to_bytes(32, "big")
            y_bytes = public_key.y.to_bytes(32, "big")
            uncompressed = b"\x04" + x_bytes + y_bytes
            if _CRYPTO_BACKEND == "native":
                self._raw: bytes = _bsv_native.pubkey_serialize(uncompressed, True)
                self._raw_unc: bytes = uncompressed
            else:
                self.key = CcPublicKey.from_point(public_key.x, public_key.y)
        elif isinstance(public_key, PublicKey):
            if _CRYPTO_BACKEND == "native":
                self._raw = public_key.serialize(True)
                self._raw_unc = None
            else:
                self.key = public_key.key
            self.compressed = public_key.compressed
        elif _CRYPTO_BACKEND == "coincurve" and hasattr(public_key, "format"):
            # CcPublicKey instance (for backward compatibility during migration)
            self.key = public_key
        else:
            if isinstance(public_key, str):
                pk: bytes = bytes.fromhex(public_key)
            elif isinstance(public_key, bytes):
                pk: bytes = public_key
            else:
                raise TypeError("unsupported public key type")
            self.compressed = pk[:1] in PUBLIC_KEY_COMPRESSED_PREFIX_LIST
            if _CRYPTO_BACKEND == "native":
                _bsv_native.pubkey_parse(pk)
                self._raw = _bsv_native.pubkey_serialize(pk, True)
                self._raw_unc = None
            else:
                self.key = CcPublicKey(pk)

    def point(self) -> Point:
        if _CRYPTO_BACKEND == "native":
            x, y = _bsv_native.pubkey_point(self._raw)
            return Point(x, y)
        return Point(*self.key.point())

    def serialize(self, compressed: Optional[bool] = None) -> bytes:
        compressed = self.compressed if compressed is None else compressed
        if _CRYPTO_BACKEND == "native":
            return _bsv_native.pubkey_serialize(self._raw, compressed)
        return self.key.format(compressed)

    def hex(self, compressed: Optional[bool] = None) -> str:
        return self.serialize(compressed).hex()

    def hash160(self, compressed: Optional[bool] = None) -> bytes:
        """
        :returns: public key hash corresponding to this public key
        """
        return hash160(self.serialize(compressed))

    hash = hash160

    def address(self, compressed: Optional[bool] = None, network: Network = Network.MAINNET) -> str:
        """
        :returns: P2PKH address corresponding to this public key
        """
        return base58check_encode(NETWORK_ADDRESS_PREFIX_DICT.get(network) + self.hash160(compressed))

    def verify(self, signature: bytes, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256) -> bool:
        """
        verify serialized ECDSA signature in bitcoin strict DER (low-s) format
        """
        if _CRYPTO_BACKEND == "native":
            msg32 = hasher(message) if hasher else message
            return _bsv_native.ecdsa_verify(signature, msg32, self.serialize())
        return self.key.verify(signature, message, hasher)

    def verify_recoverable(
        self, signature: bytes, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256
    ) -> bool:
        """
        verify serialized recoverable ECDSA signature in format "r (32 bytes) + s (32 bytes) + recovery_id (1 byte)"
        """
        r, s, _ = deserialize_ecdsa_recoverable(signature)
        der = serialize_ecdsa_der((r, s))
        return self.verify(der, message, hasher) and self == recover_public_key(signature, message, hasher)

    def derive_shared_secret(self, key: "PrivateKey") -> bytes:
        if _CRYPTO_BACKEND == "native":
            result = _bsv_native.pubkey_tweak_mul(self.serialize(), key.serialize(), self.compressed)
            return result
        return PublicKey(self.key.multiply(key.serialize())).serialize()

    def encrypt(self, message: bytes) -> bytes:
        """
        Electrum ECIES (aka BIE1) encryption
        """
        ephemeral_private_key = PrivateKey()
        ecdh_key: bytes = self.derive_shared_secret(ephemeral_private_key)
        key: bytes = hashlib.sha512(ecdh_key).digest()
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        cipher: bytes = aes_encrypt_with_iv(key_e, iv, message)
        encrypted: bytes = b"BIE1" + ephemeral_private_key.public_key().serialize() + cipher
        mac: bytes = hmac.new(key_m, encrypted, hashlib.sha256).digest()
        return encrypted + mac

    def encrypt_text(self, text: str) -> str:
        """
        :returns: BIE1 encrypted text, base64 encoded
        """
        message: bytes = text.encode("utf-8")
        return b64encode(self.encrypt(message)).decode("ascii")

    def derive_child(self, private_key: "PrivateKey", invoice_number: str) -> "PublicKey":
        """
        derive a child key with BRC-42
        :param private_key: the private key of the other party
        :param invoice_number: the invoice number used to derive the child key
        :return: the derived child key
        """
        shared_key = self.derive_shared_secret(private_key)
        hashing = hmac_sha256(shared_key, invoice_number.encode("utf-8"))
        point = curve_multiply(int.from_bytes(hashing, "big"), curve.g)
        final_point = curve_add(self.point(), point)
        return PublicKey(final_point)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, PublicKey):
            return self.serialize(compressed=True) == o.serialize(compressed=True)
        return super().__eq__(o)  # pragma: no cover

    def __str__(self) -> str:  # pragma: no cover
        return f"<PublicKey hex={self.hex()}>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()


class PrivateKey:
    def __init__(self, private_key: str | int | bytes | None = None, network: Optional[Network] = None):
        """
        create private key from WIF (str), or int, or bytes
        random a new private key if None
        """
        self.network: Network = network or Network.MAINNET
        self.compressed: bool = True

        if private_key is None:
            self._secret: bytes = os.urandom(32)
            while not self._is_valid_secret(self._secret):
                self._secret = os.urandom(32)  # pragma: no cover
        elif (
            _CRYPTO_BACKEND == "coincurve"
            and isinstance(private_key, type(None)) is False
            and hasattr(private_key, "secret")
        ):
            # CcPrivateKey instance (backward compat during migration)
            self._secret = private_key.secret
        elif isinstance(private_key, str):
            private_key_bytes, self.compressed, self.network = decode_wif(private_key)
            self._secret = private_key_bytes
        elif isinstance(private_key, int):
            self._secret = private_key.to_bytes(32, "big")
        elif isinstance(private_key, bytes):
            self._secret = private_key
        else:
            raise TypeError("unsupported private key type")

    def _is_valid_secret(self, secret: bytes) -> bool:
        if _CRYPTO_BACKEND == "native":
            return _bsv_native.seckey_verify(secret)
        return len(secret) == 32 and int.from_bytes(secret, "big") > 0 and int.from_bytes(secret, "big") < curve.n

    def public_key(self) -> PublicKey:
        if _CRYPTO_BACKEND == "native":
            pk_bytes = _bsv_native.pubkey_from_secret(self._secret, self.compressed)
            return PublicKey(pk_bytes)
        return PublicKey(CcPrivateKey(self._secret).public_key.format(self.compressed))

    def address(self, compressed: Optional[bool] = None, network: Optional[Network] = None) -> str:
        """
        :returns: P2PKH address corresponding to this private key
        """
        compressed = self.compressed if compressed is None else compressed
        network = network or self.network
        return self.public_key().address(compressed, network)

    def wif(self, compressed: Optional[bool] = None, network: Optional[Network] = None) -> str:
        compressed = self.compressed if compressed is None else compressed
        network = network or self.network
        key_bytes = self.serialize()
        compressed_bytes = b"\x01" if compressed else b""
        return base58check_encode(NETWORK_WIF_PREFIX_DICT.get(network) + key_bytes + compressed_bytes)

    def int(self) -> int:
        return int.from_bytes(self._secret, "big")

    def serialize(self) -> bytes:
        return self._secret

    def hex(self) -> str:
        return self._secret.hex()

    def der(self) -> bytes:  # pragma: no cover
        if _CRYPTO_BACKEND == "coincurve":
            return CcPrivateKey(self._secret).to_der()
        raise NotImplementedError("DER export requires coincurve backend")

    def pem(self) -> bytes:  # pragma: no cover
        if _CRYPTO_BACKEND == "coincurve":
            return CcPrivateKey(self._secret).to_pem()
        raise NotImplementedError("PEM export requires coincurve backend")

    def sign(
        self, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256, k: Optional[int] = None
    ) -> bytes:
        """
        :returns: ECDSA signature in bitcoin strict DER (low-s) format
        """
        if k:
            if _CRYPTO_BACKEND == "native":
                msg32 = hasher(message) if hasher else message
                k_bytes = (k % curve.n).to_bytes(32, "big")
                return _bsv_native.ecdsa_sign_with_k(msg32, self._secret, k_bytes)
            return self._sign_custom_k(message, hasher, k)
        if _CRYPTO_BACKEND == "native":
            msg32 = hasher(message) if hasher else message
            return _bsv_native.ecdsa_sign(msg32, self._secret)
        return CcPrivateKey(self._secret).sign(message, hasher)

    def _sign_custom_k(self, message: bytes, hasher: Callable[[bytes], bytes], k: int) -> bytes:
        """Pure Python fallback for ECDSA signing with custom nonce k."""
        z = int.from_bytes(hasher(message), "big")

        k = k % curve.n
        if k == 0:
            raise ValueError("Invalid nonce k")

        R = curve_multiply(k, curve.g)
        if R is None:
            raise ValueError("Invalid R value")
        r = R.x

        d = int.from_bytes(self.serialize(), "big")
        s = (pow(k, -1, curve.n) * (z + r * d)) % curve.n
        if s == 0:
            raise ValueError("Invalid s value")

        if s > curve.n // 2:
            s = curve.n - s

        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, "big")
        s_bytes = s.to_bytes((s.bit_length() + 7) // 8, "big")

        if r_bytes[0] & 0x80:
            r_bytes = b"\x00" + r_bytes
        if s_bytes[0] & 0x80:
            s_bytes = b"\x00" + s_bytes

        signature = (
            b"\x30"
            + (4 + len(r_bytes) + len(s_bytes)).to_bytes(1, "big")
            + b"\x02"
            + len(r_bytes).to_bytes(1, "big")
            + r_bytes
            + b"\x02"
            + len(s_bytes).to_bytes(1, "big")
            + s_bytes
        )

        return signature

    def verify(self, signature: bytes, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256) -> bool:
        """
        verify ECDSA signature in bitcoin strict DER (low-s) format
        """
        return self.public_key().verify(signature, message, hasher)

    def sign_recoverable(self, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256) -> bytes:
        """
        :returns: serialized recoverable ECDSA signature (aka compact signature) in format
                    r (32 bytes) + s (32 bytes) + recovery_id (1 byte)
        """
        if _CRYPTO_BACKEND == "native":
            msg32 = hasher(message) if hasher else message
            return _bsv_native.ecdsa_sign_recoverable(msg32, self._secret)
        return CcPrivateKey(self._secret).sign_recoverable(message, hasher)

    def verify_recoverable(
        self, signature: bytes, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256
    ) -> bool:
        """
        verify serialized recoverable ECDSA signature in format "r (32 bytes) + s (32 bytes) + recovery_id (1 byte)"
        """
        return self.public_key().verify_recoverable(signature, message, hasher)

    def sign_text(self, text: str) -> tuple[str, str]:
        """sign arbitrary text with bitcoin private key
        :returns: (p2pkh_address, stringified_recoverable_ecdsa_signature)
        This function follows Bitcoin Signed Message Format.
        For BRC-77, use signed_message.py instead.
        """
        message: bytes = text_digest(text)
        return self.address(), stringify_ecdsa_recoverable(self.sign_recoverable(message), self.compressed)

    def derive_shared_secret(self, key: PublicKey) -> bytes:
        if _CRYPTO_BACKEND == "native":
            result = _bsv_native.pubkey_tweak_mul(key.serialize(), self.serialize(), key.compressed)
            return result
        return PublicKey(key.key.multiply(self.serialize())).serialize()

    def decrypt(self, message: bytes) -> bytes:
        """
        Electrum ECIES (aka BIE1) decryption
        """
        assert len(message) >= 85, "invalid encrypted length"
        encrypted, mac = message[:-32], message[-32:]
        magic_bytes, ephemeral_public_key, cipher = encrypted[:4], PublicKey(encrypted[4:37]), encrypted[37:]
        assert magic_bytes.decode("utf-8") == "BIE1", "invalid magic bytes"
        ecdh_key = self.derive_shared_secret(ephemeral_public_key)
        key = hashlib.sha512(ecdh_key).digest()
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        assert hmac.new(key_m, encrypted, hashlib.sha256).digest().hex() == mac.hex(), "incorrect hmac checksum"
        return aes_decrypt_with_iv(key_e, iv, cipher)

    def decrypt_text(self, text: str) -> str:
        """
        decrypt BIE1 encrypted, base64 encoded text
        """
        message: bytes = b64decode(text)
        return self.decrypt(message).decode("utf-8")

    def encrypt(self, message: bytes) -> bytes:  # pragma: no cover
        """
        Electrum ECIES (aka BIE1) encryption
        """
        return self.public_key().encrypt(message)

    def encrypt_text(self, text: str) -> str:  # pragma: no cover
        """
        :returns: BIE1 encrypted text, base64 encoded
        """
        return self.public_key().encrypt_text(text)

    def derive_child(self, public_key: PublicKey, invoice_number: str) -> "PrivateKey":
        """
        derive a child key with BRC-42
        :param public_key: the public key of the other party
        :param invoice_number: the invoice number used to derive the child key
        :return: the derived child key
        """
        shared_key = self.derive_shared_secret(public_key)
        hashing = hmac_sha256(shared_key, invoice_number.encode("utf-8"))
        return PrivateKey((self.int() + int.from_bytes(hashing, "big")) % curve.n)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, PrivateKey):
            return self._secret == o._secret
        return super().__eq__(o)  # pragma: no cover

    def __str__(self) -> str:  # pragma: no cover
        return f"<PrivateKey wif={self.wif()} int={self.int()}>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    @classmethod
    def from_hex(cls, octets: str | bytes) -> "PrivateKey":
        b: bytes = octets if isinstance(octets, bytes) else bytes.fromhex(octets)
        return PrivateKey(b)

    @classmethod
    def from_der(cls, octets: str | bytes) -> "PrivateKey":  # pragma: no cover
        b: bytes = octets if isinstance(octets, bytes) else bytes.fromhex(octets)
        if _CRYPTO_BACKEND == "coincurve":
            return PrivateKey(CcPrivateKey.from_der(b).secret)
        raise NotImplementedError("DER import requires coincurve backend")

    @classmethod
    def from_pem(cls, octets: str | bytes) -> "PrivateKey":  # pragma: no cover
        b: bytes = octets if isinstance(octets, bytes) else bytes.fromhex(octets)
        if _CRYPTO_BACKEND == "coincurve":
            return PrivateKey(CcPrivateKey.from_pem(b).secret)
        raise NotImplementedError("PEM import requires coincurve backend")

    def to_key_shares(self, threshold: int, total_shares: int) -> "KeyShares":
        """
        Split the private key into shares using Shamir's Secret Sharing Scheme.

        Args:
            threshold: The minimum number of shares required to reconstruct the private key
            total_shares: The total number of shares to generate

        Returns:
            A KeyShares object containing the generated shares

        Raises:
            ValueError: If threshold or total_shares are invalid
        """

        # Input validation
        if not isinstance(threshold, int) or not isinstance(total_shares, int):
            raise ValueError("threshold and totalShares must be numbers")
        if threshold < 2:
            raise ValueError("threshold must be at least 2")
        if total_shares < 2:
            raise ValueError("totalShares must be at least 2")
        if threshold > total_shares:
            raise ValueError("threshold should be less than or equal to totalShares")

        # Create polynomial from private key
        poly = Polynomial.from_private_key(self.int(), threshold)

        # Generate shares
        points = []
        used_x_coordinates = set()

        seed = os.urandom(64)

        for i in range(total_shares):
            x = None
            attempts = 0

            while x is None or x == 0 or x in used_x_coordinates:
                counter = [i, attempts, *list(os.urandom(32))]
                counter_bytes = bytes(counter)

                h = hmac_sha512(seed, counter_bytes)
                x = int.from_bytes(h, "big") % curve.p

                attempts += 1
                if attempts > 5:
                    raise ValueError("Failed to generate unique x coordinate after 5 attempts")

            used_x_coordinates.add(x)
            y = poly.value_at(x)

            points.append(PointInFiniteField(x, y))

        integrity = self.public_key().hash160().hex()[:8]

        return KeyShares(points, threshold, integrity)

    def to_backup_shares(self, threshold: int, total_shares: int) -> list:
        """
        Creates a backup of the private key by splitting it into shares.

        Args:
            threshold: The number of shares which will be required to reconstruct the private key
            total_shares: The number of shares to generate for distribution

        Returns:
            List of share strings in backup format
        """
        key_shares = self.to_key_shares(threshold, total_shares)
        return key_shares.to_backup_format()

    @staticmethod
    def from_backup_shares(shares: list) -> "PrivateKey":
        """
        Reconstructs a private key from backup shares.

        Args:
            shares: List of share strings in backup format

        Returns:
            The reconstructed PrivateKey object

        Raises:
            ValueError: If shares are invalid or inconsistent
        """
        return PrivateKey.from_key_shares(KeyShares.from_backup_format(shares))

    @staticmethod
    def from_key_shares(key_shares: "KeyShares") -> "PrivateKey":
        """
        Combines shares to reconstruct the private key.

        Args:
            key_shares: A KeyShares object containing the shares

        Returns:
            The reconstructed PrivateKey object

        Raises:
            ValueError: If not enough shares are provided or shares are invalid
        """

        points = key_shares.points
        threshold = key_shares.threshold
        integrity = key_shares.integrity

        # Validate inputs
        if threshold < 2:
            raise ValueError("threshold must be at least 2")
        if len(points) < threshold:
            raise ValueError(f"At least {threshold} shares are required to reconstruct the private key")

        # Check for duplicate x values
        for i in range(threshold):
            for j in range(i + 1, threshold):
                if points[i].x == points[j].x:
                    raise ValueError("Duplicate share detected, each must be unique.")

        # Create polynomial from points
        poly = Polynomial(points[:threshold], threshold)

        # Evaluate polynomial at x=0 to get the private key
        secret_value = poly.value_at(0)

        # Create private key from secret value
        private_key = PrivateKey(secret_value)

        # Verify integrity by comparing hash of public key
        reconstructed_integrity = private_key.public_key().hash160().hex()[:8]
        if reconstructed_integrity != integrity:
            raise ValueError("Integrity hash mismatch")

        return private_key


def verify_signed_text(
    text: str, address: str, signature: str, hasher: Optional[Callable[[bytes], bytes]] = hash256
) -> bool:
    """
    verify signed arbitrary text
    """
    serialized_recoverable, compressed = unstringify_ecdsa_recoverable(signature)
    r, s, _ = deserialize_ecdsa_recoverable(serialized_recoverable)
    message: bytes = text_digest(text)
    public_key: PublicKey = recover_public_key(serialized_recoverable, message, hasher)
    der: bytes = serialize_ecdsa_der((r, s))
    return public_key.verify(der, message, hasher) and public_key.address(compressed=compressed) == address


def recover_public_key(
    signature: bytes, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256
) -> PublicKey:
    """
    recover public key from serialized recoverable ECDSA signature in format
      "r (32 bytes) + s (32 bytes) + recovery_id (1 byte)"
    """
    if _CRYPTO_BACKEND == "native":
        msg32 = hasher(message) if hasher else message
        pk_bytes = _bsv_native.ecdsa_recover(signature, msg32, True)
        return PublicKey(pk_bytes)
    return PublicKey(CcPublicKey.from_signature_and_message(signature, message, hasher))
