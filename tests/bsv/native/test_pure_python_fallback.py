"""
Pure Python crypto fallback tests.

When ``_bsv_native`` is unavailable, ``bsv.keys`` / ``bsv.curve`` fall back to a
pure Python ECDSA / secp256k1 implementation (added when coincurve was dropped).
That fallback is never exercised on machines where the native module builds, so
these tests force ``_CRYPTO_BACKEND = "python"`` and assert:

  1. round-trips work (sign/verify, sign_recoverable/recover, ECIES, BRC-42), and
  2. the pure Python path is *equivalent* to the native path — same public keys,
     addresses, and (thanks to RFC 6979) byte-identical signatures, and each
     backend verifies the other's signatures.

Item (2) is what guards the RFC 6979 nonce and low-S normalization in the Python
code against silent drift from libsecp256k1.
"""

import sys

import pytest

import _bsv_native
import bsv.curve  # ensure the submodule is imported into sys.modules
import bsv.keys
from bsv.hash import hash256 as py_hash256
from bsv.keys import PrivateKey, PublicKey, recover_public_key

# bsv/__init__.py re-exports the ``curve`` namedtuple, which shadows the
# ``bsv.curve`` submodule attribute — so ``import bsv.curve as curve_mod`` would
# bind the namedtuple, not the module. Fetch the real modules via sys.modules.
curve_mod = sys.modules["bsv.curve"]
keys_mod = sys.modules["bsv.keys"]

# A few fixed secrets (avoid RNG so failures are reproducible).
SECRETS = [
    "0000000000000000000000000000000000000000000000000000000000000001",
    "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",  # n-1
]
MESSAGES = [b"", b"hello world", b"\xff" * 64, bytes(range(32))]


@pytest.fixture()
def force_python(monkeypatch):
    """Force the pure Python crypto backend in both keys.py and curve.py.

    The backend functions read the module-level ``_CRYPTO_BACKEND`` at call time,
    so monkeypatching the globals is sufficient to route through the Python path.
    """
    monkeypatch.setattr(keys_mod, "_CRYPTO_BACKEND", "python")
    monkeypatch.setattr(curve_mod, "_CRYPTO_BACKEND", "python")
    assert keys_mod._CRYPTO_BACKEND == "python"
    assert curve_mod._CRYPTO_BACKEND == "python"


# ═══════════════════════════════════════════════════════════════════════
# Round-trips (pure Python only)
# ═══════════════════════════════════════════════════════════════════════


class TestPurePythonRoundTrips:
    @pytest.mark.parametrize("secret_hex", SECRETS)
    @pytest.mark.parametrize("message", MESSAGES)
    def test_sign_verify(self, force_python, secret_hex, message):
        pk = PrivateKey(bytes.fromhex(secret_hex))
        pub = pk.public_key()
        sig = pk.sign(message)
        assert pub.verify(sig, message)
        assert not pub.verify(sig, message + b"x")

    @pytest.mark.parametrize("secret_hex", SECRETS)
    def test_sign_recoverable_recover(self, force_python, secret_hex):
        pk = PrivateKey(bytes.fromhex(secret_hex))
        pub = pk.public_key()
        msg = b"recoverable message"
        sig = pk.sign_recoverable(msg)
        assert pub.verify_recoverable(sig, msg)
        assert recover_public_key(sig, msg) == pub

    @pytest.mark.parametrize("secret_hex", SECRETS)
    def test_ecies_roundtrip(self, force_python, secret_hex):
        pk = PrivateKey(bytes.fromhex(secret_hex))
        pub = pk.public_key()
        plaintext = b"secret payload \x00\x01\x02"
        assert pk.decrypt(pub.encrypt(plaintext)) == plaintext

    def test_brc42_child_symmetry(self, force_python):
        a = PrivateKey(bytes.fromhex(SECRETS[1]))
        b = PrivateKey(bytes.fromhex(SECRETS[2]))
        invoice = "2-3-4"
        # child private key of A derived against B's pubkey ...
        child_priv = a.derive_child(b.public_key(), invoice)
        # ... matches child public key of A's pubkey derived against B's privkey.
        child_pub = a.public_key().derive_child(b, invoice)
        assert child_priv.public_key() == child_pub

    def test_shared_secret_symmetry(self, force_python):
        a = PrivateKey(bytes.fromhex(SECRETS[1]))
        b = PrivateKey(bytes.fromhex(SECRETS[2]))
        assert a.public_key().derive_shared_secret(b) == b.public_key().derive_shared_secret(a)

    @pytest.mark.parametrize("secret_hex", SECRETS)
    def test_pubkey_serialize_roundtrip(self, force_python, secret_hex):
        pub = PrivateKey(bytes.fromhex(secret_hex)).public_key()
        compressed = pub.serialize(True)
        uncompressed = pub.serialize(False)
        assert len(compressed) == 33 and compressed[0] in (0x02, 0x03)
        assert len(uncompressed) == 65 and uncompressed[0] == 0x04
        # Re-parse both encodings back to the same key.
        assert PublicKey(compressed) == pub
        assert PublicKey(uncompressed) == pub


# ═══════════════════════════════════════════════════════════════════════
# Native ⇔ Python equivalence
# ═══════════════════════════════════════════════════════════════════════


class TestNativePythonEquivalence:
    @pytest.mark.parametrize("secret_hex", SECRETS)
    def test_pubkey_and_address_match_native(self, monkeypatch, secret_hex):
        secret = bytes.fromhex(secret_hex)
        # Native reference (backend-independent: calls _bsv_native directly).
        native_compressed = _bsv_native.pubkey_from_secret(secret, True)
        native_uncompressed = _bsv_native.pubkey_from_secret(secret, False)

        monkeypatch.setattr(keys_mod, "_CRYPTO_BACKEND", "python")
        monkeypatch.setattr(curve_mod, "_CRYPTO_BACKEND", "python")
        pk = PrivateKey(secret)
        assert pk.public_key().serialize(True) == native_compressed
        assert pk.public_key().serialize(False) == native_uncompressed

    @pytest.mark.parametrize("secret_hex", SECRETS)
    @pytest.mark.parametrize("message", MESSAGES)
    def test_der_signature_identical_to_native(self, monkeypatch, secret_hex, message):
        """RFC 6979 determinism: same key + message ⇒ byte-identical DER signature."""
        secret = bytes.fromhex(secret_hex)
        msg32 = py_hash256(message)
        native_sig = _bsv_native.ecdsa_sign(msg32, secret)

        monkeypatch.setattr(keys_mod, "_CRYPTO_BACKEND", "python")
        monkeypatch.setattr(curve_mod, "_CRYPTO_BACKEND", "python")
        py_sig = PrivateKey(secret).sign(message)

        assert py_sig == native_sig

    @pytest.mark.parametrize("secret_hex", SECRETS)
    def test_recoverable_signature_identical_to_native(self, monkeypatch, secret_hex):
        secret = bytes.fromhex(secret_hex)
        msg = b"cross backend recoverable"
        msg32 = py_hash256(msg)
        native_sig = _bsv_native.ecdsa_sign_recoverable(msg32, secret)

        monkeypatch.setattr(keys_mod, "_CRYPTO_BACKEND", "python")
        monkeypatch.setattr(curve_mod, "_CRYPTO_BACKEND", "python")
        py_sig = PrivateKey(secret).sign_recoverable(msg)

        assert py_sig == native_sig

    @pytest.mark.parametrize("secret_hex", SECRETS)
    def test_cross_backend_verify(self, monkeypatch, secret_hex):
        """Native verifies a Python-made signature and vice versa."""
        secret = bytes.fromhex(secret_hex)
        msg = b"cross verify"

        # Sign with the Python backend.
        monkeypatch.setattr(keys_mod, "_CRYPTO_BACKEND", "python")
        monkeypatch.setattr(curve_mod, "_CRYPTO_BACKEND", "python")
        pk_py = PrivateKey(secret)
        py_sig = pk_py.sign(msg)
        # Python verifies native's signature.
        native_sig = _bsv_native.ecdsa_sign(py_hash256(msg), secret)
        assert pk_py.public_key().verify(native_sig, msg)

        # Native verifies the Python signature.
        monkeypatch.setattr(keys_mod, "_CRYPTO_BACKEND", "native")
        monkeypatch.setattr(curve_mod, "_CRYPTO_BACKEND", "native")
        assert PrivateKey(secret).public_key().verify(py_sig, msg)


# ═══════════════════════════════════════════════════════════════════════
# Curve math equivalence (curve_add / curve_multiply)
# ═══════════════════════════════════════════════════════════════════════


class TestCurveMathEquivalence:
    @pytest.mark.parametrize("scalar", [1, 2, 7, 255, 0x123456789ABCDEF, curve_mod.curve.n - 1])
    def test_curve_multiply_matches_native(self, monkeypatch, scalar):
        g = curve_mod.curve.g
        monkeypatch.setattr(curve_mod, "_CRYPTO_BACKEND", "native")
        native = curve_mod.curve_multiply(scalar, g)
        monkeypatch.setattr(curve_mod, "_CRYPTO_BACKEND", "python")
        py = curve_mod.curve_multiply(scalar, g)
        assert py == native

    def test_curve_add_matches_native(self, monkeypatch):
        g = curve_mod.curve.g
        monkeypatch.setattr(curve_mod, "_CRYPTO_BACKEND", "python")
        p = curve_mod.curve_multiply(7, g)
        q = curve_mod.curve_multiply(11, g)
        py_sum = curve_mod.curve_add(p, q)
        monkeypatch.setattr(curve_mod, "_CRYPTO_BACKEND", "native")
        native_sum = curve_mod.curve_add(p, q)
        assert py_sum == native_sum
        # 7G + 11G == 18G
        assert py_sum == curve_mod.curve_multiply(18, g)
