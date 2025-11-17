"""
Tests for Schnorr Zero-Knowledge Proof implementation.

Translated from ts-sdk/src/primitives/__tests/Schnorr.test.ts
"""
import pytest
from bsv.primitives.schnorr import Schnorr
from bsv.keys import PrivateKey, PublicKey
from bsv.curve import Point, curve, curve_multiply, curve_add


class TestSchnorrZeroKnowledgeProof:
    """Test Schnorr Zero-Knowledge Proof matching TS SDK tests."""

    def setup_method(self):
        """Set up test fixtures."""
        self.schnorr = Schnorr()

    def test_should_verify_a_valid_proof(self):
        """Test that a valid proof verifies correctly."""
        # Generate private keys
        a = PrivateKey()
        b = PrivateKey()

        # Compute public keys
        A = a.public_key()
        B = b.public_key()

        # Compute shared secret S = B * a
        S_point = curve_multiply(a.int(), B.point())

        # Generate proof
        proof = self.schnorr.generate_proof(a, A, B, S_point)

        # Verify proof
        result = self.schnorr.verify_proof(A.point(), B.point(), S_point, proof)
        assert result is True

    def test_should_fail_verification_if_proof_is_tampered_r_modified(self):
        """Test that tampering with R causes verification to fail."""
        a = PrivateKey()
        b = PrivateKey()
        A = a.public_key()
        B = b.public_key()
        S_point = curve_multiply(a.int(), B.point())

        proof = self.schnorr.generate_proof(a, A, B, S_point)

        # Tamper with R
        tampered_r = curve_add(proof['R'], curve.g) if proof['R'] else curve.g
        tampered_proof = {**proof, 'R': tampered_r}

        result = self.schnorr.verify_proof(A.point(), B.point(), S_point, tampered_proof)
        assert result is False

    def test_should_fail_verification_if_proof_is_tampered_z_modified(self):
        """Test that tampering with z causes verification to fail."""
        a = PrivateKey()
        b = PrivateKey()
        A = a.public_key()
        B = b.public_key()
        S_point = curve_multiply(a.int(), B.point())

        proof = self.schnorr.generate_proof(a, A, B, S_point)

        # Tamper with z
        tampered_z = (proof['z'] + 1) % curve.n
        tampered_proof = {**proof, 'z': tampered_z}

        result = self.schnorr.verify_proof(A.point(), B.point(), S_point, tampered_proof)
        assert result is False

    def test_should_fail_verification_if_proof_is_tampered_s_prime_modified(self):
        """Test that tampering with S' causes verification to fail."""
        a = PrivateKey()
        b = PrivateKey()
        A = a.public_key()
        B = b.public_key()
        S_point = curve_multiply(a.int(), B.point())

        proof = self.schnorr.generate_proof(a, A, B, S_point)

        # Tamper with S'
        tampered_s_prime = curve_add(proof['SPrime'], curve.g) if proof['SPrime'] else curve.g
        tampered_proof = {**proof, 'SPrime': tampered_s_prime}

        result = self.schnorr.verify_proof(A.point(), B.point(), S_point, tampered_proof)
        assert result is False

    def test_should_fail_verification_if_inputs_are_tampered_a_modified(self):
        """Test that tampering with A causes verification to fail."""
        a = PrivateKey()
        b = PrivateKey()
        A = a.public_key()
        B = b.public_key()
        S_point = curve_multiply(a.int(), B.point())

        proof = self.schnorr.generate_proof(a, A, B, S_point)

        # Tamper with A
        tampered_a = curve_add(A.point(), curve.g) if A.point() else curve.g

        result = self.schnorr.verify_proof(tampered_a, B.point(), S_point, proof)
        assert result is False

    def test_should_fail_verification_if_inputs_are_tampered_b_modified(self):
        """Test that tampering with B causes verification to fail."""
        a = PrivateKey()
        b = PrivateKey()
        A = a.public_key()
        B = b.public_key()
        S_point = curve_multiply(a.int(), B.point())

        proof = self.schnorr.generate_proof(a, A, B, S_point)

        # Tamper with B
        tampered_b = curve_add(B.point(), curve.g) if B.point() else curve.g

        result = self.schnorr.verify_proof(A.point(), tampered_b, S_point, proof)
        assert result is False

    def test_should_fail_verification_if_inputs_are_tampered_s_modified(self):
        """Test that tampering with S causes verification to fail."""
        a = PrivateKey()
        b = PrivateKey()
        A = a.public_key()
        B = b.public_key()
        S_point = curve_multiply(a.int(), B.point())

        proof = self.schnorr.generate_proof(a, A, B, S_point)

        # Tamper with S
        tampered_s = curve_add(S_point, curve.g) if S_point else curve.g

        result = self.schnorr.verify_proof(A.point(), B.point(), tampered_s, proof)
        assert result is False

    def test_should_fail_verification_if_using_wrong_private_key(self):
        """Test that using wrong private key causes verification to fail."""
        a = PrivateKey()
        wrong_a = PrivateKey()
        b = PrivateKey()
        A = a.public_key()
        B = b.public_key()
        S_point = curve_multiply(a.int(), B.point())

        # Generate proof using wrong private key
        proof = self.schnorr.generate_proof(wrong_a, A, B, S_point)

        result = self.schnorr.verify_proof(A.point(), B.point(), S_point, proof)
        assert result is False

    def test_should_fail_verification_if_using_wrong_public_key(self):
        """Test that using wrong public key causes verification to fail."""
        a = PrivateKey()
        b = PrivateKey()
        wrong_b = PrivateKey()
        A = a.public_key()
        B = b.public_key()
        wrong_b_public = wrong_b.public_key()
        S_point = curve_multiply(a.int(), B.point())

        proof = self.schnorr.generate_proof(a, A, B, S_point)

        # Verify proof with wrong B
        result = self.schnorr.verify_proof(A.point(), wrong_b_public.point(), S_point, proof)
        assert result is False

    def test_should_fail_verification_if_shared_secret_s_is_incorrect(self):
        """Test that incorrect shared secret causes verification to fail."""
        a = PrivateKey()
        b = PrivateKey()
        A = a.public_key()
        B = b.public_key()

        # Intentionally compute incorrect shared secret
        correct_s = curve_multiply(a.int(), B.point())
        incorrect_s = curve_add(correct_s, curve.g) if correct_s else curve.g

        # Generate proof with correct S
        proof = self.schnorr.generate_proof(a, A, B, correct_s)

        # Verify proof with incorrect S
        result = self.schnorr.verify_proof(A.point(), B.point(), incorrect_s, proof)
        assert result is False

    def test_should_verify_a_valid_proof_with_fixed_keys(self):
        """Test that a valid proof verifies with fixed keys for determinism."""
        # Use fixed private keys for determinism
        a_int = int('123456789abcdef123456789abcdef123456789abcdef123456789abcdef', 16)
        b_int = int('abcdef123456789abcdef123456789abcdef123456789abcdef123456789', 16)
        a = PrivateKey(a_int)
        b = PrivateKey(b_int)

        A = a.public_key()
        B = b.public_key()
        S_point = curve_multiply(a.int(), B.point())

        proof = self.schnorr.generate_proof(a, A, B, S_point)

        result = self.schnorr.verify_proof(A.point(), B.point(), S_point, proof)
        assert result is True

