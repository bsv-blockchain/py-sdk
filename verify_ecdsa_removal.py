#!/usr/bin/env python3
"""
Verification script to ensure ECDSA functionality still works after removing ecdsa dependency.
"""
from bsv.keys import PrivateKey, PublicKey

def test_basic_signing():
    """Test basic signing and verification functionality."""
    print("Testing basic signing and verification...")

    # Create a private key
    private_key = PrivateKey()

    # Create a message
    message = b"Hello, world!"

    # Sign the message
    signature = private_key.sign(message)
    print(f"Generated signature: {signature.hex()}")

    # Verify the signature
    public_key = private_key.public_key()
    is_valid = public_key.verify(signature, message)
    print(f"Signature verification: {'PASS' if is_valid else 'FAIL'}")

    assert is_valid, "Signature verification failed!"
    print("✓ Basic signing/verification works")

def test_recoverable_signing():
    """Test recoverable signing functionality."""
    print("\nTesting recoverable signing...")

    from bsv.keys import verify_signed_text

    private_key = PrivateKey()
    text = "Hello, recoverable world!"

    # Sign text with recoverable signature
    address, signature = private_key.sign_text(text)
    print(f"Generated address: {address}")
    print(f"Generated signature: {signature}")

    # Verify the signed text
    is_valid = verify_signed_text(text, address, signature)
    print(f"Recoverable signature verification: {'PASS' if is_valid else 'FAIL'}")

    assert is_valid, "Recoverable signature verification failed!"
    print("✓ Recoverable signing/verification works")

def test_ecdh():
    """Test ECDH key exchange."""
    print("\nTesting ECDH key exchange...")

    alice = PrivateKey()
    bob = PrivateKey()

    # Perform ECDH
    alice_secret = alice.derive_shared_secret(bob.public_key())
    bob_secret = bob.derive_shared_secret(alice.public_key())

    print(f"Alice's secret: {alice_secret.hex()}")
    print(f"Bob's secret: {bob_secret.hex()}")

    assert alice_secret == bob_secret, "ECDH secrets don't match!"
    print("✓ ECDH key exchange works")

if __name__ == "__main__":
    print("Verifying ECDSA functionality after removing ecdsa dependency...")
    print("=" * 60)

    try:
        test_basic_signing()
        test_recoverable_signing()
        test_ecdh()

        print("\n" + "=" * 60)
        print("🎉 All functionality tests passed! ECDSA dependency can be safely removed.")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        raise
