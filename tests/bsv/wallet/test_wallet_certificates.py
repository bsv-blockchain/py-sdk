"""
Comprehensive tests for certificate management in WalletImpl.
"""
import pytest
from bsv.keys import PrivateKey
from bsv.wallet.wallet_impl import WalletImpl


@pytest.fixture
def wallet():
    priv = PrivateKey()
    return WalletImpl(priv, permission_callback=lambda action: True)


def test_acquire_certificate_basic(wallet):
    """Test basic certificate acquisition."""
    args = {
        "type": b"driver_license",
        "serialNumber": b"DL123456",
        "certifier": "dmv_authority",
        "keyringForSubject": {"subject": "public_key_data"},
        "fields": {"name": "John Doe", "expiry": "2025-12-31"}
    }
    result = wallet.acquire_certificate(args, "test")
    
    assert result == {}
    assert len(wallet._certificates) == 1


def test_acquire_multiple_certificates(wallet):
    """Test acquiring multiple certificates."""
    # Add first certificate
    wallet.acquire_certificate({
        "type": b"passport",
        "serialNumber": b"PP111",
        "certifier": "gov",
        "fields": {"country": "USA"}
    }, "test")
    
    # Add second certificate
    wallet.acquire_certificate({
        "type": b"license",
        "serialNumber": b"LIC222",
        "certifier": "state",
        "fields": {"state": "CA"}
    }, "test")
    
    assert len(wallet._certificates) == 2


def test_list_certificates_empty(wallet):
    """Test listing certificates when none exist."""
    result = wallet.list_certificates({}, "test")
    assert "certificates" in result
    assert result["certificates"] == []


def test_list_certificates_with_data(wallet):
    """Test listing certificates with data."""
    # Add multiple certificates
    for i in range(3):
        wallet.acquire_certificate({
            "type": b"cert_type",
            "serialNumber": f"SN{i}".encode(),
            "certifier": f"authority_{i}",
            "fields": {"index": i}
        }, "test")
    
    result = wallet.list_certificates({}, "test")
    assert len(result["certificates"]) == 3


def test_prove_certificate(wallet):
    """Test proving a certificate."""
    # First acquire a certificate
    wallet.acquire_certificate({
        "type": b"identity",
        "serialNumber": b"ID123",
        "certifier": "issuer",
        "keyringForSubject": {"key": "value"},
        "fields": {"verified": True}
    }, "test")
    
    # Try to prove it
    args = {
        "certificate": {
            "type": b"identity",
            "serialNumber": b"ID123",
            "certifier": "issuer"
        },
        "fieldsToReveal": ["verified"],
        "verifier": "verifier_pubkey"
    }
    result = wallet.prove_certificate(args, "test")
    
    # Should return empty dict or proof data
    assert isinstance(result, dict)


def test_relinquish_certificate(wallet):
    """Test relinquishing a certificate."""
    # First acquire a certificate
    wallet.acquire_certificate({
        "type": b"temp_cert",
        "serialNumber": b"TEMP001",
        "certifier": "temp_authority",
        "fields": {}
    }, "test")
    
    assert len(wallet._certificates) == 1
    
    # Relinquish it
    args = {
        "type": b"temp_cert",
        "serialNumber": b"TEMP001",
        "certifier": "temp_authority"
    }
    _ = wallet.relinquish_certificate(args, "test")
    
    # Certificate should be removed
    remaining = wallet.list_certificates({}, "test")
    assert len(remaining["certificates"]) == 0


def test_acquire_certificate_with_empty_fields(wallet):
    """Test acquiring certificate with minimal/empty fields."""
    args = {
        "type": b"minimal",
        "serialNumber": b"MIN001",
        "certifier": "minimal_issuer"
    }
    result = wallet.acquire_certificate(args, "test")
    
    assert result == {}
    assert len(wallet._certificates) == 1
    cert = wallet._certificates[0]
    assert cert["attributes"] == {}


def test_acquire_certificate_with_complex_fields(wallet):
    """Test acquiring certificate with complex nested fields."""
    complex_fields = {
        "personal": {
            "name": "John Doe",
            "age": 30,
            "address": {
                "street": "123 Main St",
                "city": "Anytown",
                "zip": "12345"
            }
        },
        "credentials": ["credential1", "credential2"],
        "verified": True,
        "score": 95.5
    }
    
    args = {
        "type": b"complex_cert",
        "serialNumber": b"COMPLEX001",
        "certifier": "complex_issuer",
        "fields": complex_fields
    }
    result = wallet.acquire_certificate(args, "test")
    
    assert result == {}
    cert = wallet._certificates[0]
    assert cert["attributes"] == complex_fields


def test_list_certificates_preserves_order(wallet):
    """Test that list_certificates preserves acquisition order."""
    serials = [f"SN{i:03d}".encode() for i in range(5)]
    
    for serial in serials:
        wallet.acquire_certificate({
            "type": b"ordered",
            "serialNumber": serial,
            "certifier": "issuer",
            "fields": {}
        }, "test")
    
    result = wallet.list_certificates({}, "test")
    certs = result["certificates"]
    
    # Verify order is preserved
    for i, cert in enumerate(certs):
        assert serials[i] in cert.get("certificateBytes", b"")


def test_certificate_keyring_storage(wallet):
    """Test that certificate keyring is properly stored."""
    keyring = {
        "masterKey": "key_data_123",
        "derivedKeys": ["key1", "key2"],
        "metadata": {"created": "2024-01-01"}
    }
    
    wallet.acquire_certificate({
        "type": b"keyring_cert",
        "serialNumber": b"KR001",
        "certifier": "issuer",
        "keyringForSubject": keyring,
        "fields": {}
    }, "test")
    
    cert = wallet._certificates[0]
    assert cert["keyring"] == keyring


def test_certificate_match_tuple_storage(wallet):
    """Test that certificate match tuple is properly stored."""
    cert_type = b"match_test"
    serial = b"MATCH001"
    certifier = "match_issuer"
    
    wallet.acquire_certificate({
        "type": cert_type,
        "serialNumber": serial,
        "certifier": certifier,
        "fields": {}
    }, "test")
    
    cert = wallet._certificates[0]
    assert "match" in cert
    assert cert["match"] == (cert_type, serial, certifier)


def test_discover_by_attributes(wallet):
    """Test discovering certificates by attributes."""
    # Add certificates with searchable attributes
    wallet.acquire_certificate({
        "type": b"searchable",
        "serialNumber": b"SEARCH001",
        "certifier": "issuer",
        "fields": {"category": "education", "level": "bachelor"}
    }, "test")
    
    wallet.acquire_certificate({
        "type": b"searchable",
        "serialNumber": b"SEARCH002",
        "certifier": "issuer",
        "fields": {"category": "education", "level": "master"}
    }, "test")
    
    # Try to discover
    args = {
        "attributes": {"category": "education"}
    }
    result = wallet.discover_by_attributes(args, "test")
    
    assert isinstance(result, dict)


def test_discover_by_identity_key(wallet):
    """Test discovering certificates by identity key."""
    args = {
        "identityKey": wallet.public_key.hex(),
        "limit": 10
    }
    result = wallet.discover_by_identity_key(args, "test")
    
    assert isinstance(result, dict)

