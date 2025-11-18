"""
Comprehensive tests for bsv/auth/requested_certificate_set.py

Tests certificate type mapping, certifier validation, and JSON serialization.
"""

import base64
import json
import pytest
from unittest.mock import Mock
from bsv.keys import PublicKey, PrivateKey
from bsv.auth.requested_certificate_set import (
    RequestedCertificateTypeIDAndFieldList,
    RequestedCertificateSet,
    certifier_in_list,
    is_empty_public_key,
)


class TestRequestedCertificateTypeIDAndFieldList:
    """Test RequestedCertificateTypeIDAndFieldList class."""
    
    def test_init_empty(self):
        """Test initialization with no mapping."""
        cert_types = RequestedCertificateTypeIDAndFieldList()
        assert cert_types.mapping == {}
        assert cert_types.is_empty()
    
    def test_init_with_mapping(self):
        """Test initialization with mapping."""
        cert_type = b"A" * 32
        mapping = {cert_type: ["name", "email"]}
        cert_types = RequestedCertificateTypeIDAndFieldList(mapping)
        assert cert_types.mapping == mapping
        assert not cert_types.is_empty()
    
    def test_to_json_dict(self):
        """Test conversion to JSON dict."""
        cert_type = b"B" * 32
        mapping = {cert_type: ["field1", "field2"]}
        cert_types = RequestedCertificateTypeIDAndFieldList(mapping)
        json_dict = cert_types.to_json_dict()
        expected_key = base64.b64encode(cert_type).decode('ascii')
        assert expected_key in json_dict
        assert json_dict[expected_key] == ["field1", "field2"]
    
    def test_from_json_dict_valid(self):
        """Test creation from valid JSON dict."""
        cert_type = b"C" * 32
        json_dict = {base64.b64encode(cert_type).decode('ascii'): ["name"]}
        cert_types = RequestedCertificateTypeIDAndFieldList.from_json_dict(json_dict)
        assert cert_type in cert_types
        assert cert_types[cert_type] == ["name"]
    
    def test_from_json_dict_invalid_length(self):
        """Test from_json_dict with invalid certificate type length."""
        invalid_key = base64.b64encode(b"short").decode('ascii')
        json_dict = {invalid_key: ["field"]}
        with pytest.raises(ValueError, match="Expected 32 bytes"):
            RequestedCertificateTypeIDAndFieldList.from_json_dict(json_dict)
    
    def test_getitem(self):
        """Test __getitem__ method."""
        cert_type = b"D" * 32
        mapping = {cert_type: ["email"]}
        cert_types = RequestedCertificateTypeIDAndFieldList(mapping)
        assert cert_types[cert_type] == ["email"]
    
    def test_setitem(self):
        """Test __setitem__ method."""
        cert_type = b"E" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList()
        cert_types[cert_type] = ["phone"]
        assert cert_types[cert_type] == ["phone"]
    
    def test_contains(self):
        """Test __contains__ method."""
        cert_type = b"F" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["field"]})
        assert cert_type in cert_types
        assert b"G" * 32 not in cert_types
    
    def test_len(self):
        """Test __len__ method."""
        cert_types = RequestedCertificateTypeIDAndFieldList()
        assert len(cert_types) == 0
        cert_types[b"H" * 32] = ["field1"]
        assert len(cert_types) == 1
        cert_types[b"I" * 32] = ["field2"]
        assert len(cert_types) == 2
    
    def test_items(self):
        """Test items method."""
        cert_type1 = b"J" * 32
        cert_type2 = b"K" * 32
        mapping = {cert_type1: ["a"], cert_type2: ["b"]}
        cert_types = RequestedCertificateTypeIDAndFieldList(mapping)
        items = list(cert_types.items())
        assert len(items) == 2
        assert (cert_type1, ["a"]) in items
        assert (cert_type2, ["b"]) in items


class TestHelperFunctions:
    """Test helper functions."""
    
    def test_certifier_in_list_found(self):
        """Test certifier_in_list when certifier is in list."""
        pk1 = PrivateKey().public_key()
        pk2 = PrivateKey().public_key()
        certifiers = [pk1, pk2]
        assert certifier_in_list(certifiers, pk1)
        assert certifier_in_list(certifiers, pk2)
    
    def test_certifier_in_list_not_found(self):
        """Test certifier_in_list when certifier is not in list."""
        pk1 = PrivateKey().public_key()
        pk2 = PrivateKey().public_key()
        certifiers = [pk1]
        assert not certifier_in_list(certifiers, pk2)
    
    def test_certifier_in_list_none(self):
        """Test certifier_in_list with None."""
        pk1 = PrivateKey().public_key()
        certifiers = [pk1]
        assert not certifier_in_list(certifiers, None)
    
    def test_certifier_in_list_empty_list(self):
        """Test certifier_in_list with empty list."""
        pk1 = PrivateKey().public_key()
        assert not certifier_in_list([], pk1)
    
    def test_is_empty_public_key_none(self):
        """Test is_empty_public_key with None."""
        assert is_empty_public_key(None)
    
    def test_is_empty_public_key_zero_bytes(self):
        """Test is_empty_public_key with zero bytes."""
        mock_key = Mock(spec=PublicKey)
        mock_key.serialize.return_value = b'\x00' * 33
        assert is_empty_public_key(mock_key)
    
    def test_is_empty_public_key_valid_key(self):
        """Test is_empty_public_key with valid key."""
        pk = PrivateKey().public_key()
        # A newly generated key should not be empty
        assert not is_empty_public_key(pk)
    
    def test_is_empty_public_key_exception(self):
        """Test is_empty_public_key when serialize raises exception."""
        mock_key = Mock(spec=PublicKey)
        mock_key.serialize.side_effect = Exception("Serialization error")
        assert is_empty_public_key(mock_key)


class TestRequestedCertificateSet:
    """Test RequestedCertificateSet class."""
    
    def test_init_empty(self):
        """Test initialization with no parameters."""
        cert_set = RequestedCertificateSet()
        assert cert_set.certifiers == []
        assert cert_set.certificate_types.is_empty()
    
    def test_init_with_params(self):
        """Test initialization with certifiers and certificate types."""
        pk = PrivateKey().public_key()
        cert_type = b"L" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["name"]})
        cert_set = RequestedCertificateSet([pk], cert_types)
        assert cert_set.certifiers == [pk]
        assert cert_set.certificate_types == cert_types
    
    def test_to_json_dict(self):
        """Test conversion to JSON dict."""
        pk = PrivateKey().public_key()
        cert_type = b"M" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["email"]})
        cert_set = RequestedCertificateSet([pk], cert_types)
        json_dict = cert_set.to_json_dict()
        assert "certifiers" in json_dict
        assert "certificateTypes" in json_dict
        assert len(json_dict["certifiers"]) == 1
        assert json_dict["certifiers"][0] == pk.hex()
    
    def test_from_json_dict(self):
        """Test creation from JSON dict."""
        pk = PrivateKey().public_key()
        cert_type = b"N" * 32
        json_dict = {
            "certifiers": [pk.hex()],
            "certificateTypes": {base64.b64encode(cert_type).decode('ascii'): ["name"]}
        }
        cert_set = RequestedCertificateSet.from_json_dict(json_dict)
        assert len(cert_set.certifiers) == 1
        assert cert_set.certifiers[0].hex() == pk.hex()
        assert cert_type in cert_set.certificate_types
    
    def test_to_json(self):
        """Test conversion to JSON string."""
        pk = PrivateKey().public_key()
        cert_type = b"O" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["phone"]})
        cert_set = RequestedCertificateSet([pk], cert_types)
        json_str = cert_set.to_json()
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert "certifiers" in parsed
        assert "certificateTypes" in parsed
    
    def test_from_json(self):
        """Test creation from JSON string."""
        pk = PrivateKey().public_key()
        cert_type = b"P" * 32
        json_dict = {
            "certifiers": [pk.hex()],
            "certificateTypes": {base64.b64encode(cert_type).decode('ascii'): ["address"]}
        }
        json_str = json.dumps(json_dict)
        cert_set = RequestedCertificateSet.from_json(json_str)
        assert len(cert_set.certifiers) == 1
        assert cert_type in cert_set.certificate_types
    
    def test_validate_success(self):
        """Test validate with valid data."""
        pk = PrivateKey().public_key()
        cert_type = b"Q" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["name"]})
        cert_set = RequestedCertificateSet([pk], cert_types)
        cert_set.validate()  # Should not raise
    
    def test_validate_empty_certifiers(self):
        """Test validate with empty certifiers list."""
        cert_type = b"R" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["name"]})
        cert_set = RequestedCertificateSet([], cert_types)
        with pytest.raises(ValueError, match="certifiers list is empty"):
            cert_set.validate()
    
    def test_validate_empty_certificate_types(self):
        """Test validate with empty certificate types."""
        pk = PrivateKey().public_key()
        cert_set = RequestedCertificateSet([pk], RequestedCertificateTypeIDAndFieldList())
        with pytest.raises(ValueError, match="certificate types map is empty"):
            cert_set.validate()
    
    def test_validate_invalid_cert_type_length(self):
        """Test validate with invalid certificate type length."""
        pk = PrivateKey().public_key()
        short_type = b"short"
        cert_types = RequestedCertificateTypeIDAndFieldList({short_type: ["field"]})
        cert_set = RequestedCertificateSet([pk], cert_types)
        with pytest.raises(ValueError, match="empty or invalid certificate type"):
            cert_set.validate()
    
    def test_validate_empty_fields(self):
        """Test validate with empty fields list."""
        pk = PrivateKey().public_key()
        cert_type = b"S" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: []})
        cert_set = RequestedCertificateSet([pk], cert_types)
        with pytest.raises(ValueError, match="no fields specified"):
            cert_set.validate()
    
    def test_validate_uninitialized_public_key(self):
        """Test validate with uninitialized public key."""
        mock_key = Mock(spec=PublicKey)
        mock_key.serialize.return_value = b'\x00' * 33
        cert_type = b"T" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["name"]})
        cert_set = RequestedCertificateSet([mock_key], cert_types)
        with pytest.raises(ValueError, match="contains an empty/uninitialized public key"):
            cert_set.validate()
    
    def test_certifier_in_set_found(self):
        """Test certifier_in_set when certifier is in set."""
        pk1 = PrivateKey().public_key()
        pk2 = PrivateKey().public_key()
        cert_type = b"U" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["name"]})
        cert_set = RequestedCertificateSet([pk1, pk2], cert_types)
        assert cert_set.certifier_in_set(pk1)
        assert cert_set.certifier_in_set(pk2)
    
    def test_certifier_in_set_not_found(self):
        """Test certifier_in_set when certifier is not in set."""
        pk1 = PrivateKey().public_key()
        pk2 = PrivateKey().public_key()
        cert_type = b"V" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["name"]})
        cert_set = RequestedCertificateSet([pk1], cert_types)
        assert not cert_set.certifier_in_set(pk2)
    
    def test_certifier_in_set_none(self):
        """Test certifier_in_set with None."""
        pk = PrivateKey().public_key()
        cert_type = b"W" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["name"]})
        cert_set = RequestedCertificateSet([pk], cert_types)
        assert not cert_set.certifier_in_set(None)
    
    def test_repr(self):
        """Test __repr__ method."""
        pk = PrivateKey().public_key()
        cert_type = b"X" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["name"]})
        cert_set = RequestedCertificateSet([pk], cert_types)
        repr_str = repr(cert_set)
        assert "RequestedCertificateSet" in repr_str
        assert "certifiers" in repr_str
        assert "certificate_types" in repr_str


class TestRoundTrip:
    """Test round-trip serialization and deserialization."""
    
    def test_json_round_trip(self):
        """Test JSON serialization round trip."""
        pk = PrivateKey().public_key()
        cert_type = b"Y" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["name", "email"]})
        original = RequestedCertificateSet([pk], cert_types)
        
        # To JSON and back
        json_str = original.to_json()
        restored = RequestedCertificateSet.from_json(json_str)
        
        # Verify
        assert len(restored.certifiers) == len(original.certifiers)
        assert restored.certifiers[0].hex() == original.certifiers[0].hex()
        assert cert_type in restored.certificate_types
        assert restored.certificate_types[cert_type] == ["name", "email"]
    
    def test_json_dict_round_trip(self):
        """Test JSON dict round trip."""
        pk1 = PrivateKey().public_key()
        pk2 = PrivateKey().public_key()
        cert_type1 = b"Z" * 32
        cert_type2 = b"0" * 32
        cert_types = RequestedCertificateTypeIDAndFieldList({
            cert_type1: ["field1"],
            cert_type2: ["field2", "field3"]
        })
        original = RequestedCertificateSet([pk1, pk2], cert_types)
        
        # To dict and back
        json_dict = original.to_json_dict()
        restored = RequestedCertificateSet.from_json_dict(json_dict)
        
        # Verify
        assert len(restored.certifiers) == 2
        assert len(restored.certificate_types) == 2
        assert cert_type1 in restored.certificate_types
        assert cert_type2 in restored.certificate_types

