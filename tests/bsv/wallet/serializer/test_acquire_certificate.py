"""
Comprehensive tests for bsv/wallet/serializer/acquire_certificate.py

Tests serialization and deserialization of certificate acquisition arguments.
"""

import pytest
from bsv.wallet.serializer.acquire_certificate import (
    serialize_acquire_certificate_args,
    deserialize_acquire_certificate_args,
    DIRECT,
    ISSUANCE,
)

# Helper for required direct protocol fields
DIRECT_REQUIRED = {
    "serialNumber": b"\x00" * 32,
    "revocationOutpoint": {"txid": b"\x00" * 32, "index": 0},
    "signature": b"",
    "keyringRevealer": {"certifier": True},
    "keyringForSubject": {},
}


class TestSerializeDirectProtocol:
    """Test serialization with direct acquisition protocol."""
    
    def test_serialize_minimal_direct(self):
        """Test serializing minimal direct protocol args."""
        args = {
            "type": b"\x01" * 32,
            "certifier": b"\x02" * 33,
            "acquisitionProtocol": "direct",
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
        assert len(result) > 0
    
    def test_serialize_direct_with_fields(self):
        """Test serializing with fields map."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "fields": {"key1": "value1", "key2": "value2"},
            "acquisitionProtocol": "direct",
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_direct_with_privileged(self):
        """Test serializing with privileged flag."""
        args = {
            "type": b"\xAB" * 32,
            "certifier": b"\xCD" * 33,
            "privileged": True,
            "privilegedReason": "testing",
            "acquisitionProtocol": "direct",
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_direct_with_serial_number(self):
        """Test serializing with serial number."""
        args = {
            "type": b"\x11" * 32,
            "certifier": b"\x22" * 33,
            "acquisitionProtocol": "direct",
            "serialNumber": b"\xFF" * 32,
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_direct_with_revocation_outpoint(self):
        """Test serializing with revocation outpoint."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "revocationOutpoint": {
                "txid": b"\xAA" * 32,
                "index": 5
            }
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_direct_with_signature(self):
        """Test serializing with signature."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "signature": b"\x12\x34\x56\x78",
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_direct_with_keyring_revealer_certifier(self):
        """Test serializing with keyring revealer as certifier."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "keyringRevealer": {"certifier": True},
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_direct_with_keyring_revealer_pubkey(self):
        """Test serializing with keyring revealer pubkey."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "keyringRevealer": {"pubKey": b"\xAB" * 33},
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_direct_with_keyring_for_subject(self):
        """Test serializing with keyring for subject."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "keyringForSubject": {
                "key1": b"value1",
                "key2": b"value2",
            }
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_direct_with_keyring_for_subject_string_values(self):
        """Test serializing with keyring for subject with string values."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "keyringForSubject": {
                "key1": "stringvalue",
            }
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)


class TestSerializeIssuanceProtocol:
    """Test serialization with issuance acquisition protocol."""
    
    def test_serialize_issuance_minimal(self):
        """Test serializing minimal issuance protocol args."""
        args = {
            "type": b"\x01" * 32,
            "certifier": b"\x02" * 33,
            "acquisitionProtocol": "issuance",
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_issuance_with_url(self):
        """Test serializing issuance with certifier URL."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "issuance",
            "certifierUrl": "https://certifier.example.com",
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_issuance_with_fields(self):
        """Test serializing issuance with fields."""
        args = {
            "type": b"\xAA" * 32,
            "certifier": b"\xBB" * 33,
            "acquisitionProtocol": "issuance",
            "fields": {"name": "John", "email": "john@example.com"},
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)


class TestDeserializeDirectProtocol:
    """Test deserialization with direct protocol."""
    
    def test_deserialize_direct_minimal(self):
        """Test deserializing minimal direct protocol."""
        args = {
            "type": b"\x01" * 32,
            "certifier": b"\x02" * 33,
            "acquisitionProtocol": "direct",
            "serialNumber": b"\x00" * 32,
            "revocationOutpoint": {"txid": b"\x00" * 32, "index": 0},
            "signature": b"",
            "keyringRevealer": {"certifier": True},
            "keyringForSubject": {},
        }
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["acquisitionProtocol"] == "direct"
        assert deserialized["type"] == b"\x01" * 32
        assert deserialized["certifier"] == b"\x02" * 33
    
    def test_deserialize_direct_with_fields(self):
        """Test deserializing with fields."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "fields": {"alpha": "one", "beta": "two"},
            **DIRECT_REQUIRED,
        }
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["fields"]["alpha"] == "one"
        assert deserialized["fields"]["beta"] == "two"
    
    def test_deserialize_direct_with_privileged_true(self):
        """Test deserializing with privileged=True."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "privileged": True,
            "privilegedReason": "admin access",
            **DIRECT_REQUIRED,
        }
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["privileged"] is True
        assert deserialized["privilegedReason"] == "admin access"
    
    def test_deserialize_direct_with_privileged_false(self):
        """Test deserializing with privileged=False."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "privileged": False,
            "privilegedReason": "",
            **DIRECT_REQUIRED,
        }
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["privileged"] is False
    
    def test_deserialize_direct_with_revocation_outpoint(self):
        """Test deserializing with revocation outpoint."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "serialNumber": b"\x00" * 32,
            "revocationOutpoint": {
                "txid": b"\xDE\xAD" * 16,
                "index": 42
            },
            "signature": b"",
            "keyringRevealer": {"certifier": True},
            "keyringForSubject": {},
        }
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["revocationOutpoint"]["txid"] == b"\xDE\xAD" * 16
        assert deserialized["revocationOutpoint"]["index"] == 42
    
    def test_deserialize_direct_with_keyring_revealer_certifier(self):
        """Test deserializing with keyring revealer as certifier."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "serialNumber": b"\x00" * 32,
            "revocationOutpoint": {"txid": b"\x00" * 32, "index": 0},
            "signature": b"",
            "keyringRevealer": {"certifier": True},
            "keyringForSubject": {},
        }
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["keyringRevealer"]["certifier"] is True
    
    def test_deserialize_direct_with_keyring_for_subject(self):
        """Test deserializing with keyring for subject."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "serialNumber": b"\x00" * 32,
            "revocationOutpoint": {"txid": b"\x00" * 32, "index": 0},
            "signature": b"",
            "keyringRevealer": {"certifier": True},
            "keyringForSubject": {
                "alpha": b"dataA",
                "beta": b"dataB",
            }
        }
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert b"dataA" in deserialized["keyringForSubject"]["alpha"]
        assert b"dataB" in deserialized["keyringForSubject"]["beta"]


class TestDeserializeIssuanceProtocol:
    """Test deserialization with issuance protocol."""
    
    def test_deserialize_issuance_minimal(self):
        """Test deserializing minimal issuance protocol."""
        args = {
            "type": b"\x03" * 32,
            "certifier": b"\x04" * 33,
            "acquisitionProtocol": "issuance",
        }
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["acquisitionProtocol"] == "issuance"
    
    def test_deserialize_issuance_with_url(self):
        """Test deserializing issuance with URL."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "issuance",
            "certifierUrl": "https://example.com/cert",
        }
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["certifierUrl"] == "https://example.com/cert"


class TestRoundTrip:
    """Test round-trip serialization/deserialization."""
    
    @pytest.mark.parametrize("protocol", ["direct", "issuance"])
    def test_round_trip_basic(self, protocol):
        """Test basic round trip for both protocols."""
        args = {
            "type": b"\xFF" * 32,
            "certifier": b"\xEE" * 33,
            "acquisitionProtocol": protocol,
        }
        if protocol == "direct":
            args.update(DIRECT_REQUIRED)
        
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["acquisitionProtocol"] == protocol
        assert deserialized["type"] == args["type"]
        assert deserialized["certifier"] == args["certifier"]
    
    def test_round_trip_direct_complete(self):
        """Test complete round trip with direct protocol."""
        args = {
            "type": b"\x11" * 32,
            "certifier": b"\x22" * 33,
            "acquisitionProtocol": "direct",
            "fields": {"field1": "val1", "field2": "val2"},
            "privileged": True,
            "privilegedReason": "admin",
            "serialNumber": b"\x33" * 32,
            "revocationOutpoint": {"txid": b"\x44" * 32, "index": 10},
            "signature": b"sig_data",
            "keyringRevealer": {"certifier": True},
            "keyringForSubject": {"key1": b"data1"},
        }
        
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["acquisitionProtocol"] == "direct"
        assert deserialized["fields"]["field1"] == "val1"
        assert deserialized["privileged"] is True
        assert deserialized["revocationOutpoint"]["index"] == 10
    
    def test_round_trip_issuance_complete(self):
        """Test complete round trip with issuance protocol."""
        args = {
            "type": b"\xAA" * 32,
            "certifier": b"\xBB" * 33,
            "acquisitionProtocol": "issuance",
            "fields": {"name": "Alice", "role": "user"},
            "privileged": False,
            "privilegedReason": "",
            "certifierUrl": "https://ca.example.org",
        }
        
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["acquisitionProtocol"] == "issuance"
        assert deserialized["certifierUrl"] == "https://ca.example.org"
        assert deserialized["fields"]["name"] == "Alice"


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_serialize_empty_fields(self):
        """Test serializing with empty fields dict."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "fields": {},
            "acquisitionProtocol": "direct",
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_none_fields(self):
        """Test serializing with None fields."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "fields": None,
            "acquisitionProtocol": "direct",
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_fields_sorted_order(self):
        """Test that fields are serialized in sorted order."""
        args1 = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "fields": {"z": "last", "a": "first"},
            "acquisitionProtocol": "direct",
        }
        args2 = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "fields": {"a": "first", "z": "last"},
            "acquisitionProtocol": "direct",
        }
        
        result1 = serialize_acquire_certificate_args(args1)
        result2 = serialize_acquire_certificate_args(args2)
        
        assert result1 == result2  # Same serialization regardless of dict order
    
    def test_serialize_missing_type_uses_default(self):
        """Test serializing with missing type uses empty default."""
        args = {
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_missing_certifier_uses_default(self):
        """Test serializing with missing certifier uses empty default."""
        args = {
            "type": b"\x00" * 32,
            "acquisitionProtocol": "direct",
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_empty_keyring_for_subject(self):
        """Test serializing with empty keyring for subject."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "keyringForSubject": {},
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_none_keyring_for_subject(self):
        """Test serializing with None keyring for subject."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "keyringForSubject": None,
        }
        result = serialize_acquire_certificate_args(args)
        assert isinstance(result, bytes)
    
    def test_default_protocol_is_direct(self):
        """Test that default protocol is direct."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            # acquisitionProtocol not specified
            **DIRECT_REQUIRED,
        }
        result = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(result)
        
        # Default should be "direct" based on code logic
        assert deserialized["acquisitionProtocol"] == "direct"
    
    def test_round_trip_with_unicode_fields(self):
        """Test round trip with unicode in fields."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "issuance",
            "fields": {"名前": "太郎", "email": "taro@例.jp"},
        }
        
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["fields"]["名前"] == "太郎"
    
    def test_round_trip_privileged_none(self):
        """Test round trip with privileged=None."""
        args = {
            "type": b"\x00" * 32,
            "certifier": b"\x00" * 33,
            "acquisitionProtocol": "direct",
            "privileged": None,
            **DIRECT_REQUIRED,
        }
        
        serialized = serialize_acquire_certificate_args(args)
        deserialized = deserialize_acquire_certificate_args(serialized)
        
        assert deserialized["privileged"] is None

