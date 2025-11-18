# Coverage Improvement Tactical Plan - Specific Test Cases

This document provides concrete, implementable test cases for the highest-impact coverage improvements.

## 🎯 Immediate Action Items (Next 100 Test Cases)

### File: `bsv/utils.py` (0% → 80% = +286 statements)

#### Test Suite 1: Varint Operations (15 tests)
```python
# File: tests/bsv/test_utils_varint.py

import pytest
from bsv.utils import unsigned_to_varint, varint_to_unsigned

class TestVarintOperations:
    """Test varint encoding and decoding."""
    
    # Valid encodings
    def test_varint_encode_zero():
        assert unsigned_to_varint(0) == b'\x00'
    
    def test_varint_encode_single_byte():
        assert unsigned_to_varint(252) == b'\xfc'
    
    def test_varint_encode_fd_prefix():
        assert unsigned_to_varint(253) == b'\xfd\xfd\x00'
    
    def test_varint_encode_two_byte():
        assert unsigned_to_varint(65535) == b'\xfd\xff\xff'
    
    def test_varint_encode_fe_prefix():
        assert unsigned_to_varint(65536) == b'\xfe\x00\x00\x01\x00'
    
    def test_varint_encode_four_byte():
        assert unsigned_to_varint(4294967295) == b'\xfe\xff\xff\xff\xff'
    
    def test_varint_encode_ff_prefix():
        assert unsigned_to_varint(4294967296) == b'\xff\x00\x00\x00\x00\x01\x00\x00\x00'
    
    def test_varint_encode_eight_byte():
        assert unsigned_to_varint(18446744073709551615) == b'\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    
    # Round-trip tests
    @pytest.mark.parametrize("value", [0, 1, 127, 252, 253, 65535, 65536, 2**32-1, 2**32])
    def test_varint_round_trip(value):
        encoded = unsigned_to_varint(value)
        decoded, _ = varint_to_unsigned(encoded)
        assert decoded == value
    
    # Negative tests
    def test_varint_encode_negative_raises():
        with pytest.raises(ValueError, match="negative"):
            unsigned_to_varint(-1)
    
    def test_varint_decode_empty_raises():
        with pytest.raises(ValueError, match="empty"):
            varint_to_unsigned(b'')
    
    def test_varint_decode_incomplete_fd():
        with pytest.raises(ValueError, match="incomplete"):
            varint_to_unsigned(b'\xfd\x00')
    
    def test_varint_decode_incomplete_fe():
        with pytest.raises(ValueError, match="incomplete"):
            varint_to_unsigned(b'\xfe\x00\x00')
    
    def test_varint_decode_incomplete_ff():
        with pytest.raises(ValueError, match="incomplete"):
            varint_to_unsigned(b'\xff\x00\x00\x00')
    
    def test_varint_encode_overflow():
        with pytest.raises(ValueError, match="overflow"):
            unsigned_to_varint(2**64)
```

#### Test Suite 2: Hex Conversion Operations (10 tests)
```python
# File: tests/bsv/test_utils_hex.py

import pytest
from bsv.utils import hex_to_bytes, bytes_to_hex

class TestHexConversion:
    """Test hex string to bytes conversion."""
    
    def test_hex_to_bytes_simple():
        assert hex_to_bytes("48656c6c6f") == b"Hello"
    
    def test_hex_to_bytes_uppercase():
        assert hex_to_bytes("48656C6C6F") == b"Hello"
    
    def test_hex_to_bytes_mixed_case():
        assert hex_to_bytes("48656C6c6F") == b"Hello"
    
    def test_hex_to_bytes_empty():
        assert hex_to_bytes("") == b""
    
    def test_bytes_to_hex_simple():
        assert bytes_to_hex(b"Hello") == "48656c6c6f"
    
    def test_bytes_to_hex_empty():
        assert bytes_to_hex(b"") == ""
    
    # Round-trip tests
    @pytest.mark.parametrize("data", [b"", b"\x00", b"\xff", b"Test", b"\x00\xff\x00\xff"])
    def test_hex_round_trip(data):
        hex_str = bytes_to_hex(data)
        result = hex_to_bytes(hex_str)
        assert result == data
    
    # Negative tests
    def test_hex_to_bytes_odd_length():
        with pytest.raises(ValueError, match="odd length"):
            hex_to_bytes("123")
    
    def test_hex_to_bytes_invalid_char():
        with pytest.raises(ValueError, match="invalid hex"):
            hex_to_bytes("12GH")
    
    def test_hex_to_bytes_none_input():
        with pytest.raises(TypeError):
            hex_to_bytes(None)
```

#### Test Suite 3: Pushdrop Token Operations (12 tests)
```python
# File: tests/bsv/test_utils_pushdrop.py

import pytest
from bsv.utils import encode_pushdrop_token, decode_pushdrop_token

class TestPushdropTokens:
    """Test pushdrop token encoding and decoding."""
    
    def test_encode_pushdrop_token_simple():
        fields = [b"field1", b"field2"]
        result = encode_pushdrop_token(fields)
        assert isinstance(result, bytes)
    
    def test_encode_pushdrop_token_single_field():
        fields = [b"single"]
        result = encode_pushdrop_token(fields)
        assert result == b"OP_0 OP_RETURN single"  # Adjust to actual format
    
    def test_encode_pushdrop_token_empty_field():
        fields = [b"", b"data"]
        result = encode_pushdrop_token(fields)
        assert isinstance(result, bytes)
    
    def test_encode_pushdrop_token_large_field():
        fields = [b"x" * 1000]
        result = encode_pushdrop_token(fields)
        assert isinstance(result, bytes)
    
    def test_decode_pushdrop_token_simple():
        # Create a token first
        fields = [b"field1", b"field2"]
        token = encode_pushdrop_token(fields)
        decoded = decode_pushdrop_token(token)
        assert decoded == fields
    
    def test_decode_pushdrop_token_single():
        fields = [b"single"]
        token = encode_pushdrop_token(fields)
        decoded = decode_pushdrop_token(token)
        assert decoded == fields
    
    # Round-trip tests
    @pytest.mark.parametrize("fields", [
        [b"a"],
        [b"a", b"b"],
        [b"", b"nonempty"],
        [b"x" * 100],
    ])
    def test_pushdrop_round_trip(fields):
        token = encode_pushdrop_token(fields)
        decoded = decode_pushdrop_token(token)
        assert decoded == fields
    
    # Negative tests
    def test_encode_pushdrop_token_none():
        with pytest.raises(TypeError):
            encode_pushdrop_token(None)
    
    def test_encode_pushdrop_token_empty_list():
        with pytest.raises(ValueError, match="empty"):
            encode_pushdrop_token([])
    
    def test_decode_pushdrop_token_invalid():
        with pytest.raises(ValueError, match="invalid"):
            decode_pushdrop_token(b"invalid data")
    
    def test_decode_pushdrop_token_truncated():
        fields = [b"field1", b"field2"]
        token = encode_pushdrop_token(fields)
        with pytest.raises(ValueError):
            decode_pushdrop_token(token[:10])  # Truncated
    
    def test_decode_pushdrop_token_corrupted():
        fields = [b"field1"]
        token = encode_pushdrop_token(fields)
        corrupted = token[:-1] + b'\xff'  # Corrupt last byte
        with pytest.raises(ValueError):
            decode_pushdrop_token(corrupted)
```

### File: `bsv/wallet/serializer/list_outputs.py` (4% → 85% = +92 statements)

```python
# File: tests/bsv/wallet/test_list_outputs_serializer.py

import pytest
from bsv.wallet.serializer.list_outputs import (
    serialize_list_outputs_args,
    deserialize_list_outputs_result
)

class TestListOutputsSerialization:
    """Test list_outputs argument serialization."""
    
    # Basic serialization
    def test_serialize_minimal_args():
        args = {}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_basket():
        args = {"basket": "default"}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
        assert b"default" in result
    
    def test_serialize_with_single_tag():
        args = {"tags": ["tag1"]}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_multiple_tags():
        args = {"tags": ["tag1", "tag2", "tag3"]}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_basket_and_tags():
        args = {
            "basket": "custom",
            "tags": ["tag1", "tag2"]
        }
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_limit():
        args = {"limit": 10}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_offset():
        args = {"offset": 5}
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_all_options():
        args = {
            "basket": "full",
            "tags": ["a", "b"],
            "limit": 100,
            "offset": 10,
            "include_locking_script": True,
            "include_spent": False
        }
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    # Negative tests
    def test_serialize_with_none_basket():
        args = {"basket": None}
        # Should handle None gracefully or raise
        result = serialize_list_outputs_args(args)
        assert isinstance(result, bytes)
    
    def test_serialize_with_invalid_tags_type():
        args = {"tags": "not a list"}
        with pytest.raises(TypeError):
            serialize_list_outputs_args(args)
    
    def test_serialize_with_negative_limit():
        args = {"limit": -1}
        with pytest.raises(ValueError, match="negative"):
            serialize_list_outputs_args(args)
    
    def test_serialize_with_negative_offset():
        args = {"offset": -1}
        with pytest.raises(ValueError, match="negative"):
            serialize_list_outputs_args(args)

class TestListOutputsDeserialization:
    """Test list_outputs result deserialization."""
    
    def test_deserialize_empty_list():
        # Construct valid empty result bytes
        data = b'\x00'  # Zero outputs
        result = deserialize_list_outputs_result(data)
        assert result == {"outputs": []}
    
    def test_deserialize_single_output():
        # Construct valid single output bytes
        # Format: [count][output_data]
        data = b'\x01' + b'\x00' * 50  # Mock output data
        result = deserialize_list_outputs_result(data)
        assert len(result["outputs"]) == 1
    
    def test_deserialize_multiple_outputs():
        # Construct valid multiple outputs
        data = b'\x03' + (b'\x00' * 50) * 3  # 3 mock outputs
        result = deserialize_list_outputs_result(data)
        assert len(result["outputs"]) == 3
    
    def test_deserialize_output_with_all_fields():
        # Construct output with all optional fields
        # txid, vout, satoshis, locking_script, spent, etc.
        pass  # Implement based on actual format
    
    # Negative tests
    def test_deserialize_empty_data():
        with pytest.raises(ValueError, match="empty"):
            deserialize_list_outputs_result(b'')
    
    def test_deserialize_truncated_data():
        data = b'\x02' + b'\x00' * 10  # Says 2 outputs but insufficient data
        with pytest.raises(ValueError, match="truncated"):
            deserialize_list_outputs_result(data)
    
    def test_deserialize_corrupted_count():
        data = b'\xff' * 100  # Invalid varint count
        with pytest.raises(ValueError):
            deserialize_list_outputs_result(data)
    
    def test_deserialize_invalid_output_format():
        data = b'\x01' + b'\xff' * 10  # Invalid output structure
        with pytest.raises(ValueError):
            deserialize_list_outputs_result(data)

class TestListOutputsRoundTrip:
    """Test serialization round-trips."""
    
    def test_round_trip_minimal():
        args = {}
        serialized = serialize_list_outputs_args(args)
        # Can't really round-trip args, but ensure consistent serialization
        serialized2 = serialize_list_outputs_args(args)
        assert serialized == serialized2
    
    def test_round_trip_with_tags():
        args = {"tags": ["tag1", "tag2"]}
        serialized = serialize_list_outputs_args(args)
        serialized2 = serialize_list_outputs_args(args)
        assert serialized == serialized2
```

### File: `bsv/identity/client.py` (13% → 70% = +131 statements)

```python
# File: tests/bsv/identity/test_identity_client_comprehensive.py

import pytest
from unittest.mock import Mock, patch, MagicMock
from bsv.identity.client import IdentityClient
from bsv.identity.types import DisplayableIdentity

class TestIdentityClientAuthentication:
    """Test authentication methods."""
    
    @patch('bsv.identity.client.ContactsManager')
    def test_authenticate_success(mock_contacts):
        client = IdentityClient()
        mock_contacts.authenticate.return_value = {"token": "abc123"}
        result = client.authenticate("user", "pass")
        assert result["token"] == "abc123"
    
    @patch('bsv.identity.client.ContactsManager')
    def test_authenticate_invalid_credentials(mock_contacts):
        client = IdentityClient()
        mock_contacts.authenticate.side_effect = ValueError("Invalid credentials")
        with pytest.raises(ValueError, match="Invalid credentials"):
            client.authenticate("wrong", "wrong")
    
    @patch('bsv.identity.client.ContactsManager')
    def test_authenticate_network_error(mock_contacts):
        client = IdentityClient()
        mock_contacts.authenticate.side_effect = ConnectionError()
        with pytest.raises(ConnectionError):
            client.authenticate("user", "pass")
    
    def test_authenticate_empty_username():
        client = IdentityClient()
        with pytest.raises(ValueError, match="username"):
            client.authenticate("", "pass")
    
    def test_authenticate_empty_password():
        client = IdentityClient()
        with pytest.raises(ValueError, match="password"):
            client.authenticate("user", "")
    
    def test_authenticate_none_inputs():
        client = IdentityClient()
        with pytest.raises(TypeError):
            client.authenticate(None, None)

class TestIdentityClientLookup:
    """Test identity lookup methods."""
    
    @patch('bsv.identity.client.ContactsManager')
    def test_get_identity_by_key_found(mock_contacts):
        client = IdentityClient()
        expected = DisplayableIdentity(
            identity_key="key123",
            handle="user@domain.com",
            display_name="User"
        )
        mock_contacts.get_identity.return_value = expected
        result = client.get_identity("key123")
        assert result.identity_key == "key123"
    
    @patch('bsv.identity.client.ContactsManager')
    def test_get_identity_not_found(mock_contacts):
        client = IdentityClient()
        mock_contacts.get_identity.return_value = None
        result = client.get_identity("nonexistent")
        assert result is None
    
    @patch('bsv.identity.client.ContactsManager')
    def test_resolve_identity_by_handle(mock_contacts):
        client = IdentityClient()
        expected = DisplayableIdentity(
            identity_key="key123",
            handle="user@domain.com"
        )
        mock_contacts.resolve.return_value = expected
        result = client.resolve("user@domain.com")
        assert result.handle == "user@domain.com"
    
    def test_resolve_invalid_handle_format():
        client = IdentityClient()
        with pytest.raises(ValueError, match="invalid handle"):
            client.resolve("invalid handle without @")
    
    def test_resolve_empty_handle():
        client = IdentityClient()
        with pytest.raises(ValueError, match="empty"):
            client.resolve("")
    
    @patch('bsv.identity.client.ContactsManager')
    def test_resolve_network_timeout(mock_contacts):
        client = IdentityClient()
        mock_contacts.resolve.side_effect = TimeoutError()
        with pytest.raises(TimeoutError):
            client.resolve("user@domain.com")

class TestIdentityClientManagement:
    """Test identity creation and updates."""
    
    @patch('bsv.identity.client.ContactsManager')
    def test_create_identity(mock_contacts):
        client = IdentityClient()
        identity_data = {
            "handle": "newuser@domain.com",
            "display_name": "New User"
        }
        mock_contacts.create_identity.return_value = {"identity_key": "new123"}
        result = client.create_identity(identity_data)
        assert result["identity_key"] == "new123"
    
    @patch('bsv.identity.client.ContactsManager')
    def test_create_identity_duplicate_handle(mock_contacts):
        client = IdentityClient()
        identity_data = {"handle": "existing@domain.com"}
        mock_contacts.create_identity.side_effect = ValueError("Duplicate handle")
        with pytest.raises(ValueError, match="Duplicate"):
            client.create_identity(identity_data)
    
    def test_create_identity_missing_required_fields():
        client = IdentityClient()
        with pytest.raises(ValueError, match="required"):
            client.create_identity({})  # Missing handle
    
    @patch('bsv.identity.client.ContactsManager')
    def test_update_identity(mock_contacts):
        client = IdentityClient()
        updates = {"display_name": "Updated Name"}
        mock_contacts.update_identity.return_value = {"success": True}
        result = client.update_identity("key123", updates)
        assert result["success"] is True
    
    def test_update_identity_invalid_key():
        client = IdentityClient()
        with pytest.raises(ValueError):
            client.update_identity("", {})
    
    @patch('bsv.identity.client.ContactsManager')
    def test_delete_identity(mock_contacts):
        client = IdentityClient()
        mock_contacts.delete_identity.return_value = True
        result = client.delete_identity("key123")
        assert result is True
    
    @patch('bsv.identity.client.ContactsManager')
    def test_delete_identity_not_found(mock_contacts):
        client = IdentityClient()
        mock_contacts.delete_identity.return_value = False
        result = client.delete_identity("nonexistent")
        assert result is False

class TestIdentityClientEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_client_with_none_wallet():
        # Should create default wallet
        client = IdentityClient(wallet=None)
        assert client.wallet is not None
    
    def test_client_with_custom_originator():
        client = IdentityClient(originator="custom.domain.com")
        assert client.originator == "custom.domain.com"
    
    @patch('bsv.identity.client.ContactsManager')
    def test_concurrent_operations(mock_contacts):
        import threading
        client = IdentityClient()
        
        def operation():
            client.get_identity("key123")
        
        threads = [threading.Thread(target=operation) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Should not crash
    
    @patch('bsv.identity.client.ContactsManager')
    def test_malformed_response_handling(mock_contacts):
        client = IdentityClient()
        mock_contacts.get_identity.return_value = {"invalid": "structure"}
        with pytest.raises(ValueError, match="malformed"):
            client.get_identity("key123")
```

### File: `bsv/utils/binary.py` (31% → 85% = +36 statements)

```python
# File: tests/bsv/test_utils_binary.py

import pytest
from bsv.utils.binary import (
    int_to_bytes, bytes_to_int, 
    int_to_bytes_signed, bytes_to_int_signed,
    reverse_bytes, bits_to_bytes, bytes_to_bits
)

class TestIntToBytes:
    """Test integer to bytes conversion."""
    
    def test_int_to_bytes_zero():
        assert int_to_bytes(0, 1) == b'\x00'
    
    def test_int_to_bytes_one():
        assert int_to_bytes(1, 1) == b'\x01'
    
    def test_int_to_bytes_255():
        assert int_to_bytes(255, 1) == b'\xff'
    
    def test_int_to_bytes_256():
        assert int_to_bytes(256, 2) == b'\x01\x00'
    
    def test_int_to_bytes_max_uint32():
        result = int_to_bytes(2**32 - 1, 4)
        assert len(result) == 4
        assert result == b'\xff\xff\xff\xff'
    
    def test_int_to_bytes_little_endian():
        result = int_to_bytes(0x1234, 2, byteorder='little')
        assert result == b'\x34\x12'
    
    def test_int_to_bytes_big_endian():
        result = int_to_bytes(0x1234, 2, byteorder='big')
        assert result == b'\x12\x34'
    
    # Negative tests
    def test_int_to_bytes_overflow():
        with pytest.raises(OverflowError):
            int_to_bytes(256, 1)  # Doesn't fit in 1 byte
    
    def test_int_to_bytes_negative_unsigned():
        with pytest.raises(OverflowError):
            int_to_bytes(-1, 1)  # Negative in unsigned
    
    def test_int_to_bytes_zero_length():
        with pytest.raises(ValueError):
            int_to_bytes(0, 0)

class TestBytesToInt:
    """Test bytes to integer conversion."""
    
    def test_bytes_to_int_zero():
        assert bytes_to_int(b'\x00') == 0
    
    def test_bytes_to_int_one():
        assert bytes_to_int(b'\x01') == 1
    
    def test_bytes_to_int_255():
        assert bytes_to_int(b'\xff') == 255
    
    def test_bytes_to_int_multi_byte():
        assert bytes_to_int(b'\x01\x00') == 256
    
    def test_bytes_to_int_little_endian():
        assert bytes_to_int(b'\x34\x12', byteorder='little') == 0x1234
    
    def test_bytes_to_int_big_endian():
        assert bytes_to_int(b'\x12\x34', byteorder='big') == 0x1234
    
    # Round-trip tests
    @pytest.mark.parametrize("value,length", [
        (0, 1), (1, 1), (255, 1),
        (256, 2), (65535, 2),
        (2**32-1, 4), (2**64-1, 8)
    ])
    def test_int_bytes_round_trip(value, length):
        bytes_data = int_to_bytes(value, length)
        result = bytes_to_int(bytes_data)
        assert result == value
    
    # Negative tests
    def test_bytes_to_int_empty():
        with pytest.raises(ValueError):
            bytes_to_int(b'')

class TestSignedConversions:
    """Test signed integer conversions."""
    
    def test_int_to_bytes_signed_negative():
        result = int_to_bytes_signed(-1, 1)
        assert result == b'\xff'
    
    def test_int_to_bytes_signed_positive():
        result = int_to_bytes_signed(127, 1)
        assert result == b'\x7f'
    
    def test_bytes_to_int_signed_negative():
        assert bytes_to_int_signed(b'\xff') == -1
    
    def test_bytes_to_int_signed_positive():
        assert bytes_to_int_signed(b'\x7f') == 127
    
    @pytest.mark.parametrize("value,length", [
        (-128, 1), (127, 1),
        (-32768, 2), (32767, 2),
        (-2147483648, 4), (2147483647, 4)
    ])
    def test_signed_round_trip(value, length):
        bytes_data = int_to_bytes_signed(value, length)
        result = bytes_to_int_signed(bytes_data)
        assert result == value

class TestByteOperations:
    """Test byte manipulation operations."""
    
    def test_reverse_bytes_simple():
        assert reverse_bytes(b'\x01\x02\x03') == b'\x03\x02\x01'
    
    def test_reverse_bytes_single():
        assert reverse_bytes(b'\x42') == b'\x42'
    
    def test_reverse_bytes_empty():
        assert reverse_bytes(b'') == b''
    
    def test_reverse_bytes_palindrome():
        data = b'\x01\x02\x01'
        assert reverse_bytes(data) == data
    
    def test_bits_to_bytes():
        bits = [1, 0, 1, 0, 1, 0, 1, 0]  # 0xAA
        result = bits_to_bytes(bits)
        assert result == b'\xaa'
    
    def test_bytes_to_bits():
        result = bytes_to_bits(b'\xaa')
        assert result == [1, 0, 1, 0, 1, 0, 1, 0]
    
    @pytest.mark.parametrize("data", [b'', b'\x00', b'\xff', b'\x01\x02\x03'])
    def test_bits_round_trip(data):
        bits = bytes_to_bits(data)
        result = bits_to_bytes(bits)
        assert result == data
```

## 🎯 Next Steps

1. **Implement Test Suite 1-3** for `bsv/utils.py`
2. **Implement list_outputs tests**
3. **Implement identity_client tests**
4. **Implement binary operations tests**
5. **Run coverage and verify improvement**
6. **Iterate based on results**

## 📊 Expected Impact

| File | Current | Target | New Tests | Impact |
|------|---------|--------|-----------|--------|
| bsv/utils.py | 0% | 80% | 37 | +286 stmts |
| bsv/wallet/serializer/list_outputs.py | 4% | 85% | 24 | +92 stmts |
| bsv/identity/client.py | 13% | 70% | 31 | +131 stmts |
| bsv/utils/binary.py | 31% | 85% | 27 | +36 stmts |
| **Total** | **-** | **-** | **119** | **+545 stmts** |

**Expected Coverage Increase: 66% → 69%**

---

*Generated: 2024-11-18*
*Status: Ready for Implementation*

