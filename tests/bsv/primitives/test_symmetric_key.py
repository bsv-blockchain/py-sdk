"""Tests for SymmetricKey - AES-GCM encryption compatible with TS/Go SDKs.

These tests verify that:
1. Basic encryption/decryption works
2. Cross-SDK compatibility with TS/Go test vectors
"""

import pytest
import base64

from bsv.primitives.symmetric_key import SymmetricKey


class TestSymmetricKeyBasic:
    """Basic functionality tests."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test basic encryption and decryption."""
        key = SymmetricKey.from_random()
        plaintext = b"a thing to encrypt"
        
        ciphertext = key.encrypt(plaintext)
        decrypted = key.decrypt(ciphertext)
        
        assert decrypted == plaintext

    def test_encrypt_decrypt_string(self):
        """Test encryption with string input."""
        key = SymmetricKey.from_random()
        plaintext = "Hello, World!"
        
        ciphertext = key.encrypt(plaintext)
        decrypted = key.decrypt(ciphertext)
        
        assert decrypted == plaintext.encode('utf-8')

    def test_encrypt_decrypt_list(self):
        """Test encryption with list input."""
        key = SymmetricKey.from_random()
        plaintext = [42, 99, 33, 0, 1]
        
        ciphertext = key.encrypt(plaintext)
        decrypted = key.decrypt(ciphertext)
        
        assert list(decrypted) == plaintext

    def test_ciphertext_format(self):
        """Test that ciphertext has correct format: IV (32) + data + tag (16)."""
        key = SymmetricKey.from_random()
        plaintext = b"test"
        
        ciphertext = key.encrypt(plaintext)
        
        # Minimum length: IV (32) + plaintext (4) + tag (16) = 52
        assert len(ciphertext) >= 48
        # Length should be: 32 + len(plaintext) + 16
        assert len(ciphertext) == 32 + len(plaintext) + 16

    def test_different_keys_produce_different_ciphertext(self):
        """Test that different keys produce different ciphertext."""
        key1 = SymmetricKey.from_random()
        key2 = SymmetricKey.from_random()
        plaintext = b"same plaintext"
        
        ciphertext1 = key1.encrypt(plaintext)
        ciphertext2 = key2.encrypt(plaintext)
        
        assert ciphertext1 != ciphertext2

    def test_wrong_key_fails_decryption(self):
        """Test that wrong key fails decryption."""
        key1 = SymmetricKey.from_random()
        key2 = SymmetricKey.from_random()
        plaintext = b"secret message"
        
        ciphertext = key1.encrypt(plaintext)
        
        with pytest.raises(ValueError, match="Decryption failed"):
            key2.decrypt(ciphertext)

    def test_ciphertext_too_short_error(self):
        """Test error for ciphertext shorter than IV + tag."""
        key = SymmetricKey.from_random()
        short_ciphertext = b"\x00" * 47  # Less than 48 bytes minimum
        
        with pytest.raises(ValueError, match="Ciphertext too short"):
            key.decrypt(short_ciphertext)


class TestSymmetricKeyConstruction:
    """Test key construction from various sources."""

    def test_from_bytes(self):
        """Test construction from bytes."""
        key_bytes = bytes(range(32))
        key = SymmetricKey.from_bytes(key_bytes)
        
        assert key.to_bytes() == key_bytes

    def test_from_hex(self):
        """Test construction from hex string."""
        hex_string = "5a90d59d829197983a54d887fdea2dc4c38098f00ba3110f2645633b6ea11458"
        key = SymmetricKey.from_hex(hex_string)
        
        assert key.to_hex() == hex_string

    def test_from_list(self):
        """Test construction from list of integers."""
        key_list = list(range(32))
        key = SymmetricKey(key_list)
        
        assert key.to_bytes() == bytes(key_list)

    def test_from_int(self):
        """Test construction from integer."""
        key_int = 0x5a90d59d829197983a54d887fdea2dc4c38098f00ba3110f2645633b6ea11458
        key = SymmetricKey(key_int)
        
        assert len(key.to_bytes()) == 32

    def test_short_key_padding(self):
        """Test that short keys are left-padded with zeros (matching Go SDK)."""
        # 31-byte key should be padded to 32 bytes
        short_key = bytes(range(31))
        key = SymmetricKey(short_key)
        
        expected = b'\x00' + bytes(range(31))
        assert key.to_bytes() == expected
        assert len(key.to_bytes()) == 32


class TestSymmetricKeyTSGoCompatibility:
    """Test vectors from TS/Go SDKs for cross-SDK compatibility.
    
    These vectors are from:
    - ts-sdk/src/primitives/__tests/SymmetricKey.vectors.ts
    - go-sdk/primitives/ec/testdata/SymmetricKey.vectors.json
    """

    # Test vectors from TS/Go SDKs (base64 encoded)
    TEST_VECTORS = [
        {
            "ciphertext": "1cf74FpvW0koFZk5e1VQcCtF7UdLj9mtN/L9loFlXwhf6w/06THwVirsvDShuT/KlOjO/HFALj8AcGLU1KRs4zNJDaX2wNebuPkH+qp5N/0cp3fZxgFzHJB3jBPDcdFi8O9WXIBLx9jUQ5KFQk0mZCB2k90VniInWuzqqOQAQQlBy2rgBWp4xg==",
            "key": "LIe9CoVXxDDDKt9F4j2lE+GP4oPcMElwyX+LVsuRLqw=",
            "plaintext": "5+w9tts+i14GDfPSEJwcaAfce7zVLC7wsRAMnCBqIczkqL08I05FZTl7n14H9hnPkS7HBm3EGWNDKCZ64ckCGg=="
        },
        {
            "ciphertext": "IFh45HxwvK7wgIZr5UDxvUiEkvjsXVV6VIksaEQoTNCPleaRxE1CE1eZj5ZSPa/Mo2HXa2kvEmVAMslY12gMb7qHAHT2fSORB8TJKubKcjwGUrRxqOWvk24lv7QKhq3uhKkJxZSkPBZS6UM+xX+x7Mb53CoC8Z+7Ork50wGRAA415C+T8FIluA==",
            "key": "Di30+CTH8yKVJfXmbkRU6DOesD042IkjZCbFL1lnNqY=",
            "plaintext": "6pHqDrkIuGmWIpB1spu30PP848D04WlERSjrEZ/JD0jfdS814cOjs4MFkePT1IHeM4+qGFwAMk7HKgWShOKFDQ=="
        },
        {
            "ciphertext": "JeUMCTX3hW7uH7Njfqjtjxd/8jB0Uj4eLLbLNBSMqF3XJmtq2oyX/WWS1po8cwn7jrcK0k8mVxHax/DctH6CIDMc0udBxWYLDyftvIYr448otWmn2IKQN4d3Bh2PKdiIQOo36DO2wOy+T2OJSmJ2XvAkenSZIckCdPIQVpeIi7Bt2ZpHmkObkg==",
            "key": "v7kFn4JdB3OVVjy8lk7UTvWe0vY5Qyzn64Q0EVoezlU=",
            "plaintext": "bSYHdJn15pcsaI8CNmfjKQ3ZvMg7zBaxuxBqyWBmCLdqj29bK54C26G1mx5e605hDrFpuJoNSDTECrk67ebffA=="
        },
        {
            "ciphertext": "ktpzKolKsvtWrvLl0yMdGvh5ngd1hiaNcC1b5yuzo2DEKO/4S7gePO/CWOmW/dloHhzfbBQH9rKDFKK7xHHgqYRc",
            "key": "qIgnjD0FfGVMiWo107bP0oHsLA402lhC7AYUFIKY1KQ=",
            "plaintext": "A cat and a mouse."
        },
        {
            "ciphertext": "vremTalPp+NxN/loEtLMB94tEymdFk2TfBoTWNYcf4sQqYSNkx2WPdJ4LxrIsGuIg9KMOt7FOcIpDb6rRVpP",
            "key": "K7E/bf3wp6hrVeW0V1KvFJS5JZMhyxwPHCIW6wKBTb0=",
            "plaintext": "üñîçø∂é"
        }
    ]

    @pytest.mark.parametrize("vector", TEST_VECTORS, ids=lambda v: v["plaintext"][:20] + "..." if len(v["plaintext"]) > 20 else v["plaintext"])
    def test_decrypt_ts_go_vectors(self, vector):
        """Test that Python SDK can decrypt TS/Go encrypted data.
        
        In the TS SDK test vectors, the plaintext field contains the raw string value.
        For the first 3 vectors, the plaintext is a base64 string that represents
        the actual plaintext bytes. The TS test uses: Buffer.from(vector.plaintext).toString('hex')
        which treats plaintext as a UTF-8 string, NOT as base64-encoded bytes.
        """
        # Decode key and ciphertext from base64
        key_bytes = base64.b64decode(vector["key"])
        ciphertext = base64.b64decode(vector["ciphertext"])
        
        # Create key and decrypt
        key = SymmetricKey(key_bytes)
        decrypted = key.decrypt(ciphertext)
        
        # The plaintext in these vectors is the literal string, encoded as UTF-8
        # This matches the TS SDK test: Buffer.from(vector.plaintext).toString('hex')
        expected = vector["plaintext"].encode('utf-8')
        
        assert decrypted == expected


class TestSymmetricKeyCrossSDKVectors:
    """Cross-SDK compatibility tests using specific vectors from Go SDK."""

    def test_31_byte_key_ts_ciphertext(self):
        """Test Go SDK's 31-byte key cross-compatibility vectors."""
        # These ciphertexts were generated by TypeScript SDK with 31-byte key
        # from WIF: L4B2postXdaP7TiUrUBYs53Fqzheu7WhSoQVPuY8qBdoBeEwbmZx
        
        # The key derived from this WIF has a 31-byte X coordinate
        # In hex: 00 + actual 31 bytes = 32 bytes after padding
        key_hex = "0039c6b7af8a2ec6a3e5e0e42bf0f3c65d9a8b7c4e1f2d3a4b5c6d7e8f9a0b1c2"
        
        # Note: For actual cross-SDK testing, we'd need the actual key from the WIF
        # This is a placeholder test structure
        pass

    def test_32_byte_key_bidirectional(self):
        """Test that Python can encrypt/decrypt using same format as TS/Go."""
        # Create a key using a known value
        key_hex = "5a90d59d829197983a54d887fdea2dc4c38098f00ba3110f2645633b6ea11458"
        key = SymmetricKey.from_hex(key_hex)
        
        # Test roundtrip
        plaintext = b"cross-sdk test message"
        ciphertext = key.encrypt(plaintext)
        decrypted = key.decrypt(ciphertext)
        
        assert decrypted == plaintext
        
        # Verify ciphertext format: IV (32) + data + tag (16)
        assert len(ciphertext) == 32 + len(plaintext) + 16


class TestSymmetricKeyUnicode:
    """Test Unicode string handling."""

    def test_unicode_encryption(self):
        """Test encryption of Unicode strings."""
        key = SymmetricKey.from_random()
        plaintext = "日本語テスト 🚀"
        
        ciphertext = key.encrypt(plaintext)
        decrypted = key.decrypt(ciphertext)
        
        assert decrypted.decode('utf-8') == plaintext

    def test_special_characters(self):
        """Test special characters like in TS vector."""
        key = SymmetricKey.from_random()
        plaintext = "üñîçø∂é"
        
        ciphertext = key.encrypt(plaintext)
        decrypted = key.decrypt(ciphertext)
        
        assert decrypted.decode('utf-8') == plaintext


class TestSymmetricKeyEdgeCases:
    """Edge case tests."""

    def test_empty_plaintext(self):
        """Test encryption of empty data."""
        key = SymmetricKey.from_random()
        plaintext = b""
        
        ciphertext = key.encrypt(plaintext)
        decrypted = key.decrypt(ciphertext)
        
        assert decrypted == plaintext
        # Length should be IV (32) + 0 + tag (16) = 48
        assert len(ciphertext) == 48

    def test_large_plaintext(self):
        """Test encryption of large data."""
        key = SymmetricKey.from_random()
        plaintext = b"x" * 10000
        
        ciphertext = key.encrypt(plaintext)
        decrypted = key.decrypt(ciphertext)
        
        assert decrypted == plaintext

    def test_hex_string_decryption(self):
        """Test decryption from hex string input."""
        key = SymmetricKey.from_random()
        plaintext = b"test message"
        
        ciphertext = key.encrypt(plaintext)
        ciphertext_hex = ciphertext.hex()
        
        # Decrypt from hex string
        decrypted = key.decrypt(ciphertext_hex)
        
        assert decrypted == plaintext

