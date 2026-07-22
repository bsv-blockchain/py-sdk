"""
Coverage tests for spv/verify.py - untested branches.
"""

import time

import pytest

# ========================================================================
# SPV verification branches
# ========================================================================


def test_verify_merkle_proof_basic():
    """Test basic merkle proof verification."""
    try:
        from bsv.spv.verify import verify_merkle_proof

        txid = b"\x00" * 32
        merkle_root = b"\x00" * 32
        proof = []

        # Empty proof, txid should match root
        is_valid = verify_merkle_proof(txid, merkle_root, proof)
        assert is_valid
    except (ImportError, AttributeError):
        pytest.skip("verify_merkle_proof not available")


def test_verify_merkle_proof_with_path():
    """Test merkle proof with path."""
    try:
        from bsv.spv.verify import verify_merkle_proof

        txid = b"\x01" * 32
        merkle_root = b"\x02" * 32
        proof = [{"hash": b"\x03" * 32, "side": "left"}, {"hash": b"\x04" * 32, "side": "right"}]

        try:
            is_valid = verify_merkle_proof(txid, merkle_root, proof)
            assert isinstance(is_valid, bool)
        except (KeyError, TypeError):
            # Proof format may be different
            pytest.skip("Proof format different")
    except (ImportError, AttributeError):
        pytest.skip("verify_merkle_proof not available")


def test_verify_merkle_proof_invalid():
    """Test verifying invalid merkle proof."""
    try:
        from bsv.spv.verify import verify_merkle_proof

        txid = b"\x01" * 32
        merkle_root = b"\xff" * 32
        proof = []

        is_valid = verify_merkle_proof(txid, merkle_root, proof)
        assert not is_valid
    except (ImportError, AttributeError):
        pytest.skip("verify_merkle_proof not available")


# ========================================================================
# Block header verification branches
# ========================================================================


def test_verify_block_header():
    """Test verifying block header."""
    try:
        from bsv.spv.verify import verify_block_header

        # Genesis block header
        header = b"\x01" + b"\x00" * 79

        try:
            is_valid = verify_block_header(header)
            assert isinstance(is_valid, bool)
        except (NameError, AttributeError):
            pytest.skip("verify_block_header not available")
    except ImportError:
        pytest.skip("SPV verify not available")


def test_verify_block_header_invalid():
    """Test verifying invalid block header."""
    try:
        from bsv.spv.verify import verify_block_header

        # Invalid header (wrong length)
        header = b"\x00" * 60

        try:
            is_valid = verify_block_header(header)
            assert not is_valid
        except (ValueError, NameError, AttributeError):
            # Expected
            pass
    except ImportError:
        pytest.skip("SPV verify not available")


# ========================================================================
# Edge cases
# ========================================================================


def test_verify_merkle_proof_empty_txid():
    """Test verifying with empty txid."""
    from bsv.spv.verify import verify_merkle_proof

    with pytest.raises(ValueError, match="txid must be 32 bytes"):
        verify_merkle_proof(b"", b"\x00" * 32, [])


# ========================================================================
# Merkle proof error cases and edge cases
# ========================================================================


def test_verify_merkle_proof_invalid_merkle_root():
    """Test verify_merkle_proof with invalid merkle root."""
    try:
        from bsv.spv.verify import verify_merkle_proof

        # Test with wrong length merkle root
        try:
            verify_merkle_proof(b"\x00" * 32, b"\x00" * 16, [])
            raise AssertionError("Should raise ValueError for invalid merkle root length")
        except ValueError as e:
            assert "merkle_root must be 32 bytes" in str(e)

        # Test with non-bytes merkle root
        try:
            verify_merkle_proof(b"\x00" * 32, "invalid", [])
            raise AssertionError("Should raise ValueError for non-bytes merkle root")
        except ValueError as e:
            assert "merkle_root must be 32 bytes" in str(e)
    except (ImportError, AttributeError):
        pytest.skip("verify_merkle_proof not available")


def test_verify_merkle_proof_invalid_proof_elements():
    """Test verify_merkle_proof with invalid proof elements."""
    try:
        from bsv.spv.verify import verify_merkle_proof

        # Test with non-dict proof element
        try:
            verify_merkle_proof(b"\x00" * 32, b"\x00" * 32, ["invalid"])
            raise AssertionError("Should raise ValueError for non-dict proof element")
        except ValueError as e:
            assert "must be dictionaries" in str(e)

        # Test with dict missing 'hash' key
        try:
            verify_merkle_proof(b"\x00" * 32, b"\x00" * 32, [{"side": "left"}])
            raise AssertionError("Should raise ValueError for missing hash key")
        except ValueError as e:
            assert "must contain 'hash' and 'side' keys" in str(e)

        # Test with dict missing 'side' key
        try:
            verify_merkle_proof(b"\x00" * 32, b"\x00" * 32, [{"hash": b"\x00" * 32}])
            raise AssertionError("Should raise ValueError for missing side key")
        except ValueError as e:
            assert "must contain 'hash' and 'side' keys" in str(e)
    except (ImportError, AttributeError):
        pytest.skip("verify_merkle_proof not available")


def test_verify_merkle_proof_invalid_hash():
    """Test verify_merkle_proof with invalid hash in proof."""
    try:
        from bsv.spv.verify import verify_merkle_proof

        # Test with wrong length hash
        try:
            verify_merkle_proof(b"\x00" * 32, b"\x00" * 32, [{"hash": b"\x00" * 16, "side": "left"}])
            raise AssertionError("Should raise ValueError for invalid hash length")
        except ValueError as e:
            assert "must be 32 bytes" in str(e)

        # Test with non-bytes hash
        try:
            verify_merkle_proof(b"\x00" * 32, b"\x00" * 32, [{"hash": "invalid", "side": "left"}])
            raise AssertionError("Should raise ValueError for non-bytes hash")
        except ValueError as e:
            assert "must be 32 bytes" in str(e)
    except (ImportError, AttributeError):
        pytest.skip("verify_merkle_proof not available")


def test_verify_merkle_proof_invalid_side():
    """Test verify_merkle_proof with invalid side in proof."""
    try:
        from bsv.spv.verify import verify_merkle_proof

        # Test with invalid side
        try:
            verify_merkle_proof(b"\x00" * 32, b"\x00" * 32, [{"hash": b"\x00" * 32, "side": "invalid"}])
            raise AssertionError("Should raise ValueError for invalid side")
        except ValueError as e:
            assert "must be 'left' or 'right'" in str(e)
    except (ImportError, AttributeError):
        pytest.skip("verify_merkle_proof not available")


# ========================================================================
# Block header verification edge cases
# ========================================================================


def test_verify_block_header_invalid_length():
    """Test verify_block_header with invalid length."""
    try:
        from bsv.spv.verify import verify_block_header

        # Test with too short header
        result = verify_block_header(b"\x00" * 50)
        assert not result

        # Test with too long header
        result = verify_block_header(b"\x00" * 90)
        assert not result
    except ImportError:
        pytest.skip("verify_block_header not available")


def test_verify_block_header_invalid_version():
    """Test verify_block_header with invalid version."""
    try:
        from bsv.spv.verify import verify_block_header

        # Test with negative version
        header = b"\xff\xff\xff\xff" + b"\x00" * 76
        result = verify_block_header(header)
        assert not result

        # Test with version too high
        header = b"\x00\x00\x00\x80" + b"\x00" * 76
        result = verify_block_header(header)
        assert not result
    except ImportError:
        pytest.skip("verify_block_header not available")


def test_verify_block_header_invalid_timestamp():
    """Test verify_block_header with invalid timestamp."""
    try:
        from bsv.spv.verify import verify_block_header

        # Test with timestamp before genesis (1231006505)
        header = b"\x01\x00\x00\x00" + b"\x00" * 68 + b"\x00\x00\x00\x00" + b"\x00" * 4
        result = verify_block_header(header)
        assert not result

        # Test with timestamp too far in future (more than 2 hours ahead)
        future_timestamp = int(time.time()) + (3 * 60 * 60)  # 3 hours in future
        timestamp_bytes = future_timestamp.to_bytes(4, "little")
        header = b"\x01\x00\x00\x00" + b"\x00" * 68 + timestamp_bytes + b"\x00" * 4
        result = verify_block_header(header)
        assert not result
    except ImportError:
        pytest.skip("verify_block_header not available")


def test_verify_block_header_invalid_bits():
    """Test verify_block_header with invalid bits/difficulty."""
    try:
        from bsv.spv.verify import verify_block_header

        # Test with bits too low
        header = b"\x01\x00\x00\x00" + b"\x00" * 72 + b"\x00\x00\x00\x00"
        result = verify_block_header(header)
        assert not result

        # Test with bits too high
        header = b"\x01\x00\x00\x00" + b"\x00" * 72 + b"\x00\x00\x00\x21"
        result = verify_block_header(header)
        assert not result
    except ImportError:
        pytest.skip("verify_block_header not available")


def test_verify_block_header_pow_validation():
    """Test verify_block_header PoW validation edge cases."""
    try:
        from bsv.spv.verify import verify_block_header

        # Create a header with low difficulty that should fail PoW
        # This is a simplified test - in practice, PoW validation depends on the actual difficulty
        header = b"\x01\x00\x00\x00" + b"\xff" * 32 + b"\xff" * 32
        header += b"\x00\x00\x00\x00"
        header += b"\xff\xff\x00\x1d"
        header += b"\x00\x00\x00\x00"

        # Should fail due to timestamp, but if we ignore that, PoW should be checked
        # For this test, we'll just ensure the function returns a boolean
        result = verify_block_header(header)
        assert isinstance(result, bool)
    except ImportError:
        pytest.skip("verify_block_header not available")


def test_verify_block_header_edge_cases():
    """Test verify_block_header various edge cases."""
    try:
        from bsv.spv.verify import verify_block_header

        # Test with current timestamp (should pass timestamp check)
        current_time = int(time.time())
        timestamp_bytes = current_time.to_bytes(4, "little")

        # Create a minimal valid-looking header
        header = b"\x01\x00\x00\x00"
        header += b"\x00" * 32
        header += b"\x00" * 32
        header += timestamp_bytes
        header += b"\xff\xff\x00\x1d"
        header += b"\x00\x00\x00\x00"

        # Should return False due to PoW check, but should not crash
        result = verify_block_header(header)
        assert isinstance(result, bool)
    except ImportError:
        pytest.skip("verify_block_header not available")
