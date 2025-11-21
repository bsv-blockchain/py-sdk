"""
Comprehensive tests for bsv/wallet/cached_key_deriver.py

Tests the CachedKeyDeriver class including caching functionality and key derivation.
"""

import pytest
import threading
from unittest.mock import Mock, MagicMock, patch
from bsv.wallet.cached_key_deriver import CachedKeyDeriver
from bsv.wallet.key_deriver import Protocol, Counterparty
from bsv.keys import PrivateKey, PublicKey


class TestCachedKeyDeriverInit:
    """Test CachedKeyDeriver initialization."""
    
    def test_init_with_default_cache_size(self):
        """Test initialization with default cache size."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        assert deriver.max_cache_size == CachedKeyDeriver.DEFAULT_MAX_CACHE_SIZE
        assert deriver.max_cache_size == 1000
        assert len(deriver._cache) == 0
    
    def test_init_with_custom_cache_size(self):
        """Test initialization with custom cache size."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key, max_cache_size=500)
        
        assert deriver.max_cache_size == 500
    
    def test_init_with_zero_cache_size_uses_default(self):
        """Test that zero cache size falls back to default."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key, max_cache_size=0)
        
        assert deriver.max_cache_size == CachedKeyDeriver.DEFAULT_MAX_CACHE_SIZE
    
    def test_init_with_negative_cache_size_uses_default(self):
        """Test that negative cache size falls back to default."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key, max_cache_size=-10)
        
        assert deriver.max_cache_size == CachedKeyDeriver.DEFAULT_MAX_CACHE_SIZE
    
    def test_init_creates_key_deriver(self):
        """Test that initialization creates underlying KeyDeriver."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        assert deriver.key_deriver is not None
        from bsv.wallet.key_deriver import KeyDeriver
        assert isinstance(deriver.key_deriver, KeyDeriver)


class TestMakeCacheKey:
    """Test _make_cache_key method."""
    
    def test_make_cache_key_basic(self):
        """Test creating cache key with basic parameters."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        key = deriver._make_cache_key("method", protocol, "key_id", counterparty)
        
        assert isinstance(key, tuple)
        assert len(key) == 5
        assert key[0] == "method"
        assert key[2] == "key_id"
    
    def test_make_cache_key_with_for_self(self):
        """Test creating cache key with for_self parameter."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        key1 = deriver._make_cache_key("method", protocol, "key_id", counterparty, True)
        key2 = deriver._make_cache_key("method", protocol, "key_id", counterparty, False)
        
        assert key1 != key2
        assert key1[4] is True
        assert key2[4] is False
    
    def test_make_cache_key_different_methods(self):
        """Test that different methods produce different keys."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        key1 = deriver._make_cache_key("method1", protocol, "key_id", counterparty)
        key2 = deriver._make_cache_key("method2", protocol, "key_id", counterparty)
        
        assert key1 != key2
    
    def test_make_cache_key_different_protocols(self):
        """Test that different protocols produce different keys."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol1 = Protocol(security_level=1, protocol="test1")
        protocol2 = Protocol(security_level=2, protocol="test2")
        counterparty = Counterparty(type=1)
        
        key1 = deriver._make_cache_key("method", protocol1, "key_id", counterparty)
        key2 = deriver._make_cache_key("method", protocol2, "key_id", counterparty)
        
        assert key1 != key2
    
    def test_make_cache_key_different_counterparties(self):
        """Test that different counterparties produce different keys."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty1 = Counterparty(type=1)
        counterparty2 = Counterparty(type=2)
        
        key1 = deriver._make_cache_key("method", protocol, "key_id", counterparty1)
        key2 = deriver._make_cache_key("method", protocol, "key_id", counterparty2)
        
        assert key1 != key2


class TestCacheGetSet:
    """Test _cache_get and _cache_set methods."""
    
    def test_cache_miss(self):
        """Test cache miss returns None."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        result = deriver._cache_get(("test", "key"))
        
        assert result is None
    
    def test_cache_hit(self):
        """Test cache hit returns cached value."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        key = ("test", "key")
        value = "cached_value"
        
        deriver._cache_set(key, value)
        result = deriver._cache_get(key)
        
        assert result == value
    
    def test_cache_set_and_get_roundtrip(self):
        """Test setting and getting cache values."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        key1 = ("method1", "key1")
        key2 = ("method2", "key2")
        value1 = "value1"
        value2 = "value2"
        
        deriver._cache_set(key1, value1)
        deriver._cache_set(key2, value2)
        
        assert deriver._cache_get(key1) == value1
        assert deriver._cache_get(key2) == value2
    
    def test_cache_update_existing_key(self):
        """Test updating existing cache key."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        key = ("test", "key")
        value1 = "value1"
        value2 = "value2"
        
        deriver._cache_set(key, value1)
        deriver._cache_set(key, value2)
        
        assert deriver._cache_get(key) == value2
    
    def test_cache_eviction_when_full(self):
        """Test that cache evicts oldest entry when full."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key, max_cache_size=2)
        
        key1 = ("method", "key1")
        key2 = ("method", "key2")
        key3 = ("method", "key3")
        
        deriver._cache_set(key1, "value1")
        deriver._cache_set(key2, "value2")
        deriver._cache_set(key3, "value3")  # Should evict key1
        
        assert deriver._cache_get(key1) is None
        assert deriver._cache_get(key2) == "value2"
        assert deriver._cache_get(key3) == "value3"
    
    def test_cache_lru_behavior(self):
        """Test LRU behavior: accessed items are moved to front."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key, max_cache_size=2)
        
        key1 = ("method", "key1")
        key2 = ("method", "key2")
        key3 = ("method", "key3")
        
        deriver._cache_set(key1, "value1")
        deriver._cache_set(key2, "value2")
        
        # Access key1 to move it to front
        _ = deriver._cache_get(key1)
        
        # Add key3, should evict key2 (least recently used)
        deriver._cache_set(key3, "value3")
        
        assert deriver._cache_get(key1) == "value1"
        assert deriver._cache_get(key2) is None
        assert deriver._cache_get(key3) == "value3"
    
    def test_cache_size_limit(self):
        """Test that cache respects size limit."""
        root_key = PrivateKey()
        max_size = 10
        deriver = CachedKeyDeriver(root_key, max_cache_size=max_size)
        
        # Add more items than max size
        for i in range(max_size + 5):
            deriver._cache_set(("method", f"key{i}"), f"value{i}")
        
        assert len(deriver._cache) == max_size


class TestDerivePublicKey:
    """Test derive_public_key method."""
    
    def test_derive_public_key_first_call(self):
        """Test deriving public key on first call (cache miss)."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        pub_key = deriver.derive_public_key(protocol, "key_id", counterparty)
        
        assert isinstance(pub_key, PublicKey)
    
    def test_derive_public_key_cached(self):
        """Test that second call uses cached value."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        # First call
        pub_key1 = deriver.derive_public_key(protocol, "key_id", counterparty)
        
        # Second call should return same instance from cache
        pub_key2 = deriver.derive_public_key(protocol, "key_id", counterparty)
        
        assert pub_key1 is pub_key2
    
    def test_derive_public_key_for_self_cached_separately(self):
        """Test that for_self creates separate cache entry."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        pub_key1 = deriver.derive_public_key(protocol, "key_id", counterparty, for_self=True)
        pub_key2 = deriver.derive_public_key(protocol, "key_id", counterparty, for_self=False)
        
        # Should be different because for_self differs
        assert pub_key1 is not pub_key2


class TestDerivePrivateKey:
    """Test derive_private_key method."""
    
    def test_derive_private_key_first_call(self):
        """Test deriving private key on first call (cache miss)."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        priv_key = deriver.derive_private_key(protocol, "key_id", counterparty)
        
        assert isinstance(priv_key, PrivateKey)
    
    def test_derive_private_key_cached(self):
        """Test that second call uses cached value."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        # First call
        priv_key1 = deriver.derive_private_key(protocol, "key_id", counterparty)
        
        # Second call should return same instance from cache
        priv_key2 = deriver.derive_private_key(protocol, "key_id", counterparty)
        
        assert priv_key1 is priv_key2
    
    def test_derive_private_key_different_key_ids(self):
        """Test that different key IDs produce different keys."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        priv_key1 = deriver.derive_private_key(protocol, "key_id_1", counterparty)
        priv_key2 = deriver.derive_private_key(protocol, "key_id_2", counterparty)
        
        assert priv_key1 is not priv_key2


class TestDeriveSymmetricKey:
    """Test derive_symmetric_key method."""
    
    def test_derive_symmetric_key_first_call(self):
        """Test deriving symmetric key on first call (cache miss)."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        sym_key = deriver.derive_symmetric_key(protocol, "key_id", counterparty)
        
        assert isinstance(sym_key, bytes)
        assert len(sym_key) > 0
    
    def test_derive_symmetric_key_cached(self):
        """Test that second call uses cached value."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        # First call
        sym_key1 = deriver.derive_symmetric_key(protocol, "key_id", counterparty)
        
        # Second call should return same value from cache
        sym_key2 = deriver.derive_symmetric_key(protocol, "key_id", counterparty)
        
        assert sym_key1 is sym_key2
        assert sym_key1 == sym_key2
    
    def test_derive_symmetric_key_different_protocols(self):
        """Test that different protocols produce different keys."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol1 = Protocol(security_level=1, protocol="test1")
        protocol2 = Protocol(security_level=2, protocol="test2")
        counterparty = Counterparty(type=1)
        
        sym_key1 = deriver.derive_symmetric_key(protocol1, "key_id", counterparty)
        sym_key2 = deriver.derive_symmetric_key(protocol2, "key_id", counterparty)
        
        assert sym_key1 != sym_key2


class TestRevealSpecificSecret:
    """Test reveal_specific_secret method."""
    
    def test_reveal_specific_secret_not_implemented(self):
        """Test that reveal_specific_secret raises NotImplementedError."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        with pytest.raises(NotImplementedError, match="reveal_specific_secret is not implemented"):
            deriver.reveal_specific_secret(counterparty, protocol, "key_id")


class TestCacheThreadSafety:
    """Test thread safety of cache operations."""
    
    def test_concurrent_cache_access(self):
        """Test that concurrent cache access is thread-safe."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key, max_cache_size=100)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        results = []
        errors = []
        
        def derive_keys(thread_id):
            try:
                for i in range(10):
                    key_id = f"key_{thread_id}_{i}"
                    pub_key = deriver.derive_public_key(protocol, key_id, counterparty)
                    results.append((thread_id, i, pub_key))
            except Exception as e:
                errors.append(e)
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=derive_keys, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert len(results) == 50  # 5 threads * 10 keys
    
    def test_concurrent_cache_eviction(self):
        """Test that concurrent cache eviction doesn't cause errors."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key, max_cache_size=20)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        errors = []
        
        def add_many_keys(thread_id):
            try:
                for i in range(30):  # More than cache size
                    key_id = f"key_{thread_id}_{i}"
                    deriver.derive_symmetric_key(protocol, key_id, counterparty)
            except Exception as e:
                errors.append(e)
        
        threads = []
        for i in range(3):
            t = threading.Thread(target=add_many_keys, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert len(deriver._cache) <= deriver.max_cache_size


class TestCacheEfficiency:
    """Test cache efficiency and performance characteristics."""
    
    def test_cache_hit_efficiency(self):
        """Test that cache hits don't call underlying deriver."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        # Mock the underlying deriver to count calls
        with patch.object(deriver.key_deriver, 'derive_public_key', wraps=deriver.key_deriver.derive_public_key) as mock_derive:
            # First call - cache miss
            pub_key1 = deriver.derive_public_key(protocol, "key_id", counterparty)
            assert mock_derive.call_count == 1
            
            # Second call - cache hit
            pub_key2 = deriver.derive_public_key(protocol, "key_id", counterparty)
            assert mock_derive.call_count == 1  # Still 1, not called again
            
            assert pub_key1 is pub_key2
    
    def test_multiple_key_derivations_cache_efficiency(self):
        """Test cache efficiency with multiple different keys."""
        root_key = PrivateKey()
        deriver = CachedKeyDeriver(root_key)
        
        protocol = Protocol(security_level=2, protocol="test")
        counterparty = Counterparty(type=1)
        
        with patch.object(deriver.key_deriver, 'derive_private_key', wraps=deriver.key_deriver.derive_private_key) as mock_derive:
            # Derive 5 different keys
            for i in range(5):
                deriver.derive_private_key(protocol, f"key_{i}", counterparty)
            assert mock_derive.call_count == 5
            
            # Access the same 5 keys again - should all be cached
            for i in range(5):
                deriver.derive_private_key(protocol, f"key_{i}", counterparty)
            assert mock_derive.call_count == 5  # Still 5, no new calls

