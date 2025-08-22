import threading
from collections import OrderedDict
from typing import Any, Optional, Tuple
from .key_deriver import KeyDeriver, Protocol, Counterparty
from bsv.keys import PrivateKey, PublicKey

class CachedKeyDeriver:
    """
    Python port of Go's CachedKeyDeriver (go-sdk/wallet/cached_key_deriver.go)
    Caches derived keys using an LRU cache for performance.
    """
    DEFAULT_MAX_CACHE_SIZE = 1000

    def __init__(self, root_key: PrivateKey, max_cache_size: int = 0):
        self.key_deriver = KeyDeriver(root_key)
        self.max_cache_size = max_cache_size if max_cache_size > 0 else self.DEFAULT_MAX_CACHE_SIZE
        self._cache = OrderedDict()  # type: OrderedDict[Tuple, Any]
        self._lock = threading.Lock()

    def _make_cache_key(self, method: str, protocol: Protocol, key_id: str, counterparty: Counterparty, for_self: Optional[bool] = None) -> Tuple:
        # Counterparty and Protocol must be hashable; if not, convert to tuple/dict
        cp_tuple = (counterparty.type, getattr(counterparty, 'counterparty', None))
        proto_tuple = (protocol.security_level, protocol.protocol)
        key = (method, proto_tuple, key_id, cp_tuple, for_self)
        return key

    def _cache_get(self, key: Tuple) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key, last=False)
                return self._cache[key]
            return None

    def _cache_set(self, key: Tuple, value: Any):
        with self._lock:
            if key in self._cache:
                self._cache[key] = value
                self._cache.move_to_end(key, last=False)
            else:
                self._cache[key] = value
                self._cache.move_to_end(key, last=False)
                if len(self._cache) > self.max_cache_size:
                    self._cache.popitem(last=True)

    def derive_public_key(self, protocol: Protocol, key_id: str, counterparty: Counterparty, for_self: bool = False) -> PublicKey:
        key = self._make_cache_key('derive_public_key', protocol, key_id, counterparty, for_self)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        pub_key = self.key_deriver.derive_public_key(protocol, key_id, counterparty, for_self)
        self._cache_set(key, pub_key)
        return pub_key

    def derive_private_key(self, protocol: Protocol, key_id: str, counterparty: Counterparty) -> PrivateKey:
        key = self._make_cache_key('derive_private_key', protocol, key_id, counterparty)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        priv_key = self.key_deriver.derive_private_key(protocol, key_id, counterparty)
        self._cache_set(key, priv_key)
        return priv_key

    def derive_symmetric_key(self, protocol: Protocol, key_id: str, counterparty: Counterparty) -> bytes:
        key = self._make_cache_key('derive_symmetric_key', protocol, key_id, counterparty)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        sym_key = self.key_deriver.derive_symmetric_key(protocol, key_id, counterparty)
        self._cache_set(key, sym_key)
        return sym_key

    def reveal_specific_secret(self, counterparty: Counterparty, protocol: Protocol, key_id: str) -> Optional[bytes]:
        # NOTE: This method is a placeholder. The underlying KeyDeriver does not implement this in Python yet.
        # TODO: Implement reveal_specific_secret in KeyDeriver and here.
        key = self._make_cache_key('reveal_specific_secret', protocol, key_id, counterparty)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        # TODO: Call self.key_deriver.reveal_specific_secret when implemented
        # secret = self.key_deriver.reveal_specific_secret(counterparty, protocol, key_id)
        # self._cache_set(key, secret)
        # return secret
        raise NotImplementedError('reveal_specific_secret is not implemented in KeyDeriver')
