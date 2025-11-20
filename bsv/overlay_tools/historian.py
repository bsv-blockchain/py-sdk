"""
Historian implementation for building transaction history.

Translated from ts-sdk/src/overlay-tools/Historian.ts
"""
from typing import TypeVar, Callable, Optional, Dict, List, Any
from bsv.transaction import Transaction

T = TypeVar('T')
C = TypeVar('C')


class Historian:
    """
    Historian builds a chronological history by traversing transaction ancestry.
    
    Provides functionality to build history of typed values by traversing
    a transaction's input ancestry and interpreting each output.
    """

    def __init__(
        self,
        interpreter: Callable[[Transaction, int, Optional[C]], T | None],
        options: Optional[Dict[str, Any]] = None
    ):
        """
        Create a new Historian instance.
        
        Args:
            interpreter: Function to interpret transaction outputs into typed values
            options: Configuration options
                - debug: Enable debug logging (default: False)
                - historyCache: Optional cache for complete history results
                - interpreterVersion: Version identifier for cache invalidation (default: 'v1')
                - ctxKeyFn: Custom function to serialize context for cache keys
        """
        if interpreter is None:
            raise ValueError("interpreter is required")
        self.interpreter = interpreter
        self.debug = (options or {}).get('debug', False)
        self.history_cache = (options or {}).get('historyCache')
        self.interpreter_version = (options or {}).get('interpreterVersion', 'v1')
        ctx_key_fn = (options or {}).get('ctxKeyFn')
        if ctx_key_fn:
            self.ctx_key_fn = ctx_key_fn
        else:
            import json
            self.ctx_key_fn = lambda ctx: json.dumps(ctx) if ctx else ''

    def _history_key(self, start_transaction: Transaction, context: Optional[C] = None) -> str:
        """Generate cache key for history."""
        txid = start_transaction.txid()
        ctx_key = self.ctx_key_fn(context)
        return f"{self.interpreter_version}|{txid}|{ctx_key}"

    def build_history(
        self,
        start_transaction: Transaction,
        context: Optional[C] = None
    ) -> List[T]:
        """
        Build chronological history by traversing transaction ancestry.
        
        Args:
            start_transaction: The transaction to start history from
            context: Optional context for interpreter
            
        Returns:
            List of interpreted values in chronological order (oldest first)
        """
        # Check cache first
        cached = self._get_cached_history(start_transaction, context)
        if cached is not None:
            return cached
        
        # Build history by traversing transaction tree
        history = self._traverse_transaction_tree(start_transaction, context)
        history.reverse()  # Reverse to get chronological order (oldest first)
        
        # Cache and return result
        self._store_cached_history(start_transaction, context, history)
        return history
    
    def _get_cached_history(self, start_transaction: Transaction, context: Optional[C]) -> Optional[List[T]]:
        """Retrieve cached history if available."""
        if not self.history_cache:
            return None
        
        cache_key = self._history_key(start_transaction, context)
        cached = self.history_cache.get(cache_key)
        if cached is not None:
            return list(cached)  # Return copy
        return None
    
    def _store_cached_history(self, start_transaction: Transaction, context: Optional[C], history: List[T]):
        """Store history in cache if caching is enabled."""
        if self.history_cache:
            cache_key = self._history_key(start_transaction, context)
            self.history_cache[cache_key] = tuple(history)  # Store immutable copy
    
    def _traverse_transaction_tree(self, start_transaction: Transaction, context: Optional[C]) -> List[T]:
        """Traverse transaction ancestry and collect interpreted outputs."""
        visited = set()
        history = []
        
        def traverse(tx: Transaction):
            txid = tx.txid()
            if txid in visited:
                return
            visited.add(txid)
            
            # Interpret outputs and add to history
            self._interpret_outputs(tx, context, history)
            
            # Recursively traverse parent transactions
            for input_tx in tx.inputs:
                if hasattr(input_tx, 'source_transaction') and input_tx.source_transaction:
                    traverse(input_tx.source_transaction)
        
        traverse(start_transaction)
        return history
    
    def _interpret_outputs(self, tx: Transaction, context: Optional[C], history: List[T]):
        """Interpret transaction outputs and append results to history."""
        for i, output in enumerate(tx.outputs):
            try:
                result = self.interpreter(tx, i, context)
                if result is not None:
                    history.append(result)
            except Exception as e:
                if self.debug:
                    print(f"[Historian] Error interpreting output {i} in {tx.txid()}: {e}")

