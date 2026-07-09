"""Tests for txid() caching in Transaction."""

import time

from bsv.hash import hash256
from bsv.script.script import Script
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput

# A real mainnet coinbase tx hex for realistic benchmarking
SAMPLE_TX_HEX = (
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a"
    "2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781"
    "e62294721166bf621e73a82cbf2342c858eeac00000000"
)


def _build_chain(depth: int) -> Transaction:
    """Build a linked chain of depth transactions (simulating a BEEF ancestor chain)."""
    prev_tx = Transaction.from_hex(SAMPLE_TX_HEX)
    for _ in range(depth):
        inp = TransactionInput(
            source_transaction=prev_tx,
            source_txid=prev_tx.txid(),
            source_output_index=0,
            unlocking_script=Script(b"\x00" * 20),
            sequence=0xFFFFFFFF,
        )
        out = TransactionOutput(
            locking_script=Script(b"\x76\xa9" + b"\x00" * 20 + b"\x88\xac"),
            satoshis=1,
        )
        tx = Transaction(tx_inputs=[inp], tx_outputs=[out])
        prev_tx = tx
    return prev_tx


def _walk_chain_txids(tip: Transaction) -> list[str]:
    """Walk the chain calling txid() on each tx (simulates BEEF operations)."""
    txids = []
    current = tip
    while current is not None:
        txids.append(current.txid())
        if current.inputs:
            current = current.inputs[0].source_transaction
        else:
            break
    return txids


class TestTxidCache:
    def test_txid_returns_correct_value(self):
        tx = Transaction.from_hex(SAMPLE_TX_HEX)
        expected = hash256(tx.serialize())[::-1].hex()
        assert tx.txid() == expected

    def test_txid_cached_same_result(self):
        tx = Transaction.from_hex(SAMPLE_TX_HEX)
        first = tx.txid()
        second = tx.txid()
        assert first == second

    def test_hash_cached_same_result(self):
        tx = Transaction.from_hex(SAMPLE_TX_HEX)
        first = tx.hash()
        second = tx.hash()
        assert first == second
        assert first is second  # same object from cache

    def test_cache_invalidated_on_add_input(self):
        tx = Transaction.from_hex(SAMPLE_TX_HEX)
        txid_before = tx.txid()
        inp = TransactionInput(
            source_txid="00" * 32,
            source_output_index=0,
            unlocking_script=Script(b"\x00"),
            sequence=0xFFFFFFFF,
        )
        tx.add_input(inp)
        txid_after = tx.txid()
        assert txid_before != txid_after

    def test_cache_invalidated_on_add_output(self):
        tx = Transaction.from_hex(SAMPLE_TX_HEX)
        txid_before = tx.txid()
        out = TransactionOutput(locking_script=Script(b"\x00"), satoshis=1)
        tx.add_output(out)
        txid_after = tx.txid()
        assert txid_before != txid_after

    def test_from_reader_no_stale_cache(self):
        tx = Transaction.from_hex(SAMPLE_TX_HEX)
        assert tx._cached_txid is None
        first = tx.txid()
        assert tx._cached_txid is not None
        assert tx.txid() == first

    def test_multiple_txid_calls_return_same_object(self):
        """Cached txid string should be the exact same object (identity check)."""
        tx = Transaction.from_hex(SAMPLE_TX_HEX)
        first = tx.txid()
        second = tx.txid()
        assert first is second


class TestTxidCacheBenchmark:
    """Benchmark: measure wall-clock time for repeated txid() calls."""

    CHAIN_DEPTH = 100
    WALK_ITERATIONS = 5

    def test_benchmark_chain_walk(self):
        tip = _build_chain(self.CHAIN_DEPTH)

        # Warm-up: first walk populates cache
        txids_first = _walk_chain_txids(tip)

        # Measure subsequent walks (should hit cache)
        start = time.perf_counter()
        for _ in range(self.WALK_ITERATIONS):
            txids = _walk_chain_txids(tip)
        cached_time = time.perf_counter() - start

        assert len(txids) == self.CHAIN_DEPTH + 1
        assert txids == txids_first

        # Measure uncached: invalidate all caches and re-walk
        current = tip
        while current is not None:
            current._cached_hash = None
            current._cached_txid = None
            if current.inputs:
                current = current.inputs[0].source_transaction
            else:
                break

        start = time.perf_counter()
        for _ in range(self.WALK_ITERATIONS):
            # Invalidate before each walk to simulate no-cache
            current = tip
            while current is not None:
                current._cached_hash = None
                current._cached_txid = None
                if current.inputs:
                    current = current.inputs[0].source_transaction
                else:
                    break
            _walk_chain_txids(tip)
        uncached_time = time.perf_counter() - start

        speedup = uncached_time / cached_time if cached_time > 0 else float("inf")

        print(f"\n{'=' * 60}")
        print(f"  txid() cache benchmark (depth={self.CHAIN_DEPTH}, walks={self.WALK_ITERATIONS})")
        print(f"  Cached:   {cached_time * 1000:.2f} ms")
        print(f"  Uncached: {uncached_time * 1000:.2f} ms")
        print(f"  Speedup:  {speedup:.1f}x")
        print(f"{'=' * 60}")

        assert speedup > 2.0, f"Expected >2x speedup, got {speedup:.1f}x"

    def test_benchmark_single_tx_repeated_calls(self):
        """Simulate the pattern in to_beef_nft: same tx's txid() called multiple times."""
        tx = Transaction.from_hex(SAMPLE_TX_HEX)
        n_calls = 1000

        # Cached
        tx.txid()  # warm up
        start = time.perf_counter()
        for _ in range(n_calls):
            tx.txid()
        cached_time = time.perf_counter() - start

        # Uncached
        start = time.perf_counter()
        for _ in range(n_calls):
            tx._cached_hash = None
            tx._cached_txid = None
            tx.txid()
        uncached_time = time.perf_counter() - start

        speedup = uncached_time / cached_time if cached_time > 0 else float("inf")

        print(f"\n{'=' * 60}")
        print(f"  Single tx repeated txid() ({n_calls} calls)")
        print(f"  Cached:   {cached_time * 1000:.2f} ms")
        print(f"  Uncached: {uncached_time * 1000:.2f} ms")
        print(f"  Speedup:  {speedup:.1f}x")
        print(f"{'=' * 60}")

        assert speedup > 5.0, f"Expected >5x speedup, got {speedup:.1f}x"
