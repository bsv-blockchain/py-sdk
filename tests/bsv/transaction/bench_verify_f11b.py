"""F11b verify() benchmark — measures wall-clock time for N-input P2PKH verify.

Runs 1/10/100/1000-input transactions with native and pure-Python VM.
"""

import asyncio
import time
from unittest.mock import patch

from bsv.constants import SIGHASH
from bsv.keys import PrivateKey
from bsv.script.type import P2PKH
from bsv.spv import GullibleHeadersClient
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput


def _make_source(priv_key, n):
    addr = priv_key.address()
    return Transaction(
        tx_inputs=[],
        tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=100_000) for _ in range(n)],
    )


def _make_tx(priv_key, n):
    source = _make_source(priv_key, n)
    addr = priv_key.address()
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=source,
                source_output_index=i,
                unlocking_script_template=P2PKH().unlock(priv_key),
                sighash=SIGHASH.ALL_FORKID,
            )
            for i in range(n)
        ],
        tx_outputs=[TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=n * 100_000 - 1000)],
    )
    tx.sign()
    return tx


async def bench_verify(tx, label, runs=3):
    ct = GullibleHeadersClient()
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        result = await tx.verify(ct, scripts_only=True)
        elapsed = time.perf_counter() - t0
        assert result is True
        times.append(elapsed)
    avg = sum(times) / len(times)
    best = min(times)
    print(f"  {label}: avg={avg*1000:.1f}ms  best={best*1000:.1f}ms  ({runs} runs)")
    return avg


async def main():
    priv_key = PrivateKey()
    sizes = [1, 10, 100, 1000]

    print("Building transactions...")
    txs = {}
    for n in sizes:
        t0 = time.perf_counter()
        txs[n] = _make_tx(priv_key, n)
        elapsed = time.perf_counter() - t0
        print(f"  {n}-input tx built+signed in {elapsed*1000:.1f}ms")

    print("\n=== Native VM verify ===")
    native_times = {}
    for n in sizes:
        native_times[n] = await bench_verify(txs[n], f"N={n:>4}", runs=5 if n <= 100 else 3)

    print("\n=== Pure-Python VM verify ===")
    python_times = {}
    with patch("bsv.script.spend._USE_NATIVE_VM", False):
        for n in sizes:
            python_times[n] = await bench_verify(txs[n], f"N={n:>4}", runs=5 if n <= 100 else 1)

    print("\n=== Scaling analysis ===")
    if native_times[1] > 0:
        for n in sizes:
            ratio = native_times[n] / native_times[1]
            print(f"  native  N={n:>4}: {ratio:.1f}x vs N=1")
    if python_times[1] > 0:
        for n in sizes:
            ratio = python_times[n] / python_times[1]
            print(f"  python  N={n:>4}: {ratio:.1f}x vs N=1")

    print("\n=== Native vs Python speedup ===")
    for n in sizes:
        if native_times[n] > 0:
            speedup = python_times[n] / native_times[n]
            print(f"  N={n:>4}: {speedup:.1f}x")


if __name__ == "__main__":
    asyncio.run(main())
