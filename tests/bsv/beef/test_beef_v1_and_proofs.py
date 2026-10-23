"""V1 BEEF parsing/serialization and fail-closed proof checks (TS SDK Beef.ts parity)."""

import asyncio

import pytest

from bsv.merkle_path import MerklePath
from bsv.script.script import Script
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
from bsv.transaction.beef import ATOMIC_BEEF, BEEF_V1, BEEF_V2, Beef, BeefTx, new_beef_from_bytes

HEIGHT = 800_000
SIBLING = "11" * 32


class Tracker:
    def __init__(self, ok: bool):
        self.ok = ok
        self.calls = []

    async def is_valid_root_for_height(self, root, height):
        self.calls.append((height, root))
        return self.ok


def _pair(txid_flag: bool = True):
    """A proven parent and an unproven child spending it."""
    parent = Transaction()
    parent.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    leaf = {"offset": 0, "hash_str": parent.txid()}
    if txid_flag:
        leaf["txid"] = True
    parent.merkle_path = MerklePath(HEIGHT, [[leaf, {"offset": 1, "hash_str": SIBLING}]])
    child = Transaction()
    child.inputs = [
        TransactionInput(
            source_transaction=parent, source_txid=parent.txid(), source_output_index=0, unlocking_script=Script()
        )
    ]
    child.outputs = [TransactionOutput(Script(b"\x51"), 900)]
    return parent, child


def _verify(beef, ok):
    tracker = Tracker(ok)
    return asyncio.run(beef.verify(tracker)), tracker


def _v2(child):
    beef = Beef(version=BEEF_V2)
    beef.merge_transaction(child)
    return beef


def test_v1_parse_keeps_all_txs_and_bumps():
    parent, child = _pair()
    beef = new_beef_from_bytes(child.to_beef())
    assert beef.version == BEEF_V1
    assert list(beef.txs) == [parent.txid(), child.txid()]
    assert len(beef.bumps) == 1
    assert beef.txs[parent.txid()].bump_index == 0
    assert beef.txs[child.txid()].tx_obj.inputs[0].source_transaction is beef.txs[parent.txid()].tx_obj


@pytest.mark.parametrize("atomic", [False, True])
def test_v1_verify_consults_chain_tracker(atomic):
    parent, child = _pair()
    data = child.to_beef()
    if atomic:
        data = ATOMIC_BEEF.to_bytes(4, "little") + bytes.fromhex(child.txid())[::-1] + data
    root = parent.merkle_path.compute_root()

    ok, tracker = _verify(new_beef_from_bytes(data), False)
    assert ok is False
    assert tracker.calls == [(HEIGHT, root)]
    assert _verify(new_beef_from_bytes(data), True)[0] is True


def test_entry_without_tx_data_is_not_valid():
    beef = Beef(version=BEEF_V2)
    txid = "aa" * 32
    beef.txs[txid] = BeefTx(txid=txid)
    assert beef.verify_valid() == (False, {})
