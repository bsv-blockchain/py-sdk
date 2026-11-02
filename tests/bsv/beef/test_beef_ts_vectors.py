"""BEEF V1 / V2 / Atomic and MerklePath bytes shared with the TS SDK (ts_sdk_vectors.json)."""

import asyncio
import json
from pathlib import Path

import pytest

from bsv.beef import build_beef_v2_from_raw_hexes
from bsv.merkle_path import MerklePath
from bsv.script.script import Script
from bsv.transaction import Beef, Transaction, TransactionInput, TransactionOutput
from bsv.utils import Reader

VECTORS = json.loads((Path(__file__).parent / "ts_sdk_vectors.json").read_text())
MP = VECTORS["merkle_path"]
V = VECTORS["beef"]


def _graph():
    """The TS vector graph: A (mined) -> B, C -> D, with A a shared ancestor of D."""

    def out(sats):
        return TransactionOutput(Script("51"), sats)

    def spend(src, vout):
        return TransactionInput(
            source_transaction=src, source_txid=src.txid(), source_output_index=vout, unlocking_script=Script("00")
        )

    a = Transaction([TransactionInput(source_txid="99" * 32, unlocking_script=Script("00"))], [out(1000), out(2000)])
    a.merkle_path = MerklePath(
        800000,
        [
            [{"offset": 2, "hash_str": a.txid(), "txid": True}, {"offset": 3, "hash_str": "33" * 32}],
            [{"offset": 0, "hash_str": "44" * 32}],
        ],
    )
    b = Transaction([spend(a, 0)], [out(900)])
    c = Transaction([spend(a, 1)], [out(1900)])
    d = Transaction([spend(b, 0), spend(c, 0)], [out(2700)])
    assert [t.txid() for t in (a, b, c, d)] == [V["ids"][k] for k in "ABCD"]
    return a, b, c, d


class _Tracker:
    def __init__(self, accept):
        self.accept = accept

    async def is_valid_root_for_height(self, root, height):
        return self.accept and (height, root) == (800000, V["root"])

    async def current_height(self):
        return 900000


@pytest.mark.parametrize("name", ["single_tx_block", "level0_compound_3", "level0_compound_5"])
def test_merkle_path_roots_match_ts(name):
    mp = MerklePath.from_hex(MP[name]["hex"])
    assert mp.to_hex() == MP[name]["hex"]
    assert [mp.compute_root(leaf["hash_str"]) for leaf in mp.path[0]] == MP[name]["roots"]


def test_bump_with_computed_leaves_reads_inside_beef():
    """add_computed_leaves() output is rejected by the strict reader but read for BEEF (TS)."""
    case = MP["computed_leaves_bump"]
    with pytest.raises(ValueError, match="Invalid offset"):
        MerklePath.from_hex(case["hex"])
    mp = MerklePath.from_reader(Reader(bytes.fromhex(case["hex"])), legal_offsets_only=False)
    assert mp.compute_root("11" * 32) == case["root"]


def test_transaction_to_beef_and_atomic_match_ts():
    """to_beef() writes the shared ancestor once, in the TS order."""
    *_, d = _graph()
    assert d.to_beef().hex() == V["v1_D"]
    assert d.to_atomic_beef().hex() == V["atomic_D"]


def test_beef_merge_and_serialize_match_ts():
    *_, d = _graph()
    beef = Beef()
    beef.merge_transaction(d)
    assert beef.to_hex() == V["v2_D"]
    assert list(beef.txs) == V["v2_D_order"]
    assert beef.to_binary_atomic(V["ids"]["B"]).hex() == V["atomic_B"]


def test_beef_round_trips_ts_bytes():
    for key in ("v1_D", "v2_D", "v2_txid_only"):
        assert Beef.from_string(V[key]).to_hex() == V[key]
    atomic = Beef.from_binary(bytes.fromhex(V["atomic_B"]))
    assert atomic.atomic_txid == V["ids"]["B"]
    assert atomic.to_binary_atomic(V["ids"]["B"]).hex() == V["atomic_B"]


def test_beef_with_txid_only_matches_ts():
    _, b, _, _ = _graph()
    beef = Beef()
    beef.merge_transaction(b)
    beef.make_txid_only(V["ids"]["A"])
    assert beef.to_hex() == V["v2_txid_only"]
    assert beef.is_valid(allow_txid_only=True) is V["v2_txid_only_valid"]
    assert not beef.is_valid()


@pytest.mark.parametrize("key", ["v1_D", "v2_D", "atomic_D"])
def test_from_beef_links_the_proof_tree(key):
    tx = Transaction.from_beef(V[key])
    assert tx.txid() == V["ids"]["D"]
    b, c = (i.source_transaction for i in tx.inputs)
    assert (b.txid(), c.txid()) == (V["ids"]["B"], V["ids"]["C"])
    assert b.inputs[0].source_transaction.merkle_path.compute_root(V["ids"]["A"]) == V["root"]


def test_from_beef_selects_transactions_like_ts():
    assert Transaction.from_beef(V["v2_D"]).txid() == V["from_v2_last"]
    assert Transaction.from_beef(V["v2_D"], V["ids"]["B"]).txid() == V["from_v2_B"]
    assert Transaction.from_atomic_beef(V["atomic_B"]).txid() == V["from_atomic_B"]
    with pytest.raises(ValueError, match="not found"):
        Transaction.from_beef(V["v2_D"], "77" * 32)
    with pytest.raises(ValueError, match="BRC-95"):
        Transaction.from_atomic_beef(V["v2_D"])


def test_from_beef_leaves_missing_sources_unset():
    """A partial BEEF parses; the missing source transaction stays None (TS) instead of KeyError."""
    *_, d = _graph()
    d.inputs[1].source_transaction = None
    with pytest.raises(ValueError, match="missing"):
        d.to_beef()
    tx = Transaction.from_beef(d.to_beef(allow_partial=True))
    assert tx.inputs[0].source_transaction is not None
    assert tx.inputs[1].source_transaction is None


@pytest.mark.parametrize("key", ["v1_D", "v2_D", "atomic_D", "atomic_B"])
def test_ts_beef_verifies_only_against_its_root(key):
    beef = Beef.from_string(V[key])
    assert asyncio.run(beef.verify(_Tracker(accept=True)))
    assert not asyncio.run(beef.verify(_Tracker(accept=False)))


def test_merge_beef_accepts_bytes_and_keeps_existing_entries():
    beef = Beef.from_string(V["v2_txid_only"])
    beef.merge_beef(bytes.fromhex(V["v2_D"]))
    assert beef.find_transaction(V["ids"]["A"]).tx_obj is not None  # TxIDOnly filled
    assert beef.is_valid()
    assert beef.to_hex() == V["v2_D"]


def test_trim_known_txids_drops_unused_bumps():
    beef = Beef.from_string(V["v2_txid_only"])
    beef.make_txid_only(V["ids"]["B"])
    beef.trim_known_txids([V["ids"]["A"], V["ids"]["B"]])
    assert beef.txs == {} and beef.bumps == []


def test_build_beef_v2_from_raw_hexes_counts_only_written_txs():
    *_, d = _graph()
    data = build_beef_v2_from_raw_hexes([d.hex(), "zz", "abc"])
    assert list(Beef.from_binary(data).txs) == [V["ids"]["D"]]
