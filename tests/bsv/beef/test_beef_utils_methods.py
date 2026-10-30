from bsv.merkle_path import MerklePath


def test_find_bump_returns_matching_bump():
    from bsv.transaction.beef import BEEF_V2, Beef
    from bsv.transaction.beef_utils import find_bump

    beef = Beef(version=BEEF_V2)
    txid = "44" * 32
    beef.bumps.append(MerklePath(100, [[{"offset": 0, "hash_str": txid, "txid": True}]]))
    assert find_bump(beef, txid) is not None
    assert find_bump(beef, "55" * 32) is None


def test_add_computed_leaves_adds_row_node():
    from bsv.transaction.beef import BEEF_V2, Beef
    from bsv.transaction.beef_utils import add_computed_leaves

    beef = Beef(version=BEEF_V2)
    left = "01" * 32
    right = "02" * 32
    # row0: two leaves; row1: only the sibling the proof needs
    bump = MerklePath(
        123,
        [[{"offset": 0, "hash_str": left}, {"offset": 1, "hash_str": right}], [{"offset": 1, "hash_str": "03" * 32}]],
    )
    beef.bumps.append(bump)
    add_computed_leaves(beef)
    # Expect the parent of the row-0 pair added to row1
    assert sorted(leaf["offset"] for leaf in beef.bumps[0].path[1]) == [0, 1]


def test_trim_known_txids_removes_only_txid_only_entries():
    from bsv.transaction.beef import BEEF_V2, Beef, BeefTx
    from bsv.transaction.beef_utils import trim_known_txids

    beef = Beef(version=BEEF_V2)
    keep_tx = "a0" * 32
    drop_tx = "b0" * 32
    # keep_tx: a raw entry (should NOT be trimmed)
    beef.txs[keep_tx] = BeefTx(txid=keep_tx, tx_bytes=b"\x00", data_format=0)
    # drop_tx: txid-only (should be trimmed if known)
    beef.txs[drop_tx] = BeefTx(txid=drop_tx, data_format=2)

    trim_known_txids(beef, [drop_tx])
    assert drop_tx not in beef.txs
    assert keep_tx in beef.txs
