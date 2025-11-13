def test_find_bump_returns_matching_bump():
    from bsv.transaction.beef import Beef, BEEF_V2
    from bsv.transaction.beef_utils import find_bump

    class DummyBump:
        def __init__(self, height, txid):
            self.block_height = height
            self.path = [[{"offset": 0, "hash_str": txid, "txid": True}]]

    beef = Beef(version=BEEF_V2)
    txid = "44" * 32
    beef.bumps.append(DummyBump(100, txid))
    assert find_bump(beef, txid) is not None
    assert find_bump(beef, "55" * 32) is None


def test_add_computed_leaves_adds_row_node():
    from bsv.transaction.beef import Beef, BEEF_V2
    from bsv.transaction.beef_utils import add_computed_leaves

    class DummyBump:
        def __init__(self, height, left_hash, right_hash):
            self.block_height = height
            # row0: two leaves with even offset 0 and odd offset 1
            self.path = [[
                {"offset": 0, "hash_str": left_hash},
                {"offset": 1, "hash_str": right_hash},
            ], []]  # row1: empty initially

    beef = Beef(version=BEEF_V2)
    left = "01" * 32
    right = "02" * 32
    bump = DummyBump(123, left, right)
    beef.bumps.append(bump)
    add_computed_leaves(beef)
    # Expect one computed node added to row1
    assert len(beef.bumps[0].path[1]) >= 1


def test_trim_known_txids_removes_only_txid_only_entries():
    from bsv.transaction.beef import Beef, BEEF_V2, BeefTx
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


