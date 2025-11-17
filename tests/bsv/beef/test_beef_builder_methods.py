import pytest


def test_merge_txid_only_and_make_txid_only():
    from bsv.transaction.beef import Beef, BEEF_V2
    from bsv.transaction.beef_builder import merge_txid_only
    beef = Beef(version=BEEF_V2)
    txid = "aa" * 32
    btx = merge_txid_only(beef, txid)
    assert txid in beef.txs and beef.txs[txid].data_format == 2
    # make_txid_only should return the same state for the same txid
    btx2 = beef.make_txid_only(txid)
    assert btx2 is not None
    assert btx2.data_format == 2


def test_merge_transaction_sets_bump_index_when_bump_proves_txid():
    from bsv.transaction.beef import Beef, BeefTx, BEEF_V2
    from bsv.transaction.beef_builder import merge_bump, merge_transaction

    class DummyBump:
        def __init__(self, height, txid):
            self.block_height = height
            self.path = [[{"offset": 0, "hash_str": txid, "txid": True}]]

        def compute_root(self):
            # compute_root not used in this assertion; return constant
            return "root"

        def combine(self, other):
            return None

        def trim(self):
            return None

    # Dummy transaction exposing txid()
    class DummyTx:
        def __init__(self, txid):
            self._id = txid
            self.inputs = []
            self.merkle_path = None

        def txid(self):
            return self._id

        def serialize(self):
            return b"\x00"

    beef = Beef(version=BEEF_V2)
    txid = "bb" * 32
    bump = DummyBump(100, txid)
    idx = merge_bump(beef, bump)
    assert idx == 0
    # Merge transaction and expect bump_index to be set
    btx = merge_transaction(beef, DummyTx(txid))
    assert btx.bump_index == 0


def test_merge_beef_merges_bumps_and_txs():
    from bsv.transaction.beef import Beef, BEEF_V2, BeefTx
    from bsv.transaction.beef_builder import merge_beef, merge_txid_only

    class DummyBump:
        def __init__(self, height, txid):
            self.block_height = height
            self.path = [[{"offset": 0, "hash_str": txid, "txid": True}]]

        def compute_root(self):
            return "root"

        def combine(self, other):
            return None

        def trim(self):
            return None

    a = Beef(version=BEEF_V2)
    b = Beef(version=BEEF_V2)
    txid = "cc" * 32
    b.bumps.append(DummyBump(123, txid))
    merge_txid_only(b, txid)
    # Merge b into a
    merge_beef(a, b)
    assert len(a.bumps) == 1
    assert txid in a.txs


def test_merge_bump_combines_same_root_objects_and_sets_bump_index():
    from bsv.transaction.beef import Beef, BEEF_V2, BeefTx
    from bsv.transaction.beef_builder import merge_bump

    class DummyBump:
        def __init__(self, height, txid, root):
            self.block_height = height
            self._root = root
            self.path = [[{"offset": 0, "hash_str": txid}]]

        def compute_root(self):
            return self._root

        def combine(self, other):
            # mark leaf as txid after combine to emulate consolidation
            for leaf in self.path[0]:
                if "hash_str" in leaf:
                    leaf["txid"] = True

        def trim(self):
            return None

    beef = Beef(version=BEEF_V2)
    txid = "dd" * 32
    b1 = DummyBump(100, txid, "rootX")
    b2 = DummyBump(100, txid, "rootX")  # same root/height -> should combine

    i1 = merge_bump(beef, b1)
    i2 = merge_bump(beef, b2)
    assert i1 == 0 and i2 == 0
    assert len(beef.bumps) == 1

    # After combine, try validate should set bump_index when merging a raw tx
    from bsv.transaction.beef_builder import merge_transaction

    class DummyTx:
        def __init__(self, txid):
            self._id = txid
            self.inputs = []
            self.merkle_path = None

        def txid(self):
            return self._id

        def serialize(self):
            return b"\x00"

    btx = merge_transaction(beef, DummyTx(txid))
    assert btx.bump_index == 0


