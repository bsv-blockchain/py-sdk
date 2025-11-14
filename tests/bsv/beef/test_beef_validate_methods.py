def test_is_valid_allows_txid_only_when_bump_has_txid():
    from bsv.transaction.beef import Beef, BEEF_V2
    from bsv.transaction.beef_builder import merge_txid_only

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

    beef = Beef(version=BEEF_V2)
    txid = "11" * 32
    beef.bumps.append(DummyBump(100, txid))
    merge_txid_only(beef, txid)

    assert beef.is_valid(allow_txid_only=True) is True
    ok, roots = beef.verify_valid(allow_txid_only=True)
    assert ok is True
    # roots must contain the bump height mapping
    assert isinstance(roots, dict)
    assert 100 in roots


def test_get_valid_txids_includes_txidonly_with_proof_and_chained_raw():
    from bsv.transaction.beef import Beef, BEEF_V2, BeefTx
    from bsv.transaction.beef_validate import get_valid_txids

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

    beef = Beef(version=BEEF_V2)
    parent = "22" * 32
    child = "33" * 32
    beef.bumps.append(DummyBump(99, parent))
    # txid-only parent, raw child without inputs (treated as needing validation; remains not valid)
    beef.txs[parent] = BeefTx(txid=parent, data_format=2)
    beef.txs[child] = BeefTx(txid=child, tx_bytes=b"\x00", data_format=0)
    vs = set(get_valid_txids(beef))
    # parent is valid because it appears in bump
    assert parent in vs
    assert child not in vs


def test_verify_valid_multiple_bumps_roots_and_txidonly():
    from bsv.transaction.beef import Beef, BEEF_V2, BeefTx

    class DummyBump:
        def __init__(self, height, txid, root):
            self.block_height = height
            self._root = root
            self.path = [[{"offset": 0, "hash_str": txid, "txid": True}]]

        def compute_root(self, *_):
            return self._root

        def combine(self, other):
            return None

        def trim(self):
            return None

    beef = Beef(version=BEEF_V2)
    a = "ab" * 32
    b = "cd" * 32
    beef.bumps.append(DummyBump(500, a, "rootA"))
    beef.bumps.append(DummyBump(800, b, "rootB"))
    beef.txs[a] = BeefTx(txid=a, data_format=2)  # txid-only proven by bump
    beef.txs[b] = BeefTx(txid=b, data_format=2)  # txid-only proven by bump
    ok, roots = beef.verify_valid(allow_txid_only=True)
    assert ok is True
    assert roots.get(500) == "rootA"
    assert roots.get(800) == "rootB"


def test_verify_valid_fails_when_bump_index_mismatch():
    from bsv.transaction.beef import Beef, BEEF_V2, BeefTx

    class DummyBump:
        def __init__(self, height, txid, root):
            self.block_height = height
            self._root = root
            self.path = [[{"offset": 0, "hash_str": txid, "txid": True}]]

        def compute_root(self, *_):
            return self._root

    beef = Beef(version=BEEF_V2)
    proven_tx = "ef" * 32
    other_tx = "01" * 32
    beef.bumps.append(DummyBump(123, proven_tx, "rootZ"))
    # Create a tx with bump_index=0, but txid is not present in bump leaf -> should fail
    beef.txs[other_tx] = BeefTx(txid=other_tx, data_format=1, bump_index=0)
    ok, _ = beef.verify_valid(allow_txid_only=False)
    assert ok is False


def test_long_dependency_chain_requires_bump_for_validity():
    from bsv.transaction.beef import Beef, BEEF_V2

    class Tx:
        def __init__(self, txid, inputs=None):
            self._id = txid
            self.inputs = inputs or []
            self.merkle_path = None

        def txid(self):
            return self._id

        def serialize(self):
            return b"\x00"

    class Inp:
        def __init__(self, source_txid):
            self.source_txid = source_txid
            self.source_transaction = None

    beef = Beef(version=BEEF_V2)
    # Chain: A -> B -> C -> D (D newest)
    A, B, C, D = ("a1"*32), ("b1"*32), ("c1"*32), ("d1"*32)
    tA = Tx(A)
    tB = Tx(B, [Inp(A)])
    tC = Tx(C, [Inp(B)])
    tD = Tx(D, [Inp(C)])
    # Merge in order without bumps
    beef.merge_transaction(tA);
    beef.merge_transaction(tB)
    beef.merge_transaction(tC)
    beef.merge_transaction(tD)
    # No bumps -> structure not valid (cannot prove)
    assert beef.is_valid() is False


