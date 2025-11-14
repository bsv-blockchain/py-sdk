import pytest


def test_parse_beef_v2_varint_fd_zero_counts_ok():
    """BEEF V2 with varint(0xFD) encoded zero counts for bumps/txs should parse as empty Beef."""
    from bsv.transaction.beef import BEEF_V2, new_beef_from_bytes
    # version + bumps=VarInt(0xFD 00 00) + txs=VarInt(0xFD 00 00)
    data = int(BEEF_V2).to_bytes(4, "little") + b"\xFD\x00\x00" + b"\xFD\x00\x00"
    beef = new_beef_from_bytes(data)
    assert beef.version == BEEF_V2
    assert len(beef.bumps) == 0
    assert len(beef.txs) == 0


def test_verify_valid_fails_on_inconsistent_roots_in_single_bump():
    """A single BUMP with two txid leaves that compute different roots should invalidate."""
    from bsv.transaction.beef import Beef, BEEF_V2

    class DummyBump:
        def __init__(self, height, a, b):
            self.block_height = height
            self.path = [[
                {"offset": 0, "hash_str": a, "txid": True},
                {"offset": 1, "hash_str": b, "txid": True},
            ]]

        # Python verify_valid calls compute_root(txid) and expects a consistent root per height
        def compute_root(self, txid=None):
            if txid == "aa"*32:
                return "rootA"
            if txid == "bb"*32:
                return "rootB"
            return "rootX"

    beef = Beef(version=BEEF_V2)
    a = "aa" * 32
    b = "bb" * 32
    beef.bumps.append(DummyBump(100, a, b))
    ok, roots = beef.verify_valid(allow_txid_only=True)
    assert ok is False
    assert roots == {}


def test_merge_raw_tx_invalid_bump_index_raises():
    from bsv.transaction.beef import Beef, BEEF_V2
    from bsv.transaction import Transaction, TransactionOutput
    from bsv.script.script import Script
    from bsv.transaction.beef_serialize import to_binary
    from bsv.transaction.beef_builder import merge_raw_tx

    t = Transaction()
    t.outputs = [TransactionOutput(Script(b"\x51"), 1)]
    raw = t.serialize()
    beef = Beef(version=BEEF_V2)
    with pytest.raises(Exception, match="invalid bump index"):
        merge_raw_tx(beef, raw, bump_index=1)  # no bumps -> index out of range


def test_to_binary_dedupes_txid_only_and_raw_for_same_txid():
    """If txidOnly and RawTx of same txid exist, serialization should write once."""
    from bsv.transaction.beef import Beef, BEEF_V2, BeefTx
    from bsv.transaction import Transaction, TransactionOutput
    from bsv.script.script import Script

    beef = Beef(version=BEEF_V2)
    t = Transaction()
    t.outputs = [TransactionOutput(Script(b"\x51"), 1)]
    txid = t.txid()
    # Add txid-only then raw
    beef.txs[txid] = BeefTx(txid=txid, data_format=2)
    beef.merge_transaction(t)
    data = beef.to_binary()
    # The tx bytes should occur exactly once
    blob = bytes(data)
    count = blob.count(t.serialize())
    assert count == 1


def test_new_beef_from_atomic_bytes_too_short_raises():
    """AtomicBEEF shorter than 36 bytes must raise."""
    from bsv.transaction.beef import new_beef_from_atomic_bytes
    with pytest.raises(Exception, match="too short"):
        new_beef_from_atomic_bytes(b"\x01\x01\x01")  # shorter than 36


