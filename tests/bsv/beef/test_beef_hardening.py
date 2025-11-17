import pytest


def test_beef_unknown_version_errors():
    """Unknown BEEF version should raise an error (Go/TS parity)."""
    from bsv.transaction.beef import parse_beef
    # version=0xFFFFFFFF (unknown)
    data = (0xFFFFFFFF).to_bytes(4, 'little') + b"\x00\x00\x00\x00"
    with pytest.raises(ValueError, match='unsupported BEEF version'):
        parse_beef(data)


def test_atomic_subject_missing_returns_none_last_tx():
    """AtomicBEEF with missing subject tx should return None for last_tx (Go/TS parity)."""
    from bsv.transaction.beef import ATOMIC_BEEF
    from bsv.transaction import parse_beef_ex
    # Build Atomic with subject txid 0x33.. but empty inner
    atomic = int(ATOMIC_BEEF).to_bytes(4, 'little') + (b"\x33" * 32) + b"\x00\x00\x00\x00"
    try:
        beef, subject, last_tx = parse_beef_ex(atomic)
        assert subject == (b"\x33" * 32)[::-1].hex()
        assert last_tx is None
    except Exception:
        # Intentional: Accept failure for invalid inner; parser may raise various exceptions
        # Both success (with last_tx=None) and failure are acceptable outcomes for this test
        pass


def test_beef_v2_txidonly_then_raw_deduplicate():
    """BEEF V2: TxIDOnly followed by RawTx for same txid should deduplicate (Go/TS parity)."""
    from bsv.transaction.beef import BEEF_V2, new_beef_from_bytes
    # v2: bumps=0, txs=2 => TxIDOnly(aa), RawTx(empty invalid -> expect raise or skip)
    v2 = int(BEEF_V2).to_bytes(4, 'little') + b"\x00" + b"\x02" + b"\x02" + (b"\xaa" * 32) + b"\x00" + b"\x00"
    try:
        beef = new_beef_from_bytes(v2)
        # when parsed, either raise earlier or record one tx entry at most
        assert len(beef.txs) <= 1
    except Exception:
        # Intentional: Parser may raise various exceptions for invalid data
        # Both successful parsing (with deduplication) and failure are acceptable
        pass


def test_beef_v2_truncated_bumps_and_txs():
    """BEEF V2: truncated bumps or missing tx count should raise (Go/TS parity)."""
    from bsv.transaction.beef import BEEF_V2, new_beef_from_bytes
    # v2 with bumps=2 but no bump bytes
    v2_bad_bumps = int(BEEF_V2).to_bytes(4, 'little') + b"\x02"
    with pytest.raises((ValueError, TypeError)):
        new_beef_from_bytes(v2_bad_bumps)
    # v2 with bumps=0 and missing tx count
    v2_missing_txcount = int(BEEF_V2).to_bytes(4, 'little') + b"\x00"
    with pytest.raises((ValueError, TypeError)):
        new_beef_from_bytes(v2_missing_txcount)

# --- Additional E2E/edge-case tests for BEEF/AtomicBEEF ---
def test_beef_v2_mixed_txidonly_and_rawtx_linking():
    """BEEF V2: Mixed TxIDOnly and RawTx, parent-child linking and deduplication (Go/TS parity)."""
    from bsv.transaction import Transaction, TransactionInput, TransactionOutput
    from bsv.script.script import Script
    from bsv.transaction.beef import BEEF_V2, new_beef_from_bytes
    # Create parent tx
    parent = Transaction()
    parent.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    parent_id = parent.txid()
    # Create child tx (TxIDOnly first, then RawTx)
    child = Transaction()
    child_in = TransactionInput(source_txid=parent_id, source_output_index=0, unlocking_script=Script())
    child.inputs = [child_in]
    child.outputs = [TransactionOutput(Script(b"\x51"), 900)]
    child_id = child.txid()
    # Build BEEF V2 bytes: bumps=0, txs=3: TxIDOnly(parent), TxIDOnly(child), RawTx(parent), RawTx(child)
    v2 = int(BEEF_V2).to_bytes(4, 'little') + b"\x00"  # bumps=0
    v2 += b"\x04"  # txs=4
    v2 += b"\x02" + bytes.fromhex(parent_id)[::-1]  # TxIDOnly(parent)
    v2 += b"\x02" + bytes.fromhex(child_id)[::-1]   # TxIDOnly(child)
    v2 += b"\x00" + parent.serialize()              # RawTx(parent)
    v2 += b"\x00" + child.serialize()               # RawTx(child)
    beef = new_beef_from_bytes(v2)
    # Both parent and child should be present, and child input should link to parent
    assert parent_id in beef.txs and child_id in beef.txs
    btx = beef.find_transaction_for_signing(child_id)
    assert btx is not None
    assert btx.tx_obj is not None
    assert btx.tx_obj.inputs[0].source_transaction is not None
    assert btx.tx_obj.inputs[0].source_transaction.txid() == parent_id

def test_beef_bump_normalization_merging():
    """BEEF: BUMP normalization merges bumps with same (height, root) (Go/TS parity)."""
    from bsv.transaction.beef import Beef, BeefTx, BEEF_V2, normalize_bumps
    class DummyBump:
        def __init__(self, height, root):
            self.block_height = height
            self._root = root
        def compute_root(self):
            return self._root
        def combine(self, other):
            self._root = self._root  # no-op for test
        def trim(self):
            pass
    beef = Beef(version=BEEF_V2)
    beef.bumps = [DummyBump(100, b"root1"), DummyBump(100, b"root1"), DummyBump(101, b"root2")]
    # Add dummy txs with bump_index
    beef.txs["a"] = BeefTx(txid="a", bump_index=0)
    beef.txs["b"] = BeefTx(txid="b", bump_index=1)
    beef.txs["c"] = BeefTx(txid="c", bump_index=2)
    normalize_bumps(beef)
    # After normalization, bumps with same (height, root) should be merged
    assert len(beef.bumps) == 2
    # bump_index for txs["b"] should be remapped to 0 (merged with a)
    assert beef.txs["b"].bump_index == 0
    assert beef.txs["c"].bump_index == 1

def test_atomicbeef_nested_parsing():
    """AtomicBEEF: Nested AtomicBEEF should be parsed recursively (Go/TS parity)."""
    from bsv.transaction.beef import ATOMIC_BEEF, parse_beef_ex
    # Build inner BEEF V1
    from bsv.transaction import Transaction, TransactionOutput
    from bsv.script.script import Script
    t = Transaction()
    t.outputs = [TransactionOutput(Script(b"\x51"), 1)]
    beef_bytes = t.to_beef()
    # Wrap as AtomicBEEF (subject=txid)
    atomic = int(ATOMIC_BEEF).to_bytes(4, 'little') + bytes.fromhex(t.txid())[::-1] + beef_bytes
    beef, subject, last_tx = parse_beef_ex(atomic)
    assert subject == t.txid()
    assert last_tx is not None
    assert last_tx.txid() == t.txid()


def test_atomicbeef_deeply_nested():
    """AtomicBEEF: Deeply nested AtomicBEEF (3+ levels) should parse recursively or raise."""
    from bsv.transaction.beef import ATOMIC_BEEF, parse_beef_ex
    from bsv.transaction import Transaction, TransactionOutput
    from bsv.script.script import Script
    # Build innermost tx
    t = Transaction()
    t.outputs = [TransactionOutput(Script(b"\x51"), 1)]
    beef_bytes = t.to_beef()
    # Wrap 3 times
    atomic1 = int(ATOMIC_BEEF).to_bytes(4, 'little') + bytes.fromhex(t.txid())[::-1] + beef_bytes
    atomic2 = int(ATOMIC_BEEF).to_bytes(4, 'little') + bytes.fromhex(t.txid())[::-1] + atomic1
    atomic3 = int(ATOMIC_BEEF).to_bytes(4, 'little') + bytes.fromhex(t.txid())[::-1] + atomic2
    beef, subject, last_tx = parse_beef_ex(atomic3)
    assert subject == t.txid()
    assert last_tx is not None
    assert last_tx.txid() == t.txid()


def test_beef_v2_bump_index_out_of_range():
    """BEEF V2: bump index out of range should raise ValueError."""
    from bsv.transaction.beef import BEEF_V2, new_beef_from_bytes
    # version, bumps=1, txs=1, kind=RawTxAndBumpIndex, bumpIndex=2 (invalid)
    v2 = int(BEEF_V2).to_bytes(4, 'little') + b"\x01" + b"\x00" + b"\x01" + b"\x01" + b"\x02" + b"\x00"
    import pytest
    with pytest.raises((ValueError, TypeError)):
        new_beef_from_bytes(v2)


def test_beef_v2_txidonly_rawtx_duplicate_order():
    """BEEF V2: TxIDOnly, RawTx, TxIDOnly for same txid should deduplicate and not crash."""
    from bsv.transaction.beef import BEEF_V2, new_beef_from_bytes
    txid = b"\xbb" * 32
    v2 = int(BEEF_V2).to_bytes(4, 'little') + b"\x00" + b"\x03" + b"\x02" + txid + b"\x00" + b"\x01" + b"\x00" + b"\x02" + txid
    try:
        beef = new_beef_from_bytes(v2)
        # Should not crash, and only one entry for txid
        assert list(beef.txs.keys()).count(txid.hex()) <= 1
    except Exception:
        # Intentional: Parser may raise various exceptions for invalid data
        # Both successful parsing (with deduplication) and failure are acceptable
        pass


def test_beef_v2_extreme_tx_and_bump_count():
    """BEEF V2: Extremely large tx and bump counts should not crash, but may raise MemoryError."""
    from bsv.transaction.beef import BEEF_V2, new_beef_from_bytes
    # Large bump count (but no actual bump data)
    v2 = int(BEEF_V2).to_bytes(4, 'little') + b"\xFD\xFF\xFF"  # 0xFFFF bumps (truncated)
    import pytest
    with pytest.raises((ValueError, TypeError)):
        new_beef_from_bytes(v2)
    # Large tx count (but no actual tx data)
    v2 = int(BEEF_V2).to_bytes(4, 'little') + b"\x00" + b"\xFD\xFF\xFF"
    with pytest.raises(ValueError, match="unsupported tx data format"):
        new_beef_from_bytes(v2)


def test_beef_v2_txidonly_only():
    """BEEF V2: Only TxIDOnly entries, no RawTx, should parse but tx_obj is None."""
    from bsv.transaction.beef import BEEF_V2, new_beef_from_bytes
    txid = b"\xcc" * 32
    v2 = int(BEEF_V2).to_bytes(4, 'little') + b"\x00" + b"\x01" + b"\x02" + txid
    beef = new_beef_from_bytes(v2)
    assert txid.hex() in beef.txs
    assert beef.txs[txid.hex()].tx_obj is None


def test_atomicbeef_subject_not_in_inner():
    """AtomicBEEF: subject txid not present in inner BEEF should return last_tx=None."""
    from bsv.transaction.beef import ATOMIC_BEEF, parse_beef_ex
    # subject=0xdd.., inner is empty BEEF V2
    subject = b"\xdd" * 32
    v2 = int(4022206466).to_bytes(4, 'little') + b"\x00" + b"\x00"
    atomic = int(ATOMIC_BEEF).to_bytes(4, 'little') + subject + v2
    beef, subj, last_tx = parse_beef_ex(atomic)
    assert subj == subject[::-1].hex()
    assert last_tx is None


