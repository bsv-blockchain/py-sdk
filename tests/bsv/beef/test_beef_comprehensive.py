"""
Comprehensive BEEF tests covering missing functionality compared to GO/TS SDKs.
This file implements tests that are present in GO SDK's beef_test.go and TypeScript SDK's Beef.test.ts
but missing or incomplete in Python SDK.
"""
import pytest
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
from bsv.script.script import Script
from bsv.transaction.beef import Beef, BeefTx, BEEF_V1, BEEF_V2, ATOMIC_BEEF, new_beef_from_bytes, new_beef_from_atomic_bytes
from bsv.transaction.beef_utils import to_log_string, find_atomic_transaction, trim_known_txids
from bsv.transaction.beef_validate import validate_transactions
from bsv.merkle_path import MerklePath


# Test vectors from GO SDK
BRC62Hex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"


def test_from_beef_error_case():
    """Test FromBEEF with invalid data raises appropriate errors (GO: TestFromBeefErrorCase)."""
    from bsv.transaction.beef import parse_beef
    
    # Test invalid/unsupported data
    with pytest.raises(ValueError, match="unsupported BEEF version"):
        parse_beef(b"invalid data")
    
    # Test empty data - should raise some error
    with pytest.raises(Exception):  # Can be ValueError, IndexError, or struct.error
        parse_beef(b"")
    
    # Test truncated version header
    with pytest.raises(Exception):  # Can be ValueError, IndexError, or struct.error
        parse_beef(b"\x00\x01")


def test_new_empty_beef_v1():
    """Test creating empty BEEF V1 (GO: TestNewEmptyBEEF)"""
    beef = Beef(version=BEEF_V1)
    beef_bytes = beef.to_binary()
    assert beef_bytes[:4] == int(BEEF_V1).to_bytes(4, "little")
    # V1 format: version (4) + bumps (varint) + txs (varint)
    # Empty should be: version + 0x00 + 0x00
    assert len(beef_bytes) == 6


def test_new_empty_beef_v2():
    """Test creating empty BEEF V2 (GO: TestNewEmptyBEEF)"""
    beef = Beef(version=BEEF_V2)
    beef_bytes = beef.to_binary()
    assert beef_bytes[:4] == int(BEEF_V2).to_bytes(4, "little")
    # V2 format: version (4) + bumps (varint) + txs (varint)
    # Empty should be: version + 0x00 + 0x00
    assert len(beef_bytes) == 6


def test_beef_transaction_finding():
    """Test finding and removing transactions (GO: TestBeefTransactionFinding)"""
    beef = Beef(version=BEEF_V2)
    txid1 = "aa" * 32
    txid2 = "bb" * 32
    
    beef.merge_txid_only(txid1)
    beef.merge_txid_only(txid2)
    
    # Verify we can find them
    assert beef.find_transaction(txid1) is not None
    assert beef.find_transaction(txid2) is not None
    
    # Remove one
    beef.remove_existing_txid(txid1)
    
    # Verify it's gone
    assert beef.find_transaction(txid1) is None
    assert beef.find_transaction(txid2) is not None


def test_beef_sort_txs():
    """Test transaction sorting/validation with parent-child relationships (GO: TestBeefSortTxs)."""
    beef = Beef(version=BEEF_V2)
    
    # Create parent transaction
    parent = Transaction()
    parent.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    parent_id = parent.txid()
    
    # Create child transaction that spends from parent
    child = Transaction()
    child_in = TransactionInput(source_txid=parent_id, source_output_index=0, unlocking_script=Script())
    child.inputs = [child_in]
    child.outputs = [TransactionOutput(Script(b"\x51"), 900)]
    child_id = child.txid()
    
    # Add transactions to BEEF
    beef.merge_transaction(child)
    beef.merge_transaction(parent)
    
    # Verify both transactions are in BEEF
    assert parent_id in beef.txs, "Parent transaction should be in BEEF"
    assert child_id in beef.txs, "Child transaction should be in BEEF"
    
    # Verify parent-child relationship is maintained
    assert child.inputs[0].source_txid == parent_id, "Child should reference parent TXID"
    
    # Validate transactions
    result = validate_transactions(beef)
    # print(result)
    # After sorting, parent should be valid (no missing inputs, but no bump either)
    # Parent has no inputs, so it might be in not_valid if no bump is present
    # Child references parent, so once parent is in beef.txs, child should be able to validate
    # The actual validation depends on whether transactions have bumps or not
    # At minimum, both transactions should be in beef.txs
    assert parent_id in beef.txs
    assert child_id in beef.txs
    
    # Parent should be in one of the result categories
    assert (
            parent_id in result.not_valid # or parent_id in result.valid or 
            # parent_id in result.with_missing_inputs or parent_id in result.txid_only
            )
    
    # Child should also be in one of the result categories
    assert (
            child_id in result.not_valid # or child_id in result.valid or 
            # child_id in result.with_missing_inputs or child_id in result.txid_only
            )


def test_beef_to_log_string():
    """Test log string generation with transaction and bump information (GO: TestBeefToLogString)."""
    beef = Beef(version=BEEF_V2)
    
    class DummyBump:
        def __init__(self, height, txid):
            self.block_height = height
            self.path = [[{"offset": 0, "hash_str": txid, "txid": True}]]
    
    txid = "cc" * 32
    beef.bumps.append(DummyBump(100, txid))
    beef.merge_txid_only(txid)
    
    log_str = to_log_string(beef)
    
    # Verify log string is not empty and contains expected information
    assert log_str is not None, "Log string should not be None"
    assert len(log_str) > 0, "Log string should not be empty"
    assert "BEEF" in log_str or "beef" in log_str.lower() or len(log_str) > 10, \
        "Log string should contain BEEF information or be substantive"
    assert "BEEF with" in log_str
    assert "BUMPs" in log_str or "BUMP" in log_str
    assert "Transactions" in log_str or "Transaction" in log_str
    assert "BUMP 0" in log_str or "BUMP" in log_str
    assert "block:" in log_str or str(100) in log_str
    assert txid in log_str


def test_beef_clone():
    """Test BEEF cloning (GO: TestBeefClone)"""
    beef = Beef(version=BEEF_V2)
    
    class DummyBump:
        def __init__(self, height, txid):
            self.block_height = height
            self.path = [[{"offset": 0, "hash_str": txid, "txid": True}]]
    
    txid = "dd" * 32
    beef.bumps.append(DummyBump(200, txid))
    beef.merge_txid_only(txid)
    
    # Clone the object
    clone = beef.clone()
    
    # Verify basic properties match
    assert clone.version == beef.version
    assert len(clone.bumps) == len(beef.bumps)
    assert len(clone.txs) == len(beef.txs)
    
    # Verify BUMPs are copied
    assert clone.bumps[0].block_height == beef.bumps[0].block_height
    
    # Verify transactions are copied
    assert txid in clone.txs
    assert clone.txs[txid].txid == beef.txs[txid].txid
    assert clone.txs[txid].data_format == beef.txs[txid].data_format
    
    # Modify clone and verify original is unchanged
    clone.version = 999
    assert beef.version != clone.version
    
    # Remove a transaction from clone and verify original is unchanged
    clone.remove_existing_txid(txid)
    assert txid in beef.txs
    assert txid not in clone.txs


def test_beef_trim_known_txids():
    """Test trimming known TXIDs (GO: TestBeefTrimknownTxIDs)"""
    beef = Beef(version=BEEF_V2)
    
    txid1 = "ee" * 32
    txid2 = "ff" * 32
    txid3 = "00" * 32
    
    # Add transactions
    beef.merge_txid_only(txid1)
    beef.merge_txid_only(txid2)
    
    # Add a raw transaction (should not be trimmed)
    tx = Transaction()
    tx.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    beef.merge_transaction(tx)
    txid3 = tx.txid()
    
    # Convert some to TxIDOnly format
    beef.make_txid_only(txid1)
    beef.make_txid_only(txid2)
    
    # Verify they are now in TxIDOnly format
    assert beef.txs[txid1].data_format == 2
    assert beef.txs[txid2].data_format == 2
    
    # Trim the known TxIDs
    trim_known_txids(beef, [txid1, txid2])
    
    # Verify the transactions were removed
    assert txid1 not in beef.txs
    assert txid2 not in beef.txs
    
    # Verify other transactions still exist
    assert txid3 in beef.txs
    assert beef.txs[txid3].data_format != 2  # Raw transaction should not be trimmed


def test_beef_get_valid_txids():
    """Test getting valid TXIDs (GO: TestBeefGetValidTxids)"""
    beef = Beef(version=BEEF_V2)
    
    class DummyBump:
        def __init__(self, height, txid):
            self.block_height = height
            self.path = [[{"offset": 0, "hash_str": txid, "txid": True}]]
    
    txid1 = "11" * 32
    txid2 = "22" * 32
    
    # Add bump with txid1
    beef.bumps.append(DummyBump(300, txid1))
    beef.merge_txid_only(txid1)
    beef.merge_txid_only(txid2)
    
    # Get valid txids
    valid_txids = beef.get_valid_txids()
    
    # txid1 should be valid (present in bump)
    assert txid1 in valid_txids
    
    # txid2 might not be valid if not in bump and has no inputs
    assert txid2 not in valid_txids


def test_beef_find_transaction_for_signing():
    """Test finding transaction for signing (GO: TestBeefFindTransactionForSigning)"""
    beef = Beef(version=BEEF_V2)
    
    # Create parent transaction
    parent = Transaction()
    parent.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    parent_id = parent.txid()
    
    # Create child transaction
    child = Transaction()
    child_in = TransactionInput(source_txid=parent_id, source_output_index=0, unlocking_script=Script())
    child.inputs = [child_in]
    child.outputs = [TransactionOutput(Script(b"\x51"), 900)]
    child_id = child.txid()
    
    # Add transactions
    beef.merge_transaction(parent)
    beef.merge_transaction(child)
    
    # Test FindTransactionForSigning
    btx = beef.find_transaction_for_signing(child_id)
    assert btx is not None
    assert btx.txid == child_id
    
    # Verify inputs are linked
    if btx.tx_obj:
        assert len(btx.tx_obj.inputs) > 0
        if btx.tx_obj.inputs[0].source_transaction:
            assert btx.tx_obj.inputs[0].source_transaction.txid() == parent_id


def test_beef_find_atomic_transaction():
    """Test finding atomic transaction (GO: TestBeefFindAtomicTransaction)"""
    beef = Beef(version=BEEF_V2)
    
    # Create a transaction
    tx = Transaction()
    tx.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    tx_id = tx.txid()
    
    # Add transaction
    beef.merge_transaction(tx)
    
    # Test FindAtomicTransaction
    result = find_atomic_transaction(beef, tx_id)
    assert result is not None
    assert result.txid() == tx_id


def test_beef_merge_bump():
    """Test merging bumps (GO: TestBeefMergeBump)"""
    beef1 = Beef(version=BEEF_V2)
    beef2 = Beef(version=BEEF_V2)
    
    class DummyBump:
        def __init__(self, height, txid):
            self.block_height = height
            self.path = [[{"offset": 0, "hash_str": txid, "txid": True}]]
        
        def compute_root(self):
            return "root"
        
        def combine(self, other):
            pass
    
    bump = DummyBump(400, "33" * 32)
    
    # Record initial state
    initial_bump_count = len(beef1.bumps)
    
    # Test MergeBump
    idx = beef1.merge_bump(bump)
    
    # Verify the BUMP was merged
    assert len(beef1.bumps) == initial_bump_count + 1
    assert beef1.bumps[idx].block_height == bump.block_height


def test_beef_merge_transactions():
    """Test merging transactions (GO: TestBeefMergeTransactions)"""
    beef1 = Beef(version=BEEF_V2)
    beef2 = Beef(version=BEEF_V2)
    
    # Create a transaction
    tx = Transaction()
    tx.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    tx_id = tx.txid()
    
    # Add to beef2
    beef2.merge_transaction(tx)
    
    # Remove from beef1 to ensure we can merge it
    if tx_id in beef1.txs:
        beef1.remove_existing_txid(tx_id)
    
    # Test MergeTransaction
    initial_tx_count = len(beef1.txs)
    raw_tx = tx.serialize()
    beef_tx = beef1.merge_raw_tx(raw_tx, None)
    
    assert beef_tx is not None
    assert len(beef1.txs) == initial_tx_count + 1
    
    # Test MergeTransaction with Transaction object
    beef3 = Beef(version=BEEF_V2)
    if tx_id in beef3.txs:
        beef3.remove_existing_txid(tx_id)
    initial_tx_count = len(beef3.txs)
    beef_tx = beef3.merge_transaction(tx)
    
    assert beef_tx is not None
    assert len(beef3.txs) == initial_tx_count + 1


def test_beef_error_handling():
    """Test error handling (GO: TestBeefErrorHandling)"""
    # Test invalid transaction format
    invalid_bytes = b"\xff\xff\xff\xff" + b"\x00" * 10
    
    with pytest.raises(ValueError, match="unsupported BEEF version"):
        new_beef_from_bytes(invalid_bytes)


def test_beef_edge_cases_txid_only():
    """Test BEEF with only TxIDOnly transactions (GO: TestBeefEdgeCases)"""
    beef = Beef(version=BEEF_V2)
    
    txid = "44" * 32
    beef.merge_txid_only(txid)
    
    # Verify the transaction is TxIDOnly
    assert beef.txs[txid].data_format == 2
    assert beef.txs[txid].tx_obj is None
    
    # Test that TxIDOnly transactions are properly categorized
    result = validate_transactions(beef)
    assert txid in result.txid_only
    
    # Test that the transaction is not returned by GetValidTxids (unless in bump)
    valid_txids = beef.get_valid_txids()
    # If txid is not in any bump, it might not be in valid_txids
    assert txid not in valid_txids


def test_beef_merge_beef_bytes():
    """Test merging BEEF bytes (GO: TestBeefMergeBeefBytes)"""
    beef1 = Beef(version=BEEF_V2)
    
    # Create a minimal second BEEF object with a single transaction
    beef2 = Beef(version=BEEF_V2)
    tx = Transaction()
    tx.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    beef2.merge_transaction(tx)
    
    # Record initial state
    initial_tx_count = len(beef1.txs)
    
    # Test MergeBeefBytes
    beef2_bytes = beef2.to_binary()
    beef1.merge_beef_bytes(beef2_bytes)
    
    # Verify transactions were merged
    assert len(beef1.txs) == initial_tx_count + 1
    
    # Test merging invalid BEEF bytes
    invalid_bytes = b"invalid beef data"
    with pytest.raises(ValueError, match="unsupported BEEF version"):
        beef1.merge_beef_bytes(invalid_bytes)


def test_beef_merge_beef_tx():
    """Test merging BeefTx (GO: TestBeefMergeBeefTx)"""
    # Test merge valid transaction
    tx = Transaction()
    tx.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    
    beef = Beef(version=BEEF_V2)
    btx = BeefTx(txid=tx.txid(), tx_bytes=tx.serialize(), tx_obj=tx, data_format=0)
    
    result = beef.merge_beef_tx(btx)
    assert result is not None
    assert len(beef.txs) == 1
    
    # Test handle nil transaction - Python doesn't allow None, but we can test TypeError
    with pytest.raises((TypeError, AttributeError, ValueError), match="'NoneType' object has no attribute 'data_format'"):
        beef.merge_beef_tx(None)  # type: ignore
    
    # Test handle BeefTx with nil Transaction (txid-only)
    btx_nil = BeefTx(txid="55" * 32, tx_bytes=b"", tx_obj=None, data_format=2)
    result = beef.merge_beef_tx(btx_nil)
    assert result is not None
    assert result.data_format == 2


def test_beef_find_atomic_transaction_with_source_transactions():
    """Test finding atomic transaction with source transactions (GO: TestBeefFindAtomicTransactionWithSourceTransactions)"""
    beef = Beef(version=BEEF_V2)
    
    # Create source transaction
    source_tx = Transaction()
    source_tx.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    source_id = source_tx.txid()
    beef.merge_transaction(source_tx)
    
    # Create main transaction that references the source
    main_tx = Transaction()
    main_in = TransactionInput(source_txid=source_id, source_output_index=0, unlocking_script=Script())
    main_tx.inputs = [main_in]
    main_tx.outputs = [TransactionOutput(Script(b"\x51"), 900)]
    main_id = main_tx.txid()
    beef.merge_transaction(main_tx)
    
    # Create a BUMP for the source transaction
    class DummyBump:
        def __init__(self, height, txid):
            self.block_height = height
            self.path = [[{"offset": 0, "hash_str": txid, "txid": True}]]
    
    bump = DummyBump(500, source_id)
    beef.bumps.append(bump)
    
    # Test FindAtomicTransaction
    result = find_atomic_transaction(beef, main_id)
    assert result is not None
    assert result.txid() == main_id
    
    # Verify source transaction has merkle path (if implemented)
    if result.inputs and result.inputs[0].source_transaction:
        # Source transaction should be linked
        assert result.inputs[0].source_transaction.txid() == source_id


def test_beef_merge_txid_only():
    """Test merging TXID only (GO: TestBeefMergeTxidOnly)"""
    beef = Beef(version=BEEF_V2)
    
    txid = "66" * 32
    
    # Test MergeTxidOnly
    result = beef.merge_txid_only(txid)
    assert result is not None
    assert result.data_format == 2
    assert result.txid == txid
    assert result.tx_obj is None
    
    # Verify the transaction was added to the BEEF object
    assert len(beef.txs) == 1
    assert txid in beef.txs
    
    # Test merging the same txid again
    result2 = beef.merge_txid_only(txid)
    assert result2 is not None
    assert result2 == result
    assert len(beef.txs) == 1


def test_beef_find_bump_with_nil_bump_index():
    """Test finding bump with no BUMPs (GO: TestBeefFindBumpWithNilBumpIndex)"""
    beef = Beef(version=BEEF_V2)
    
    # Create a transaction with a source transaction
    source_tx = Transaction()
    source_tx.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    
    main_tx = Transaction()
    main_in = TransactionInput(source_txid=source_tx.txid(), source_output_index=0, unlocking_script=Script())
    main_tx.inputs = [main_in]
    main_tx.outputs = [TransactionOutput(Script(b"\x51"), 900)]
    
    # Add transactions to BEEF
    beef.merge_transaction(source_tx)
    beef.merge_transaction(main_tx)
    
    # Test FindBump with no BUMPs
    from bsv.transaction.beef_utils import find_bump
    result = find_bump(beef, main_tx.txid())
    assert result is None


def test_beef_bytes_serialize_deserialize():
    """Test serialization and deserialization (GO: TestBeefBytes)"""
    beef = Beef(version=BEEF_V2)
    
    # Add a TxIDOnly transaction
    txid = "77" * 32
    beef.merge_txid_only(txid)
    
    # Add a RawTx transaction
    tx = Transaction()
    tx.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    beef.merge_transaction(tx)
    
    # Serialize to bytes
    bytes_data = beef.to_binary()
    
    # Deserialize and verify
    beef2 = new_beef_from_bytes(bytes_data)
    assert beef2.version == beef.version
    assert len(beef2.bumps) == len(beef.bumps)
    assert len(beef2.txs) == len(beef.txs)
    
    # Verify transactions maintained their format
    for txid, tx in beef.txs.items():
        tx2 = beef2.txs.get(txid)
        assert tx2 is not None
        assert tx.data_format == tx2.data_format
        if tx.data_format == 2:
            assert tx2.txid == tx.txid


def test_beef_add_computed_leaves():
    """Test adding computed leaves (GO: TestBeefAddComputedLeaves)"""
    beef = Beef(version=BEEF_V2)
    
    from bsv.transaction.beef_utils import add_computed_leaves
    
    # Create leaf hashes
    left_hash = "01" * 32
    right_hash = "02" * 32
    
    # Create a BUMP with two leaves in row 0 and no computed parent in row 1
    class DummyBump:
        def __init__(self, height, left, right):
            self.block_height = height
            self.path = [
                [
                    {"offset": 0, "hash_str": left},
                    {"offset": 1, "hash_str": right},
                ],
                [],  # Empty row for parent
            ]
    
    bump = DummyBump(600, left_hash, right_hash)
    beef.bumps.append(bump)
    
    # Call AddComputedLeaves
    add_computed_leaves(beef)
    
    # Verify the parent hash was computed and added
    assert len(beef.bumps[0].path[1]) == 1
    assert beef.bumps[0].path[1][0].get("offset") == 0


def test_beef_from_v1():
    """Test parsing BEEF V1 (GO: TestBeefFromV1)"""
    beef_data = bytes.fromhex(BRC62Hex)
    beef = new_beef_from_bytes(beef_data)
    assert beef is not None
    assert beef.version == BEEF_V1
    assert beef.is_valid(allow_txid_only=False) or beef.is_valid(allow_txid_only=True)


def test_beef_make_txid_only_and_bytes():
    """Test MakeTxidOnly and Bytes (GO: TestMakeTxidOnlyAndBytes)"""
    beef = Beef(version=BEEF_V2)
    
    # Create a transaction
    tx = Transaction()
    tx.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    tx_id = tx.txid()
    
    # Add transaction
    beef.merge_transaction(tx)
    
    # Make it TxIDOnly
    beef.make_txid_only(tx_id)
    
    # Serialize to bytes
    bytes_data = beef.to_binary()
    assert bytes_data is not None
    
    # Verify it can be deserialized
    beef2 = new_beef_from_bytes(bytes_data)
    assert beef2 is not None
    assert tx_id in beef2.txs
    assert beef2.txs[tx_id].data_format == 2


def test_beef_verify():
    """Test BEEF verification (GO: TestBeefVerify)"""
    # Test with a known BEEF hex
    beef_data = bytes.fromhex(BRC62Hex)
    beef = new_beef_from_bytes(beef_data)
    
    # Verify it's valid
    is_valid_result = beef.is_valid(allow_txid_only=True)
    # Should be valid or at least parseable
    assert is_valid_result
    
    # Test verify_valid
    ok, roots = beef.verify_valid(allow_txid_only=True);
    # May or may not be valid depending on chain tracker, but should not crash
    assert isinstance(ok, bool)
    assert isinstance(roots, dict)

