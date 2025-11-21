def test_to_binary_writes_header_and_zero_counts():
    from bsv.transaction.beef import Beef, BEEF_V2
    beef = Beef(version=BEEF_V2)
    data = beef.to_binary()
    # version (4) + bumps=0 (varint 0x00) + txs=0 (varint 0x00)
    assert data[:4] == int(BEEF_V2).to_bytes(4, "little")
    assert data[4:5] == b"\x00"
    assert data[5:6] == b"\x00"


def test_to_binary_atomic_prefix_and_subject():
    from bsv.transaction.beef import Beef, BEEF_V2, ATOMIC_BEEF
    beef = Beef(version=BEEF_V2)
    subject = "aa" * 32
    atomic = beef.to_binary_atomic(subject)
    assert atomic[:4] == int(ATOMIC_BEEF).to_bytes(4, "little")
    assert atomic[4:36] == bytes.fromhex(subject)[::-1]
    # remainder starts with standard BEEF header
    assert atomic[36:40] == int(BEEF_V2).to_bytes(4, "little")


def test_to_binary_parents_before_children():
    from bsv.transaction.beef import Beef, BEEF_V2
    from bsv.transaction import Transaction, TransactionInput, TransactionOutput
    from bsv.script.script import Script

    beef = Beef(version=BEEF_V2)
    # Build parent tx
    parent = Transaction()
    parent.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    parent_id = parent.txid()
    # Build child referencing parent
    child = Transaction()
    child_in = TransactionInput(source_txid=parent_id, source_output_index=0, unlocking_script=Script())
    child.inputs = [child_in]
    child.outputs = [TransactionOutput(Script(b"\x51"), 900)]

    # Merge via methods (ensures dependency linkage)
    beef.merge_transaction(child)
    beef.merge_transaction(parent)

    data = beef.to_binary()
    # Expect parent's serialized bytes appear before child's
    p_bytes = parent.serialize()
    c_bytes = child.serialize()
    blob = bytes(data)
    p_idx = blob.find(p_bytes)
    c_idx = blob.find(c_bytes)
    assert p_idx != -1 and c_idx != -1 and p_idx < c_idx


