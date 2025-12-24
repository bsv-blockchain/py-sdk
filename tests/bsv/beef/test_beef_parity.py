def test_parse_beef_ex_from_transaction_beef_v1():
    from bsv.transaction import Transaction, TransactionOutput
    from bsv.script.script import Script
    from bsv.transaction import parse_beef_ex
    # Build simple tx and convert to BEEF (legacy V1 path)
    t = Transaction()
    t.outputs = [TransactionOutput(Script(b"\x51"), 1)]
    beef_bytes = t.to_beef()
    _, _, last_tx = parse_beef_ex(beef_bytes)
    assert last_tx is not None
    assert last_tx.txid() == t.txid()


def test_find_transaction_for_signing_links_inputs():
    from bsv.transaction import Transaction, TransactionInput, TransactionOutput
    from bsv.script.script import Script
    from bsv.transaction.beef import Beef, BeefTx, BEEF_V2
    # Parent tx
    parent = Transaction()
    parent.outputs = [TransactionOutput(Script(b"\x51"), 1000)]
    parent_id = parent.txid()
    # Child spending parent[0]
    child = Transaction()
    child_in = TransactionInput(source_txid=parent_id, source_output_index=0, unlocking_script=Script())
    child.inputs = [child_in]
    child.outputs = [TransactionOutput(Script(b"\x51"), 900)]
    child_id = child.txid()
    # Beef container holding both
    beef = Beef(version=BEEF_V2)
    beef.txs[parent_id] = BeefTx(txid=parent_id, tx_bytes=parent.serialize(), tx_obj=parent, data_format=0)
    beef.txs[child_id] = BeefTx(txid=child_id, tx_bytes=child.serialize(), tx_obj=child, data_format=0)
    btx = beef.find_transaction_for_signing(child_id)
    assert btx is not None
    assert btx.tx_obj is not None
    # After linking, child's input should reference parent in source_transaction
    assert btx.tx_obj.inputs[0].source_transaction is parent


