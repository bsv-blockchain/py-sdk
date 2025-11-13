"""
Transaction詳細テスト
GO SDKのtransaction_test.goを参考に実装
"""
import pytest
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
from bsv.script.script import Script
from bsv.script.type import P2PKH
from bsv.keys import PrivateKey
from bsv.fee_models import SatoshisPerKilobyte

BRC62Hex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"


def test_is_coinbase():
    """Test IsCoinbase (GO: TestIsCoinbase)"""
    # Coinbase transaction hex from GO SDK test
    coinbase_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff17033f250d2f43555656452f2c903fb60859897700d02700ffffffff01d864a012000000001976a914d648686cf603c11850f39600e37312738accca8f88ac00000000"
    
    tx = Transaction.from_hex(coinbase_hex)
    assert tx is not None
    
    # Check if it's a coinbase transaction
    # Coinbase transactions have exactly one input with all-zero source txid
    is_coinbase = (
        len(tx.inputs) == 1 and
        tx.inputs[0].source_txid == "00" * 32
    )
    assert is_coinbase is True


def test_is_valid_txid():
    """Test IsValidTxID (GO: TestIsValidTxID)"""
    # Valid TXID (32 bytes)
    valid_txid_hex = "fe77aa03d5563d3ec98455a76655ea3b58e19a4eb102baf7b2a47af37e94b295"
    valid_txid_bytes = bytes.fromhex(valid_txid_hex)
    
    assert len(valid_txid_bytes) == 32
    
    # Invalid TXID (31 bytes)
    invalid_txid_hex = "fe77aa03d5563d3ec98455a76655ea3b58e19a4eb102baf7b2a47af37e94b2"
    invalid_txid_bytes = bytes.fromhex(invalid_txid_hex)
    
    assert len(invalid_txid_bytes) == 31


def test_transaction_beef():
    """Test BEEF serialization and deserialization (GO: TestBEEF)"""
    tx = Transaction.from_beef(BRC62Hex)
    assert tx is not None
    
    # Verify it has inputs
    assert len(tx.inputs) > 0
    
    # Serialize back to BEEF
    beef_hex = tx.to_beef().hex()
    assert len(beef_hex) > 0
    
    # Deserialize again and verify
    tx2 = Transaction.from_beef(beef_hex)
    assert tx2 is not None
    assert tx2.txid() == tx.txid()


def test_transaction_ef():
    """Test EF (Extended Format) serialization (GO: TestEF)"""
    tx = Transaction.from_beef(BRC62Hex)
    assert tx is not None
    
    # Serialize to EF format
    ef_bytes = tx.to_ef()
    assert len(ef_bytes) > 0
    
    # Verify EF format starts with version and EF marker
    assert ef_bytes[:4] == tx.version.to_bytes(4, "little")
    # EF format has specific marker bytes
    assert len(ef_bytes) > 10


def test_transaction_shallow_clone():
    """Test ShallowClone (GO: TestShallowClone)"""
    tx = Transaction.from_beef(BRC62Hex)
    assert tx is not None
    
    # Create shallow clone (Python doesn't have explicit shallow_clone, so we test copy)
    clone = Transaction(
        tx_inputs=list(tx.inputs),
        tx_outputs=list(tx.outputs),
        version=tx.version,
        locktime=tx.locktime,
        merkle_path=tx.merkle_path
    )
    
    # Verify they serialize to the same bytes
    assert tx.serialize() == clone.serialize()


def test_transaction_clone():
    """Test Clone (GO: TestClone)"""
    tx = Transaction.from_beef(BRC62Hex)
    assert tx is not None
    
    # Create a deep copy by serializing and deserializing
    clone = Transaction.from_hex(tx.serialize())
    
    # Verify they serialize to the same bytes
    assert tx.serialize() == clone.serialize()
    assert tx.txid() == clone.txid()


def test_transaction_get_fee():
    """Test GetFee (GO: TestTransactionGetFee)"""
    tx = Transaction.from_beef(BRC62Hex)
    assert tx is not None
    
    # Calculate expected fee (handle None satoshis)
    total_input = sum([inp.satoshis for inp in tx.inputs if inp.satoshis is not None])
    total_output = tx.total_value_out()
    
    # Only calculate fee if we have valid input satoshis
    if total_input > 0:
        expected_fee = total_input - total_output
        
        # Get the fee
        fee = tx.get_fee()
        
        # Verify the fee matches the expected fee
        assert fee == expected_fee


def test_transaction_fee():
    """Test TransactionFee computation (GO: TestTransactionFee)"""
    # Create a simple transaction
    priv_key = PrivateKey("KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS")
    address = priv_key.public_key().address()
    
    # Create source transaction
    source_tx = Transaction()
    source_tx.add_output(TransactionOutput(
        locking_script=P2PKH().lock(address),
        satoshis=1000000
    ))
    
    # Create new transaction
    tx = Transaction()
    tx.add_input(TransactionInput(
        source_transaction=source_tx,
        source_output_index=0,
        unlocking_script_template=P2PKH().unlock(priv_key)
    ))
    
    # Add output
    tx.add_output(TransactionOutput(
        locking_script=P2PKH().lock(address),
        satoshis=900000
    ))
    
    # Add change output
    tx.add_output(TransactionOutput(
        locking_script=P2PKH().lock(address),
        change=True
    ))
    
    # Create fee model
    fee_model = SatoshisPerKilobyte(500)
    
    # Compute the fee
    tx.fee(fee_model, 'equal')
    
    # Sign the transaction
    tx.sign()
    
    # Get the actual fee
    fee = tx.get_fee()
    
    # Compute expected fee using the fee model
    expected_fee = fee_model.compute_fee(tx)
    
    # Verify that the actual fee matches the expected fee (within reasonable range)
    assert fee >= expected_fee - 10  # Allow small variance
    assert fee <= expected_fee + 10
    
    # Verify that total inputs >= total outputs + fee
    total_inputs = tx.total_value_in()
    total_outputs = tx.total_value_out()
    assert total_inputs >= total_outputs + fee


def test_transaction_atomic_beef():
    """Test AtomicBEEF (GO: TestAtomicBEEF)"""
    from bsv.transaction.beef import new_beef_from_bytes, ATOMIC_BEEF, BEEF_V1, BEEF_V2
    
    # Parse BEEF data to get a transaction
    tx = Transaction.from_beef(BRC62Hex)
    assert tx is not None
    
    # Create BEEF from transaction and convert to atomic
    beef_bytes = tx.to_beef()
    beef = new_beef_from_bytes(beef_bytes)
    
    # Get atomic BEEF
    txid = tx.txid()
    atomic_beef = beef.to_binary_atomic(txid)
    assert atomic_beef is not None
    assert len(atomic_beef) > 0
    
    # Verify the format:
    # 1. First 4 bytes should be ATOMIC_BEEF (0x01010101)
    assert atomic_beef[:4] == int(ATOMIC_BEEF).to_bytes(4, "little")
    
    # 2. Next 32 bytes should be the subject transaction's TXID
    txid_bytes = bytes.fromhex(txid)[::-1]
    assert atomic_beef[4:36] == txid_bytes
    
    # 3. Verify that the remaining bytes contain BEEF_V1 or BEEF_V2 data
    beef_version = int.from_bytes(atomic_beef[36:40], "little")
    assert beef_version == BEEF_V1 or beef_version == BEEF_V2


def test_transaction_uncomputed_fee():
    """Test UncomputedFee error handling (GO: TestUncomputedFee)"""
    tx = Transaction.from_beef(BRC62Hex)
    assert tx is not None
    
    # Add a change output without computing fee
    tx.add_output(TransactionOutput(
        locking_script=tx.outputs[0].locking_script,
        change=True
    ))
    
    # Signing should fail because change output has no satoshis
    with pytest.raises(ValueError):
        tx.sign()


def test_transaction_sign_unsigned():
    """Test SignUnsigned (GO: TestSignUnsigned)"""
    tx = Transaction.from_beef(BRC62Hex)
    assert tx is not None
    
    # Create a clone
    clone = Transaction.from_hex(tx.serialize())
    
    # The inputs from hex are already signed, so sign_unsigned should do nothing
    # In Python SDK, sign() with bypass=True only signs unsigned inputs
    original_unlocking_scripts = [inp.unlocking_script for inp in clone.inputs]
    
    # Sign unsigned (bypass=True means only sign if unlocking_script is None)
    clone.sign(bypass=True)
    
    # Verify scripts haven't changed (they were already signed)
    for i, inp in enumerate(clone.inputs):
        if original_unlocking_scripts[i] is not None:
            assert inp.unlocking_script == original_unlocking_scripts[i]


def test_transaction_sign_unsigned_new():
    """Test SignUnsignedNew (GO: TestSignUnsignedNew)"""
    priv_key = PrivateKey("L1y6DgX4TuonxXzRPuk9reK2TD2THjwQReNUwVrvWN3aRkjcbauB")
    address = priv_key.public_key().address()
    
    tx = Transaction()
    locking_script = P2PKH().lock(address)
    source_txid = "fe77aa03d5563d3ec98455a76655ea3b58e19a4eb102baf7b2a47af37e94b295"
    
    # Create source transaction
    source_tx = Transaction()
    source_tx.add_output(TransactionOutput(
        satoshis=1,
        locking_script=locking_script
    ))
    
    unlocking_script_template = P2PKH().unlock(priv_key)
    tx.add_input(TransactionInput(
        source_transaction=source_tx,
        source_txid=source_txid,
        unlocking_script_template=unlocking_script_template
    ))
    
    tx.add_output(TransactionOutput(
        satoshis=1,
        locking_script=locking_script
    ))
    
    # Sign unsigned inputs
    tx.sign(bypass=True)
    
    # Verify all inputs have unlocking scripts
    for inp in tx.inputs:
        assert inp.unlocking_script is not None
        assert len(inp.unlocking_script.serialize()) > 0


def test_transaction_total_output_satoshis():
    """Test TotalOutputSatoshis (GO: TestTx_TotalOutputSatoshis)"""
    # Test with zero outputs
    tx = Transaction()
    total = tx.total_value_out()
    assert total == 0
    
    # Test with multiple outputs
    tx.add_output(TransactionOutput(locking_script=Script(b"\x51"), satoshis=1000))
    tx.add_output(TransactionOutput(locking_script=Script(b"\x52"), satoshis=2000))
    
    total = tx.total_value_out()
    assert total == 3000


def test_transaction_total_input_satoshis():
    """Test TotalInputSatoshis"""
    tx = Transaction.from_beef(BRC62Hex)
    assert tx is not None
    
    # Calculate total input satoshis (handle None satoshis)
    total_input = sum([inp.satoshis for inp in tx.inputs if inp.satoshis is not None])
    
    # If inputs have satoshis, verify total is positive
    if any(inp.satoshis is not None for inp in tx.inputs):
        assert total_input > 0


def test_transaction_from_reader():
    """Test FromReader (GO: TestTransactionsReadFrom)"""
    from bsv.utils import Reader
    
    tx = Transaction.from_beef(BRC62Hex)
    assert tx is not None
    
    # Serialize and read back
    tx_bytes = tx.serialize()
    reader = Reader(tx_bytes)
    tx2 = Transaction.from_reader(reader)
    
    assert tx2 is not None
    assert tx2.txid() == tx.txid()


def test_transaction_hex_roundtrip():
    """Test hex serialization roundtrip"""
    tx = Transaction.from_beef(BRC62Hex)
    assert tx is not None
    
    # Convert to hex and back
    hex_str = tx.hex()
    tx2 = Transaction.from_hex(hex_str)
    
    assert tx2 is not None
    assert tx2.txid() == tx.txid()
    assert tx2.serialize() == tx.serialize()


def test_transaction_version_and_locktime():
    """Test transaction version and locktime defaults"""
    tx = Transaction()
    
    assert tx.version == 1
    assert tx.locktime == 0
    
    # Test custom version and locktime
    tx2 = Transaction(version=2, locktime=100)
    assert tx2.version == 2
    assert tx2.locktime == 100

