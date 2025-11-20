"""
JSONシリアライゼーションテスト
GO SDKのtxjson_test.goを参考に実装
"""
import pytest
import json
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
from bsv.keys import PrivateKey
from bsv.script.type import P2PKH, OpReturn
from bsv.script.script import Script


def test_tx_json_standard():
    """Test standard tx should marshal and unmarshal correctly (GO: TestTx_JSON)"""
    priv = PrivateKey("KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS")
    assert priv  # Verify object creation succeeds
    
    unlocker = P2PKH().unlock(priv)
    tx = Transaction()
    
    # Add input
    locking_script = Script(bytes.fromhex("76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac"))
    tx_input = TransactionInput(
        source_txid="3c8edde27cb9a9132c22038dac4391496be9db16fd21351565cc1006966fdad5",
        source_output_index=0,
        unlocking_script_template=unlocker,
    )
    tx_input.satoshis = 2000000
    tx_input.locking_script = locking_script
    tx.add_input(tx_input)
    
    # Add output
    address = priv.public_key().address()
    lock = P2PKH().lock(address)
    tx.add_output(TransactionOutput(
        locking_script=lock,
        satoshis=1000,
    ))
    
    # Sign
    tx.sign()
    
    # Test JSON serialization
    json_str = tx.to_json()
    assert json_str is not None
    assert len(json_str) > 0
    
    # Test JSON deserialization
    tx_from_json = Transaction.from_json(json_str)
    assert tx_from_json is not None
    assert tx_from_json.txid() == tx.txid()
    assert tx_from_json.hex() == tx.hex()


def test_tx_json_data_tx():
    """Test data tx should marshall correctly (GO: TestTx_JSON)"""
    priv = PrivateKey("KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS")
    assert priv is not None
    
    unlocker = P2PKH().unlock(priv)
    tx = Transaction()
    
    # Add input
    locking_script = Script(bytes.fromhex("76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac"))
    tx_input = TransactionInput(
        source_txid="3c8edde27cb9a9132c22038dac4391496be9db16fd21351565cc1006966fdad5",
        source_output_index=0,
        unlocking_script_template=unlocker,
    )
    tx_input.satoshis = 2000000
    tx_input.locking_script = locking_script
    tx.add_input(tx_input)
    
    # Add OP_RETURN output
    op_return = OpReturn()
    script = op_return.lock([b"test"])
    tx.add_output(TransactionOutput(
        locking_script=script,
        satoshis=1000,
    ))
    
    # Sign
    tx.sign()
    
    # Test JSON serialization
    json_str = tx.to_json()
    assert json_str is not None
    
    # Test JSON deserialization
    tx_from_json = Transaction.from_json(json_str)
    assert tx_from_json is not None
    assert tx_from_json.txid() == tx.txid()


def test_tx_marshal_json():
    """Test transaction with 1 input 1 p2pksh output 1 data output should create valid json (GO: TestTx_MarshallJSON)"""
    tx_hex = "0100000001abad53d72f342dd3f338e5e3346b492440f8ea821f8b8800e318f461cc5ea5a2010000006a4730440220042edc1302c5463e8397120a56b28ea381c8f7f6d9bdc1fee5ebca00c84a76e2022077069bbdb7ed701c4977b7db0aba80d41d4e693112256660bb5d674599e390cf41210294639d6e4249ea381c2e077e95c78fc97afe47a52eb24e1b1595cd3fdd0afdf8ffffffff02000000000000000008006a0548656c6c6f7f030000000000001976a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac00000000"
    tx = Transaction.from_hex(tx_hex)
    assert tx is not None
    
    json_str = tx.to_json()
    json_dict = json.loads(json_str)
    
    # Verify expected fields
    assert "txid" in json_dict
    assert "hex" in json_dict
    assert "inputs" in json_dict
    assert "outputs" in json_dict
    assert "version" in json_dict
    assert "lockTime" in json_dict
    
    # Verify expected txid
    assert json_dict["txid"] == "aec245f27b7640c8b1865045107731bfb848115c573f7da38166074b1c9e475d"
    
    # Verify inputs
    assert len(json_dict["inputs"]) == 1
    assert json_dict["inputs"][0]["vout"] == 1
    
    # Verify outputs
    assert len(json_dict["outputs"]) == 2
    assert json_dict["outputs"][0]["satoshis"] == 0
    assert json_dict["outputs"][1]["satoshis"] == 895


def test_tx_unmarshal_json():
    """Test our json with hex should map correctly (GO: TestTx_UnmarshalJSON)"""
    json_str = """{
        "version": 1,
        "lockTime": 0,
        "hex": "0100000001abad53d72f342dd3f338e5e3346b492440f8ea821f8b8800e318f461cc5ea5a2010000006a4730440220042edc1302c5463e8397120a56b28ea381c8f7f6d9bdc1fee5ebca00c84a76e2022077069bbdb7ed701c4977b7db0aba80d41d4e693112256660bb5d674599e390cf41210294639d6e4249ea381c2e077e95c78fc97afe47a52eb24e1b1595cd3fdd0afdf8ffffffff02000000000000000008006a0548656c6c6f7f030000000000001976a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac00000000",
        "inputs": [
            {
                "unlockingScript":"4730440220042edc1302c5463e8397120a56b28ea381c8f7f6d9bdc1fee5ebca00c84a76e2022077069bbdb7ed701c4977b7db0aba80d41d4e693112256660bb5d674599e390cf41210294639d6e4249ea381c2e077e95c78fc97afe47a52eb24e1b1595cd3fdd0afdf8",
                "txid": "a2a55ecc61f418e300888b1f82eaf84024496b34e3e538f3d32d342fd753adab",
                "vout": 1,
                "sequence": 4294967295
            }
        ],
        "vout": [
            {
                "satoshis": 0,
                "lockingScript": "006a0548656c6c6f"
            },
            {
                "satoshis": 895,
                "lockingScript":"76a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac"
            }
        ]
    }"""
    
    tx = Transaction.from_json(json_str)
    assert tx is not None
    
    expected_tx_hex = "0100000001abad53d72f342dd3f338e5e3346b492440f8ea821f8b8800e318f461cc5ea5a2010000006a4730440220042edc1302c5463e8397120a56b28ea381c8f7f6d9bdc1fee5ebca00c84a76e2022077069bbdb7ed701c4977b7db0aba80d41d4e693112256660bb5d674599e390cf41210294639d6e4249ea381c2e077e95c78fc97afe47a52eb24e1b1595cd3fdd0afdf8ffffffff02000000000000000008006a0548656c6c6f7f030000000000001976a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac00000000"
    assert tx.hex() == expected_tx_hex

