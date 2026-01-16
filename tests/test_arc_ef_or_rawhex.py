import pytest
from unittest.mock import MagicMock
from typing import Union


# テスト対象のクラスとメソッドをモックで再現
class Transaction:
    def __init__(self, inputs=None):
        self.inputs = inputs or []

    def to_ef(self):
        # EFフォーマットに変換するメソッドをモック
        mock = MagicMock()
        mock.hex.return_value = "ef_formatted_hex_data"
        return mock

    def hex(self):
        return "normal_hex_data"


class Input:
    def __init__(self, source_transaction=None):
        self.source_transaction = source_transaction


class BroadcastResponse:
    pass


class BroadcastFailure:
    pass


class TransactionBroadcaster:
    def request_headers(self):
        return {"Content-Type": "application/json"}

    async def broadcast(self, tx: 'Transaction') -> Union[BroadcastResponse, BroadcastFailure]:
        # Check if all inputs have source_transaction
        has_all_source_txs = all(input.source_transaction is not None for input in tx.inputs)
        request_options = {
            "method": "POST",
            "headers": self.request_headers(),
            "data": {
                "rawTx": tx.to_ef().hex() if has_all_source_txs else tx.hex()
            }
        }
        return request_options  # テスト用に結果を返す


# ユニットテスト
@pytest.fixture
def broadcaster():
    return TransactionBroadcaster()


@pytest.mark.asyncio
async def test_all_inputs_have_source_transaction(broadcaster):
    # すべての入力にsource_transactionがある場合
    inputs = [
        Input(source_transaction="tx1"),
        Input(source_transaction="tx2"),
        Input(source_transaction="tx3")
    ]
    tx = Transaction(inputs=inputs)

    result = await broadcaster.broadcast(tx)

    # EFフォーマットが使われていることを確認
    assert result["data"]["rawTx"] == "ef_formatted_hex_data"


@pytest.mark.asyncio
async def test_some_inputs_missing_source_transaction(broadcaster):
    # 一部の入力にsource_transactionがない場合
    inputs = [
        Input(source_transaction="tx1"),
        Input(source_transaction=None),  # source_transactionがない
        Input(source_transaction="tx3")
    ]
    tx = Transaction(inputs=inputs)

    result = await broadcaster.broadcast(tx)

    # 通常のhexフォーマットが使われていることを確認
    assert result["data"]["rawTx"] == "normal_hex_data"


@pytest.mark.asyncio
async def test_no_inputs_have_source_transaction(broadcaster):
    # すべての入力にsource_transactionがない場合
    inputs = [
        Input(source_transaction=None),
        Input(source_transaction=None),
        Input(source_transaction=None)
    ]
    tx = Transaction(inputs=inputs)

    result = await broadcaster.broadcast(tx)

    # 通常のhexフォーマットが使われていることを確認
    assert result["data"]["rawTx"] == "normal_hex_data"