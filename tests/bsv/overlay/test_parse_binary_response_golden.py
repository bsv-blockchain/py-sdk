"""Golden tests for HTTPSOverlayLookupFacilitator._parse_binary_response.

These pin the binary (``application/octet-stream``) lookup-response format
to the reference TypeScript SDK (``@bsv/sdk`` LookupResolver), which reads::

    varint(nOutpoints)
    per outpoint:  txid (32 bytes) | varint(outputIndex)
                   | varint(contextLength) | context (contextLength bytes)
    trailing:      one combined BEEF holding every referenced transaction

and reconstructs each output's BEEF via ``Transaction.fromBEEF(beef, txid)``.

The Python implementation must do the same: stop crashing on the varint reads
and populate each output's ``beef`` from the trailing combined BEEF, selecting
the subject transaction by txid. The trailing BEEF is a plain combined BEEF and
is exercised here in both V1 and V2 encodings.
"""

import pytest

from bsv.keys import PrivateKey
from bsv.overlay_tools.lookup_resolver import HTTPSOverlayLookupFacilitator
from bsv.script.type import P2PKH
from bsv.transaction import Transaction
from bsv.transaction.beef import BEEF_V2, parse_beef
from bsv.transaction_output import TransactionOutput
from bsv.utils import Writer


def _tx_with_outputs(n: int = 1) -> Transaction:
    addr = PrivateKey().address()
    outputs = [
        TransactionOutput(locking_script=P2PKH().lock(addr), satoshis=1000 - i)
        for i in range(n)
    ]
    return Transaction([], outputs)


def _as_v2(beef_v1: bytes) -> bytes:
    """Re-encode a V1 BEEF blob as V2 (same transactions, newer container)."""
    beef = parse_beef(beef_v1)
    beef.version = BEEF_V2
    return beef.to_binary()


def _build_binary_response(outpoints, trailing_beef: bytes) -> bytes:
    """Serialize the octet-stream lookup response the reference SDK emits.

    ``outpoints`` is a list of ``(txid_hex, output_index, context_bytes_or_none)``.
    """
    writer = Writer()
    writer.write_var_int_num(len(outpoints))
    for txid_hex, output_index, context in outpoints:
        writer.write(bytes.fromhex(txid_hex))  # 32 bytes, display order
        writer.write_var_int_num(output_index)
        context = context or b""
        writer.write_var_int_num(len(context))
        if context:
            writer.write(context)
    writer.write(trailing_beef)
    return writer.to_bytes()


def _assert_output_carries(output, expected_txid: str):
    """Each output's beef must be a real BEEF holding the expected subject tx."""
    assert output.beef, "output.beef must not be empty (BEEF was dropped)"
    recovered = parse_beef(bytes(output.beef))
    assert recovered.find_transaction(expected_txid) is not None


@pytest.mark.parametrize("encode", [lambda b: b, _as_v2], ids=["beef_v1", "beef_v2"])
def test_single_output_roundtrip(encode):
    tx = _tx_with_outputs(1)
    txid = tx.txid()
    trailing = encode(tx.to_beef())
    data = _build_binary_response([(txid, 0, None)], trailing)

    answer = HTTPSOverlayLookupFacilitator()._parse_binary_response(data)

    assert answer.type == "output-list"
    assert len(answer.outputs) == 1
    out = answer.outputs[0]
    assert out.output_index == 0
    assert out.context is None
    _assert_output_carries(out, txid)


@pytest.mark.parametrize("encode", [lambda b: b, _as_v2], ids=["beef_v1", "beef_v2"])
def test_context_is_preserved(encode):
    tx = _tx_with_outputs(1)
    txid = tx.txid()
    trailing = encode(tx.to_beef())
    context = b"\xde\xad\xbe\xef context bytes"
    data = _build_binary_response([(txid, 0, context)], trailing)

    answer = HTTPSOverlayLookupFacilitator()._parse_binary_response(data)

    assert len(answer.outputs) == 1
    assert bytes(answer.outputs[0].context) == context
    _assert_output_carries(answer.outputs[0], txid)


def test_multiple_outputs_same_tx():
    # Two outpoints of the same transaction (different vouts), one trailing BEEF.
    tx = _tx_with_outputs(2)
    txid = tx.txid()
    trailing = tx.to_beef()
    data = _build_binary_response(
        [(txid, 0, None), (txid, 1, b"ctx-1")],
        trailing,
    )

    answer = HTTPSOverlayLookupFacilitator()._parse_binary_response(data)

    assert len(answer.outputs) == 2
    assert [o.output_index for o in answer.outputs] == [0, 1]
    assert answer.outputs[0].context is None
    assert bytes(answer.outputs[1].context) == b"ctx-1"
    for out in answer.outputs:
        _assert_output_carries(out, txid)


def test_empty_output_list():
    # nOutpoints = 0, no trailing BEEF — must not crash and yields no outputs.
    writer = Writer()
    writer.write_var_int_num(0)
    answer = HTTPSOverlayLookupFacilitator()._parse_binary_response(writer.to_bytes())
    assert answer.type == "output-list"
    assert answer.outputs == []
