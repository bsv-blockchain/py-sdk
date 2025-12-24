from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_relinquish_output_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    # basket
    w.write_string(args.get("basket", ""))
    # outpoint: encode as <txidLE><index>
    from bsv.wallet.serializer.common import encode_outpoint
    w.write_bytes(encode_outpoint(args.get("output", "")))
    return w.to_bytes()


def deserialize_relinquish_output_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    basket = r.read_string()
    txid = r.read_bytes_reverse(32)
    idx = r.read_varint()
    return {"basket": basket, "output": {"txid": txid, "index": int(idx)}}


def serialize_relinquish_output_result(_: Dict[str, Any]) -> bytes:
    return b""


def deserialize_relinquish_output_result(_: bytes) -> Dict[str, Any]:
    return {}
