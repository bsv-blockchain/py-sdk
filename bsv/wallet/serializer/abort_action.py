from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_abort_action_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    # reference: optional bytes, encoded as IntBytes or negative-one
    ref = args.get("reference")
    if ref is None or ref == b"":
        w.write_negative_one()
    else:
        w.write_int_bytes(ref)
    return w.to_bytes()


def deserialize_abort_action_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    ref = r.read_int_bytes() or b""
    return {"reference": ref}


def serialize_abort_action_result(_: Dict[str, Any]) -> bytes:
    # no payload
    return b""


def deserialize_abort_action_result(_: bytes) -> Dict[str, Any]:
    return {}
