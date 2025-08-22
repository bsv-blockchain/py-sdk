from typing import Dict

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_create_action_result(result: Dict) -> bytes:
    """Serialize CreateActionResult with optional metadata.
    Expected shape:
      {
        "signableTransaction": { "tx": bytes, "reference": bytes },
        "error": Optional[str],
      }
    """
    w = Writer()
    stx = result.get("signableTransaction", {})
    tx = stx.get("tx", b"")
    ref = stx.get("reference", b"")
    w.write_int_bytes(tx)
    w.write_int_bytes(ref)
    # optional error string (negative-one for none)
    err = result.get("error")
    if err:
        w.write_string(err)
    else:
        w.write_negative_one()
    return w.to_bytes()


def deserialize_create_action_result(data: bytes) -> Dict:
    r = Reader(data)
    tx = r.read_int_bytes() or b""
    ref = r.read_int_bytes() or b""
    out = {"signableTransaction": {"tx": tx, "reference": ref}}
    # optional error
    try:
        # peek next byte to see if negative-one varint starts; we cannot peek easily, so read string with allowance
        s = r.read_string()
        if s:
            out["error"] = s
    except Exception:
        pass
    return out
