from typing import Dict, Any, Optional

from bsv.wallet.substrates.serializer import Reader, Writer

NEGATIVE_ONE = (1 << 64) - 1


def deserialize_sign_action_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    args = {
        "spends": _deserialize_spends(r),
        "reference": r.read_int_bytes() or b"",
    }
    if r.read_byte() == 1:
        args["options"] = _deserialize_sign_options(r)
    return args

def _deserialize_spends(r: Reader) -> Dict[str, Dict[str, Any]]:
    """Deserialize spends map."""
    spends = {}
    spend_count = r.read_varint()
    for _ in range(int(spend_count)):
        input_index = r.read_varint()
        spend = {
            "unlockingScript": r.read_int_bytes() or b"",
        }
        seq_opt = r.read_varint()
        spend["sequenceNumber"] = None if seq_opt == NEGATIVE_ONE else int(seq_opt & 0xFFFFFFFF)
        spends[str(int(input_index))] = spend
    return spends

def _deserialize_sign_options(r: Reader) -> Dict[str, Optional[Any]]:
    """Deserialize sign action options."""
    opts = {}
    for key in ("acceptDelayedBroadcast", "returnTXIDOnly", "noSend"):
        b = r.read_byte()
        opts[key] = None if b == 0xFF else bool(b)
    
    count = r.read_varint()
    opts["sendWith"] = None if count == NEGATIVE_ONE else [r.read_bytes(32).hex() for _ in range(int(count))]
    return opts


def serialize_sign_action_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    _serialize_spends(w, args.get("spends", {}))
    w.write_int_bytes(args.get("reference", b""))
    _serialize_sign_options(w, args.get("options"))
    return w.to_bytes()

def _serialize_spends(w: Writer, spends: Dict[str, Dict[str, Any]]):
    """Serialize spends map."""
    w.write_varint(len(spends))
    for key in sorted(spends.keys(), key=lambda x: int(x)):
        spend = spends[key]
        w.write_varint(int(key))
        w.write_int_bytes(spend.get("unlockingScript", b""))
        seq = spend.get("sequenceNumber")
        if seq is None:
            w.write_negative_one()
        else:
            w.write_varint(int(seq))

def _serialize_sign_options(w: Writer, options: Optional[Dict[str, Any]]):
    """Serialize sign action options."""
    if not options:
        w.write_byte(0)
        return
    
    w.write_byte(1)
    for key in ("acceptDelayedBroadcast", "returnTXIDOnly", "noSend"):
        val = options.get(key)
        if val is None:
            w.write_negative_one_byte()
        else:
            w.write_byte(1 if val else 0)
    
    send_with = options.get("sendWith")
    if send_with is None:
        w.write_negative_one()
    else:
        w.write_varint(len(send_with))
        for txid_hex in send_with:
            w.write_bytes(bytes.fromhex(txid_hex))
