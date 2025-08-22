from typing import Dict, Any, Optional

from bsv.wallet.substrates.serializer import Reader, Writer

NEGATIVE_ONE = (1 << 64) - 1


def deserialize_sign_action_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    args: Dict[str, Any] = {"spends": {}}

    spend_count = r.read_varint()
    for _ in range(int(spend_count)):
        input_index = r.read_varint()
        spend: Dict[str, Any] = {}
        spend["unlockingScript"] = r.read_int_bytes() or b""
        # Optional uint32
        seq_opt = r.read_varint()
        if seq_opt == NEGATIVE_ONE:
            spend["sequenceNumber"] = None
        else:
            spend["sequenceNumber"] = int(seq_opt & 0xFFFFFFFF)
        args["spends"][str(int(input_index))] = spend

    args["reference"] = r.read_int_bytes() or b""

    options_present = r.read_byte()
    if options_present == 1:
        opts: Dict[str, Optional[Any]] = {}
        # AcceptDelayedBroadcast, ReturnTXIDOnly, NoSend (optional bools)
        for key in ("acceptDelayedBroadcast", "returnTXIDOnly", "noSend"):
            b = r.read_byte()
            if b == 0xFF:
                opts[key] = None
            else:
                opts[key] = bool(b)
        # sendWith slice
        count = r.read_varint()
        if count == NEGATIVE_ONE:
            opts["sendWith"] = None
        else:
            opts["sendWith"] = [r.read_bytes(32).hex() for _ in range(int(count))]
        args["options"] = opts
    return args


def serialize_sign_action_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    spends: Dict[str, Dict[str, Any]] = args.get("spends", {})
    # Serialize spends map count
    w.write_varint(len(spends))
    # Keys must be numeric and sorted
    for key in sorted(spends.keys(), key=lambda x: int(x)):
        spend = spends[key]
        w.write_varint(int(key))
        w.write_int_bytes(spend.get("unlockingScript", b""))
        seq = spend.get("sequenceNumber")
        if seq is None:
            w.write_negative_one()
        else:
            w.write_varint(int(seq))
    # Reference
    w.write_int_bytes(args.get("reference", b""))

    options = args.get("options")
    if options:
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
    else:
        w.write_byte(0)

    return w.to_bytes()
