from typing import Optional, List, Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer

NEGATIVE_ONE = (1 << 64) - 1


def _read_varint_optional_as_uint32(r: Reader) -> Optional[int]:
    val = r.read_varint()
    if val == NEGATIVE_ONE:
        return None
    # clamp to uint32
    return int(val & 0xFFFFFFFF)


def _decode_outpoint(r: Reader) -> Dict[str, Any]:
    # txid is reversed on wire in many places; follow Go's decodeOutpoint
    txid = r.read_bytes_reverse(32)
    index = r.read_varint()
    return {"txid": txid, "index": index}


def _encode_outpoint(w: Writer, outpoint: Dict[str, Any]):
    txid = outpoint.get("txid", b"\x00" * 32)
    index = outpoint.get("index", 0)
    w.write_bytes_reverse(txid)
    w.write_varint(index)


def _read_txid_slice(r: Reader) -> Optional[List[bytes]]:
    count = r.read_varint()
    if count == NEGATIVE_ONE:
        return None
    return [r.read_bytes(32) for _ in range(count)]


def _write_txid_slice(w: Writer, txids: Optional[List[bytes]]):
    if txids is None:
        w.write_negative_one()
        return
    w.write_varint(len(txids))
    for t in txids:
        w.write_bytes(t)


def deserialize_create_action_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    args: Dict[str, Any] = {}

    # Description, InputBEEF
    args["description"] = r.read_string()
    input_beef = r.read_optional_bytes()
    args["inputBEEF"] = input_beef

    # Inputs
    inputs_len = r.read_varint()
    inputs: Optional[List[Dict[str, Any]]] = None
    if inputs_len != NEGATIVE_ONE:
        inputs = []
        for _ in range(inputs_len):
            inp: Dict[str, Any] = {}
            inp["outpoint"] = _decode_outpoint(r)
            unlocking = r.read_optional_bytes()
            if unlocking is not None:
                inp["unlockingScript"] = unlocking
                inp["unlockingScriptLength"] = len(unlocking)
            else:
                inp["unlockingScriptLength"] = r.read_varint() & 0xFFFFFFFF
            inp["inputDescription"] = r.read_string()
            inp["sequenceNumber"] = _read_varint_optional_as_uint32(r)
            inputs.append(inp)
    args["inputs"] = inputs

    # Outputs
    outputs_len = r.read_varint()
    outputs: Optional[List[Dict[str, Any]]] = None
    if outputs_len != NEGATIVE_ONE:
        outputs = []
        for _ in range(outputs_len):
            locking = r.read_optional_bytes()
            if locking is None:
                raise ValueError("locking script cannot be nil")
            out: Dict[str, Any] = {
                "lockingScript": locking,
                "satoshis": r.read_varint(),
                "outputDescription": r.read_string(),
                "basket": r.read_string(),
                "customInstructions": r.read_string(),
                "tags": r.read_string_slice() if hasattr(r, 'read_string_slice') else None,
            }
            outputs.append(out)
    args["outputs"] = outputs

    # LockTime, Version, Labels
    args["lockTime"] = _read_varint_optional_as_uint32(r)
    args["version"] = _read_varint_optional_as_uint32(r)
    # Labels slice (optional -1 allowed)
    if hasattr(r, 'read_string_slice'):
        args["labels"] = r.read_string_slice()
    else:
        # Fallback: manual read
        labels_count = r.read_varint()
        if labels_count == NEGATIVE_ONE:
            args["labels"] = None
        else:
            args["labels"] = [r.read_string() for _ in range(labels_count)]

    # Options
    options_present = r.read_byte()
    options: Optional[Dict[str, Any]] = None
    if options_present == 1:
        options = {}
        # signAndProcess, acceptDelayedBroadcast
        options["signAndProcess"] = r.read_optional_bool()
        options["acceptDelayedBroadcast"] = r.read_optional_bool()
        # trustSelf (single byte flag in Go;ここではraw保持)
        trust_self_flag = r.read_byte()
        options["trustSelfFlag"] = trust_self_flag
        # knownTxids
        options["knownTxids"] = _read_txid_slice(r)
        # returnTXIDOnly, noSend
        options["returnTXIDOnly"] = r.read_optional_bool()
        options["noSend"] = r.read_optional_bool()
        # noSendChange (as outpoints in bytes) 未実装のため raw bytes
        options["noSendChangeRaw"] = r.read_optional_bytes()
        # sendWith, randomizeOutputs
        options["sendWith"] = _read_txid_slice(r)
        options["randomizeOutputs"] = r.read_optional_bool()
    args["options"] = options

    return args


def serialize_create_action_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    # Description, InputBEEF
    w.write_string(args.get("description", ""))
    input_beef = args.get("inputBEEF")
    w.write_optional_bytes(input_beef)

    # Inputs
    inputs = args.get("inputs")
    if inputs is None:
        w.write_negative_one()
    else:
        w.write_varint(len(inputs))
        for inp in inputs:
            _encode_outpoint(w, inp.get("outpoint", {}))
            w.write_optional_bytes(inp.get("unlockingScript"))
            if inp.get("unlockingScript") is None:
                w.write_varint(int(inp.get("unlockingScriptLength", 0)))
            w.write_string(inp.get("inputDescription", ""))
            seq = inp.get("sequenceNumber")
            if seq is None:
                w.write_negative_one()
            else:
                w.write_varint(int(seq))

    # Outputs
    outputs = args.get("outputs")
    if outputs is None:
        w.write_negative_one()
    else:
        w.write_varint(len(outputs))
        for out in outputs:
            w.write_optional_bytes(out.get("lockingScript"))
            w.write_varint(int(out.get("satoshis", 0)))
            w.write_string(out.get("outputDescription", ""))
            w.write_string(out.get("basket", ""))
            w.write_string(out.get("customInstructions", ""))
            labels = out.get("tags")
            if labels is None:
                w.write_negative_one()
            else:
                w.write_varint(len(labels))
                for s in labels:
                    w.write_string(s)

    # LockTime, Version, Labels
    lock_time = args.get("lockTime")
    w.write_optional_uint32(lock_time) if hasattr(w, 'write_optional_uint32') else (
        w.write_negative_one() if lock_time is None else w.write_varint(int(lock_time))
    )
    version = args.get("version")
    w.write_optional_uint32(version) if hasattr(w, 'write_optional_uint32') else (
        w.write_negative_one() if version is None else w.write_varint(int(version))
    )
    labels = args.get("labels")
    if labels is None:
        w.write_negative_one()
    else:
        w.write_varint(len(labels))
        for s in labels:
            w.write_string(s)

    # Options (optional)
    options = args.get("options")
    if options:
        w.write_byte(1)
        # signAndProcess, acceptDelayedBroadcast
        w.write_optional_bool(options.get("signAndProcess"))
        w.write_optional_bool(options.get("acceptDelayedBroadcast"))
        # trustSelf flag (raw byte)
        w.write_byte(int(options.get("trustSelfFlag", 0)))
        # knownTxids
        _write_txid_slice(w, options.get("knownTxids"))
        # returnTXIDOnly, noSend
        w.write_optional_bool(options.get("returnTXIDOnly"))
        w.write_optional_bool(options.get("noSend"))
        # noSendChangeRaw (keep raw)
        w.write_optional_bytes(options.get("noSendChangeRaw"))
        # sendWith, randomizeOutputs
        _write_txid_slice(w, options.get("sendWith"))
        w.write_optional_bool(options.get("randomizeOutputs"))
    else:
        w.write_byte(0)

    return w.to_bytes()
