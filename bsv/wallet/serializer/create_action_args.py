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
    args = {
        "description": r.read_string(),
        "inputBEEF": r.read_optional_bytes(),
    }
    args["inputs"] = _deserialize_inputs(r)
    args["outputs"] = _deserialize_outputs(r)
    args.update(_deserialize_transaction_metadata(r))
    args["options"] = _deserialize_options(r)
    return args

def _deserialize_inputs(r: Reader) -> Optional[List[Dict[str, Any]]]:
    """Deserialize transaction inputs."""
    inputs_len = r.read_varint()
    if inputs_len == NEGATIVE_ONE:
        return None
    
    inputs = []
    for _ in range(inputs_len):
        inp = {"outpoint": _decode_outpoint(r)}
        unlocking = r.read_optional_bytes()
        if unlocking is not None:
            inp["unlockingScript"] = unlocking
            inp["unlockingScriptLength"] = len(unlocking)
        else:
            inp["unlockingScriptLength"] = r.read_varint() & 0xFFFFFFFF
        inp["inputDescription"] = r.read_string()
        inp["sequenceNumber"] = _read_varint_optional_as_uint32(r)
        inputs.append(inp)
    return inputs

def _deserialize_outputs(r: Reader) -> Optional[List[Dict[str, Any]]]:
    """Deserialize transaction outputs."""
    outputs_len = r.read_varint()
    if outputs_len == NEGATIVE_ONE:
        return None
    
    outputs = []
    for _ in range(outputs_len):
        locking = r.read_optional_bytes()
        if locking is None:
            raise ValueError("locking script cannot be nil")
        out = {
            "lockingScript": locking,
            "satoshis": r.read_varint(),
            "outputDescription": r.read_string(),
            "basket": r.read_string(),
            "customInstructions": r.read_string(),
            "tags": r.read_string_slice() if hasattr(r, 'read_string_slice') else None,
        }
        outputs.append(out)
    return outputs

def _deserialize_transaction_metadata(r: Reader) -> Dict[str, Any]:
    """Deserialize transaction metadata."""
    metadata = {
        "lockTime": _read_varint_optional_as_uint32(r),
        "version": _read_varint_optional_as_uint32(r),
    }
    if hasattr(r, 'read_string_slice'):
        metadata["labels"] = r.read_string_slice()
    else:
        labels_count = r.read_varint()
        metadata["labels"] = None if labels_count == NEGATIVE_ONE else [r.read_string() for _ in range(labels_count)]
    return metadata

def _deserialize_options(r: Reader) -> Optional[Dict[str, Any]]:
    """Deserialize action options."""
    options_present = r.read_byte()
    if options_present != 1:
        return None
    
    return {
        "signAndProcess": r.read_optional_bool(),
        "acceptDelayedBroadcast": r.read_optional_bool(),
        "trustSelfFlag": r.read_byte(),
        "knownTxids": _read_txid_slice(r),
        "returnTXIDOnly": r.read_optional_bool(),
        "noSend": r.read_optional_bool(),
        "noSendChangeRaw": r.read_optional_bytes(),
        "sendWith": _read_txid_slice(r),
        "randomizeOutputs": r.read_optional_bool(),
    }


def serialize_create_action_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    
    # Description, InputBEEF
    w.write_string(args.get("description", ""))
    w.write_optional_bytes(args.get("inputBEEF"))
    
    # Serialize main components
    _serialize_inputs(w, args.get("inputs"))
    _serialize_outputs(w, args.get("outputs"))
    _serialize_transaction_metadata(w, args)
    _serialize_options(w, args.get("options"))
    
    return w.to_bytes()

def _serialize_inputs(w: Writer, inputs: Optional[List[Dict[str, Any]]]):
    """Serialize transaction inputs."""
    if inputs is None:
        w.write_negative_one()
        return
    
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

def _serialize_outputs(w: Writer, outputs: Optional[List[Dict[str, Any]]]):
    """Serialize transaction outputs."""
    if outputs is None:
        w.write_negative_one()
        return
    
    w.write_varint(len(outputs))
    for out in outputs:
        w.write_optional_bytes(out.get("lockingScript"))
        w.write_varint(int(out.get("satoshis", 0)))
        w.write_string(out.get("outputDescription", ""))
        w.write_string(out.get("basket", ""))
        w.write_string(out.get("customInstructions", ""))
        
        # Serialize output tags
        labels = out.get("tags")
        if labels is None:
            w.write_negative_one()
        else:
            w.write_varint(len(labels))
            for s in labels:
                w.write_string(s)

def _serialize_transaction_metadata(w: Writer, args: Dict[str, Any]):
    """Serialize transaction metadata (lockTime, version, labels)."""
    # LockTime
    lock_time = args.get("lockTime")
    if hasattr(w, 'write_optional_uint32'):
        w.write_optional_uint32(lock_time)
    else:
        w.write_negative_one() if lock_time is None else w.write_varint(int(lock_time))
    
    # Version
    version = args.get("version")
    if hasattr(w, 'write_optional_uint32'):
        w.write_optional_uint32(version)
    else:
        w.write_negative_one() if version is None else w.write_varint(int(version))
    
    # Labels
    labels = args.get("labels")
    if labels is None:
        w.write_negative_one()
    else:
        w.write_varint(len(labels))
        for s in labels:
            w.write_string(s)

def _serialize_options(w: Writer, options: Optional[Dict[str, Any]]):
    """Serialize action options."""
    if not options:
        w.write_byte(0)
        return
    
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
