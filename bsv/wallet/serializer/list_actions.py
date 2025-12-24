from typing import Dict, Any, Optional, List

from bsv.wallet.substrates.serializer import Reader, Writer

NEGATIVE_ONE = (1 << 64) - 1

# labelQueryMode: 1=any, 2=all, 0xFF=None


def serialize_list_actions_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    # labels
    w.write_string_slice(args.get("labels"))
    # labelQueryMode
    mode = args.get("labelQueryMode", "")
    if mode == "any":
        w.write_byte(1)
    elif mode == "all":
        w.write_byte(2)
    else:
        w.write_negative_one_byte()
    # include options (6 optional bools)
    for key in [
        "includeLabels",
        "includeInputs",
        "includeInputSourceLockingScripts",
        "includeInputUnlockingScripts",
        "includeOutputs",
        "includeOutputLockingScripts",
    ]:
        w.write_optional_bool(args.get(key))
    # limit, offset, seekPermission
    w.write_optional_uint32(args.get("limit"))
    w.write_optional_uint32(args.get("offset"))
    w.write_optional_bool(args.get("seekPermission"))
    return w.to_bytes()


def deserialize_list_actions_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    out: Dict[str, Any] = {}
    out["labels"] = r.read_string_slice()
    mode_b = r.read_byte()
    if mode_b == 1:
        out["labelQueryMode"] = "any"
    elif mode_b == 2:
        out["labelQueryMode"] = "all"
    else:
        out["labelQueryMode"] = ""
    keys = [
        "includeLabels",
        "includeInputs",
        "includeInputSourceLockingScripts",
        "includeInputUnlockingScripts",
        "includeOutputs",
        "includeOutputLockingScripts",
    ]
    for key in keys:
        out[key] = r.read_optional_bool()
    out["limit"] = r.read_optional_uint32()
    out["offset"] = r.read_optional_uint32()
    out["seekPermission"] = r.read_optional_bool()
    return out


# Result support (per Go): actions list with inputs/outputs
_status_to_code = {
    "completed": 1,
    "unprocessed": 2,
    "sending": 3,
    "unproven": 4,
    "unsigned": 5,
    "no send": 6,
    "non-final": 7,
}
_code_to_status = {v: k for k, v in _status_to_code.items()}


def _encode_outpoint(w: Writer, outpoint: Dict[str, Any]):
    txid = outpoint.get("txid", b"\x00" * 32)
    w.write_bytes_reverse(txid)
    w.write_varint(int(outpoint.get("index", 0)))


def _decode_outpoint(r: Reader) -> Dict[str, Any]:
    txid = r.read_bytes_reverse(32)
    index = r.read_varint()
    return {"txid": txid, "index": int(index)}


def serialize_list_actions_result(result: Dict[str, Any]) -> bytes:
    w = Writer()
    actions: List[Dict[str, Any]] = result.get("actions", [])
    total = int(result.get("totalActions", len(actions)))
    if total != len(actions):
        raise ValueError(f"totalActions {total} does not match actions length {len(actions)}")
    w.write_varint(total)
    for action in actions:
        _serialize_action_metadata(w, action)
        _serialize_action_inputs(w, action.get("inputs", []))
        _serialize_action_outputs(w, action.get("outputs", []))
    return w.to_bytes()

def _serialize_action_metadata(w: Writer, action: Dict[str, Any]):
    """Serialize action metadata (txid, satoshis, status, etc.)."""
    # Basic fields
    txid = action.get("txid", b"\x00" * 32)
    if not isinstance(txid, (bytes, bytearray)) or len(txid) != 32:
        raise ValueError("txid must be 32 bytes")
    w.write_bytes_reverse(txid)
    w.write_varint(int(action.get("satoshis", 0)))
    
    # Status
    status = action.get("status", "")
    w.write_byte(_status_to_code.get(status, _status_to_code.get("unprocessed")))
    
    # Additional metadata
    w.write_optional_bool(action.get("isOutgoing"))
    w.write_string(action.get("description", ""))
    w.write_string_slice(action.get("labels"))
    w.write_varint(int(action.get("version", 0)) & 0xFFFFFFFF)
    w.write_varint(int(action.get("lockTime", 0)) & 0xFFFFFFFF)

def _serialize_action_inputs(w: Writer, inputs: List[Dict[str, Any]]):
    """Serialize action inputs."""
    if not inputs:
        w.write_negative_one()
        return
    
    w.write_varint(len(inputs))
    for inp in inputs:
        _encode_outpoint(w, inp.get("sourceOutpoint", {}))
        w.write_varint(int(inp.get("sourceSatoshis", 0)))
        w.write_int_bytes(inp.get("sourceLockingScript", b""))
        w.write_int_bytes(inp.get("unlockingScript", b""))
        w.write_string(inp.get("inputDescription", ""))
        w.write_varint(int(inp.get("sequenceNumber", 0)) & 0xFFFFFFFF)

def _serialize_action_outputs(w: Writer, outputs: List[Dict[str, Any]]):
    """Serialize action outputs."""
    if not outputs:
        w.write_negative_one()
        return
    
    w.write_varint(len(outputs))
    for out in outputs:
        w.write_varint(int(out.get("outputIndex", 0)) & 0xFFFFFFFF)
        w.write_varint(int(out.get("satoshis", 0)))
        w.write_int_bytes(out.get("lockingScript", b""))
        w.write_optional_bool(out.get("spendable"))
        w.write_string(out.get("outputDescription", ""))
        w.write_string(out.get("basket", ""))
        w.write_string_slice(out.get("tags"))
        ci = out.get("customInstructions")
        if ci is None or ci == "":
            w.write_negative_one()
        else:
            w.write_string(ci)


def deserialize_list_actions_result(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    total = r.read_varint()
    actions = [_deserialize_action(r) for _ in range(int(total))]
    return {"totalActions": int(total), "actions": actions}

def _deserialize_action(r: Reader) -> Dict[str, Any]:
    """Deserialize a single action."""
    action = _deserialize_action_metadata_from_reader(r)
    action["inputs"] = _deserialize_action_inputs(r)
    action["outputs"] = _deserialize_action_outputs(r)
    return action

def _deserialize_action_metadata_from_reader(r: Reader) -> Dict[str, Any]:
    """Deserialize action metadata."""
    txid = r.read_bytes_reverse(32)
    satoshis = int(r.read_varint())
    status_code = r.read_byte()
    b = r.read_byte()
    return {
        "txid": txid,
        "satoshis": satoshis,
        "status": _code_to_status.get(status_code, "unprocessed"),
        "isOutgoing": None if b == 0xFF else (b == 1),
        "description": r.read_string(),
        "labels": r.read_string_slice(),
        "version": int(r.read_varint()),
        "lockTime": int(r.read_varint()),
    }

def _deserialize_action_inputs(r: Reader) -> List[Dict[str, Any]]:
    """Deserialize action inputs."""
    inputs_count = r.read_varint()
    if inputs_count == NEGATIVE_ONE:
        return []
    
    inputs = []
    for _ in range(int(inputs_count)):
        inp = {
            "sourceOutpoint": _decode_outpoint(r),
            "sourceSatoshis": int(r.read_varint()),
            "sourceLockingScript": r.read_int_bytes() or b"",
            "unlockingScript": r.read_int_bytes() or b"",
            "inputDescription": r.read_string(),
            "sequenceNumber": int(r.read_varint()),
        }
        inputs.append(inp)
    return inputs

def _deserialize_action_outputs(r: Reader) -> List[Dict[str, Any]]:
    """Deserialize action outputs."""
    outputs_count = r.read_varint()
    if outputs_count == NEGATIVE_ONE:
        return []
    
    outputs = []
    for _ in range(int(outputs_count)):
        out = {
            "outputIndex": int(r.read_varint()),
            "satoshis": int(r.read_varint()),
            "lockingScript": r.read_int_bytes() or b"",
        }
        b2 = r.read_byte()
        out["spendable"] = None if b2 == 0xFF else (b2 == 1)
        out["outputDescription"] = r.read_string()
        out["basket"] = r.read_string()
        out["tags"] = r.read_string_slice()
        out["customInstructions"] = r.read_string()
        outputs.append(out)
    return outputs
