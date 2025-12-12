from typing import Dict, Any, List, Optional

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_list_outputs_args(args: Dict[str, Any]) -> bytes:  # NOSONAR - Complexity (21), requires refactoring
    w = Writer()
    # basket
    w.write_string(args.get("basket", ""))
    # tags
    tags: Optional[List[str]] = args.get("tags")
    if tags:
        w.write_varint(len(tags))
        for tag in tags:
            w.write_string(tag)
    else:
        w.write_negative_one()
    # tagQueryMode: "all"=1, "any"=2, other=-1
    mode = args.get("tagQueryMode", "")
    if mode == "all":
        w.write_byte(1)
    elif mode == "any":
        w.write_byte(2)
    else:
        w.write_negative_one_byte()
    # include: "locking scripts"=1, "entire transactions"=2, other=-1
    inc = args.get("include", "")
    if inc == "locking scripts":
        w.write_byte(1)
    elif inc == "entire transactions":
        w.write_byte(2)
    else:
        w.write_negative_one_byte()
    # includeCustomInstructions, includeTags, includeLabels (optional bools)
    for opt in ["includeCustomInstructions", "includeTags", "includeLabels"]:
        val = args.get(opt)
        if val is None:
            w.write_negative_one_byte()
        else:
            w.write_byte(1 if val else 0)
    # limit, offset
    w.write_optional_uint32(args.get("limit"))
    w.write_optional_uint32(args.get("offset"))
    # seekPermission
    seek = args.get("seekPermission")
    if seek is None:
        w.write_negative_one_byte()
    else:
        w.write_byte(1 if seek else 0)
    return w.to_bytes()


def deserialize_list_outputs_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    out: Dict[str, Any] = {}
    out["basket"] = r.read_string()
    tcnt = r.read_varint()
    tags: List[str] = []
    if tcnt != (1 << 64) - 1:
        for _ in range(int(tcnt)):
            tags.append(r.read_string())
    out["tags"] = tags
    mode_b = r.read_byte()
    out["tagQueryMode"] = "all" if mode_b == 1 else ("any" if mode_b == 2 else "")
    inc_b = r.read_byte()
    out["include"] = "locking scripts" if inc_b == 1 else ("entire transactions" if inc_b == 2 else "")
    out["includeCustomInstructions"] = None if (b := r.read_byte()) == 0xFF else (b == 1)
    out["includeTags"] = None if (b := r.read_byte()) == 0xFF else (b == 1)
    out["includeLabels"] = None if (b := r.read_byte()) == 0xFF else (b == 1)
    out["limit"] = r.read_optional_uint32()
    out["offset"] = r.read_optional_uint32()
    b2 = r.read_byte()
    out["seekPermission"] = None if b2 == 0xFF else (b2 == 1)
    return out


def serialize_list_outputs_result(result: Dict[str, Any]) -> bytes:
    w = Writer()
    outputs: List[Dict[str, Any]] = result.get("outputs", [])
    w.write_varint(len(outputs))
    _serialize_beef(w, result.get("beef"))
    for out in outputs:
        _serialize_output(w, out)
    return w.to_bytes()

def _serialize_beef(w: Writer, beef: Optional[bytes]):
    """Serialize optional BEEF."""
    if beef is None:
        w.write_negative_one()
    else:
        w.write_int_bytes(beef)

def _serialize_output(w: Writer, out: Dict[str, Any]):
    """Serialize a single output."""
    from bsv.wallet.serializer.common import encode_outpoint
    w.write_bytes(encode_outpoint(out.get("outpoint", {"txid": b"\x00"*32, "index": 0})))
    w.write_varint(int(out.get("satoshis", 0)))
    _serialize_optional_locking_script(w, out.get("lockingScript"))
    _serialize_optional_custom_instructions(w, out.get("customInstructions"))
    _serialize_string_list(w, out.get("tags") or [])
    _serialize_string_list(w, out.get("labels") or [])

def _serialize_optional_locking_script(w: Writer, ls: Optional[bytes]):
    """Serialize optional locking script."""
    if ls is None or ls == b"":
        w.write_negative_one()
    else:
        w.write_int_bytes(ls)

def _serialize_optional_custom_instructions(w: Writer, ci: Optional[str]):
    """Serialize optional custom instructions."""
    if ci is None or ci == "":
        w.write_negative_one()
    else:
        w.write_string(ci)

def _serialize_string_list(w: Writer, items: List[str]):
    """Serialize a list of strings."""
    w.write_varint(len(items))
    for item in items:
        w.write_string(item)


def deserialize_list_outputs_result(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    cnt = r.read_varint()
    beef = _deserialize_beef(r)
    outputs = [_deserialize_output(r) for _ in range(int(cnt))]
    result = {"totalOutputs": int(cnt), "outputs": outputs}
    if beef is not None:
        result["beef"] = beef
    return result

def _deserialize_beef(r: Reader) -> Optional[bytes]:
    """Deserialize optional BEEF."""
    beef_len = r.read_varint()
    if beef_len == (1 << 64) - 1:
        return None
    return r.read_bytes(int(beef_len)) if beef_len > 0 else b""

def _deserialize_output(r: Reader) -> Dict[str, Any]:
    """Deserialize a single output."""
    txid = r.read_bytes_reverse(32)
    idx = r.read_varint()
    satoshis = int(r.read_varint())
    ls_len = r.read_varint()
    lockingScript = b"" if ls_len == (1 << 64) - 1 else r.read_bytes(int(ls_len))  # NOSONAR - camelCase matches wallet wire API
    customInstructions = r.read_string()  # NOSONAR - camelCase matches wallet wire API
    tcnt = r.read_varint()
    tags = [r.read_string() for _ in range(int(tcnt))]
    lcnt = r.read_varint()
    labels = [r.read_string() for _ in range(int(lcnt))]
    return {
        "outpoint": {"txid": txid, "index": int(idx)},
        "satoshis": satoshis,
        "lockingScript": lockingScript,
        "customInstructions": customInstructions,
        "tags": tags,
        "labels": labels,
    }
