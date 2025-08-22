from typing import Dict, Any, List, Optional

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_list_outputs_args(args: Dict[str, Any]) -> bytes:
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
    # Go互換: totalOutputs, optional BEEF, outputs[{outpoint,satoshis,lockingScript,optCustom, tags, labels}]
    w = Writer()
    outputs: List[Dict[str, Any]] = result.get("outputs", [])
    w.write_varint(len(outputs))
    # BEEF（省略時は -1）
    beef = result.get("beef")
    if beef is None:
        w.write_negative_one()
    else:
        w.write_int_bytes(beef)
    from bsv.wallet.serializer.common import encode_outpoint
    for out in outputs:
        # outpoint
        w.write_bytes(encode_outpoint(out.get("outpoint", {"txid": b"\x00"*32, "index": 0})))
        # satoshis
        w.write_varint(int(out.get("satoshis", 0)))
        # lockingScript optional
        ls = out.get("lockingScript")
        if ls is None or ls == b"":
            w.write_negative_one()
        else:
            w.write_int_bytes(ls)
        # customInstructions optional string
        ci = out.get("customInstructions")
        if ci is None or ci == "":
            w.write_negative_one()
        else:
            w.write_string(ci)
        # tags, labels slices
        tags = out.get("tags") or []
        w.write_varint(len(tags))
        for t in tags:
            w.write_string(t)
        labels = out.get("labels") or []
        w.write_varint(len(labels))
        for l in labels:
            w.write_string(l)
    return w.to_bytes()


def deserialize_list_outputs_result(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    cnt = r.read_varint()
    # BEEF optional
    beef_len = r.read_varint()
    beef = None
    if beef_len != (1 << 64) - 1:
        beef = r.read_bytes(int(beef_len)) if beef_len > 0 else b""
    outputs: List[Dict[str, Any]] = []
    for _ in range(int(cnt)):
        out: Dict[str, Any] = {}
        # outpoint
        txid = r.read_bytes_reverse(32)
        idx = r.read_varint()
        out["outpoint"] = {"txid": txid, "index": int(idx)}
        # amounts and scripts
        out["satoshis"] = int(r.read_varint())
        ls_len = r.read_varint()
        if ls_len == (1 << 64) - 1:
            out["lockingScript"] = b""
        else:
            out["lockingScript"] = r.read_bytes(int(ls_len))
        out["customInstructions"] = r.read_string()
        # tags and labels
        tcnt = r.read_varint()
        out["tags"] = [r.read_string() for _ in range(int(tcnt))]
        lcnt = r.read_varint()
        out["labels"] = [r.read_string() for _ in range(int(lcnt))]
        outputs.append(out)
    result: Dict[str, Any] = {"totalOutputs": int(cnt), "outputs": outputs}
    if beef is not None:
        result["beef"] = beef
    return result
