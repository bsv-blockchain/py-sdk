from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer

# protocol codes
DIRECT = 1
ISSUANCE = 2


def serialize_acquire_certificate_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    # type (32), certifier (33)
    w.write_bytes(args.get("type", b""))
    w.write_bytes(args.get("certifier", b""))
    # fields map (string->string) sorted by key
    fields = args.get("fields", {}) or {}
    keys = sorted(fields.keys())
    w.write_varint(len(keys))
    for k in keys:
        w.write_string(k)
        w.write_string(fields[k])
    # privileged
    w.write_optional_bool(args.get("privileged"))
    w.write_string(args.get("privilegedReason", ""))
    # protocol
    proto = args.get("acquisitionProtocol", "direct")
    if proto == "direct":
        w.write_byte(DIRECT)
        w.write_bytes(args.get("serialNumber", b""))
        # revocation outpoint
        ro = args.get("revocationOutpoint", {})
        txid = ro.get("txid", b"\x00" * 32)
        w.write_bytes_reverse(txid)
        w.write_varint(int(ro.get("index", 0)))
        # signature
        w.write_int_bytes(args.get("signature", b""))
        # keyring revealer
        kr = args.get("keyringRevealer", {})
        if kr.get("certifier"):
            w.write_byte(11)
        else:
            w.write_bytes(kr.get("pubKey", b""))
        # keyring for subject
        kfs = args.get("keyringForSubject", {}) or {}
        kfs_keys = sorted(kfs.keys())
        w.write_varint(len(kfs_keys))
        for k in kfs_keys:
            w.write_string(k)
            # base64 string encoded; for now accept bytes value
            val = kfs[k]
            if isinstance(val, bytes):
                w.write_int_bytes(val)
            else:
                w.write_int_bytes(val.encode())
    else:
        w.write_byte(ISSUANCE)
        w.write_string(args.get("certifierUrl", ""))
    return w.to_bytes()


def deserialize_acquire_certificate_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    out: Dict[str, Any] = {}
    out["type"] = r.read_bytes(32)
    out["certifier"] = r.read_bytes(33)
    flen = r.read_varint()
    fields: Dict[str, str] = {}
    for _ in range(int(flen)):
        k = r.read_string()
        v = r.read_string()
        fields[k] = v
    out["fields"] = fields
    out["privileged"] = r.read_optional_bool()
    out["privilegedReason"] = r.read_string()
    proto = r.read_byte()
    if proto == DIRECT:
        out["acquisitionProtocol"] = "direct"
        out["serialNumber"] = r.read_bytes(32)
        txid = r.read_bytes_reverse(32)
        idx = r.read_varint()
        out["revocationOutpoint"] = {"txid": txid, "index": int(idx)}
        out["signature"] = r.read_int_bytes() or b""
        kr_id = r.read_byte()
        if kr_id == 11:
            out["keyringRevealer"] = {"certifier": True}
        else:
            pub_rest = r.read_bytes(32)
            out["keyringRevealer"] = {"pubKey": bytes([kr_id]) + pub_rest}
        kcnt = r.read_varint()
        kfs: Dict[str, bytes] = {}
        for _ in range(int(kcnt)):
            key = r.read_string()
            val = r.read_int_bytes() or b""
            kfs[key] = val
        out["keyringForSubject"] = kfs
    else:
        out["acquisitionProtocol"] = "issuance"
        out["certifierUrl"] = r.read_string()
    return out
