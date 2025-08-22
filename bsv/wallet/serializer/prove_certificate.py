from typing import Dict, Any, List

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_prove_certificate_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    cert = args.get("certificate", {})
    w.write_bytes(cert.get("type", b""))
    w.write_bytes(cert.get("subject", b""))
    w.write_bytes(cert.get("serialNumber", b""))
    w.write_bytes(cert.get("certifier", b""))
    # revocationOutpoint
    ro = cert.get("revocationOutpoint", {})
    txid = ro.get("txid", b"\x00" * 32)
    w.write_bytes_reverse(txid)
    w.write_varint(int(ro.get("index", 0)))
    # signature
    w.write_int_bytes(cert.get("signature", b""))
    # fields (sorted by key)
    fields: Dict[str, str] = cert.get("fields", {})
    keys = sorted(fields.keys())
    w.write_varint(len(keys))
    for k in keys:
        w.write_int_bytes(k.encode())
        w.write_int_bytes(fields[k].encode())
    # fieldsToReveal
    ftr: List[str] = args.get("fieldsToReveal", [])
    w.write_varint(len(ftr))
    for k in ftr:
        w.write_int_bytes(k.encode())
    # verifier
    w.write_bytes(args.get("verifier", b""))
    # privileged, privilegedReason
    w.write_optional_bool(args.get("privileged"))
    w.write_string(args.get("privilegedReason", ""))
    return w.to_bytes()


def deserialize_prove_certificate_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    cert: Dict[str, Any] = {}
    cert["type"] = r.read_bytes(32)
    cert["subject"] = r.read_bytes(33)
    cert["serialNumber"] = r.read_bytes(32)
    cert["certifier"] = r.read_bytes(33)
    txid = r.read_bytes_reverse(32)
    idx = r.read_varint()
    cert["revocationOutpoint"] = {"txid": txid, "index": int(idx)}
    cert["signature"] = r.read_int_bytes() or b""
    fields: Dict[str, str] = {}
    fcnt = r.read_varint()
    for _ in range(int(fcnt)):
        k = r.read_int_bytes() or b""
        v = r.read_int_bytes() or b""
        fields[k.decode()] = v.decode()
    ftr = []
    ftrcnt = r.read_varint()
    for _ in range(int(ftrcnt)):
        ftr.append((r.read_int_bytes() or b"").decode())
    verifier = r.read_bytes(33)
    out: Dict[str, Any] = {
        "certificate": cert,
        "fieldsToReveal": ftr,
        "verifier": verifier,
        "privileged": r.read_optional_bool(),
        "privilegedReason": r.read_string(),
    }
    return out


def serialize_prove_certificate_result(result: Dict[str, Any]) -> bytes:
    # Simplified: return keyringForVerifier (map) and verifier bytes if provided
    w = Writer()
    kfv = result.get("keyringForVerifier", {})
    w.write_varint(len(kfv))
    for k in sorted(kfv.keys()):
        w.write_int_bytes(k.encode())
        w.write_int_bytes(kfv[k])
    verifier = result.get("verifier", b"")
    w.write_int_bytes(verifier)
    return w.to_bytes()


def deserialize_prove_certificate_result(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    kcnt = r.read_varint()
    kfv: Dict[str, bytes] = {}
    for _ in range(int(kcnt)):
        k = r.read_int_bytes() or b""
        v = r.read_int_bytes() or b""
        kfv[k.decode()] = v
    verifier = r.read_int_bytes() or b""
    return {"keyringForVerifier": kfv, "verifier": verifier}
