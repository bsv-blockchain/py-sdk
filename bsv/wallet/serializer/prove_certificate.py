from typing import Dict, Any, List

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_prove_certificate_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    _serialize_certificate(w, args.get("certificate", {}))
    _serialize_fields_to_reveal(w, args.get("fieldsToReveal", []))
    w.write_bytes(args.get("verifier", b""))
    w.write_optional_bool(args.get("privileged"))
    w.write_string(args.get("privilegedReason", ""))
    return w.to_bytes()

def _serialize_certificate(w: Writer, cert: Dict[str, Any]):
    """Serialize certificate core fields."""
    w.write_bytes(cert.get("type", b""))
    w.write_bytes(cert.get("subject", b""))
    w.write_bytes(cert.get("serialNumber", b""))
    w.write_bytes(cert.get("certifier", b""))
    _serialize_revocation_outpoint(w, cert.get("revocationOutpoint", {}))
    w.write_int_bytes(cert.get("signature", b""))
    _serialize_fields(w, cert.get("fields", {}))

def _serialize_revocation_outpoint(w: Writer, ro: Dict[str, Any]):
    """Serialize revocation outpoint."""
    txid = ro.get("txid", b"\x00" * 32)
    w.write_bytes_reverse(txid)
    w.write_varint(int(ro.get("index", 0)))

def _serialize_fields(w: Writer, fields: Dict[str, str]):
    """Serialize certificate fields."""
    keys = sorted(fields.keys())
    w.write_varint(len(keys))
    for k in keys:
        w.write_int_bytes(k.encode())
        w.write_int_bytes(fields[k].encode())

def _serialize_fields_to_reveal(w: Writer, ftr: List[str]):
    """Serialize fields to reveal."""
    w.write_varint(len(ftr))
    for k in ftr:
        w.write_int_bytes(k.encode())


def deserialize_prove_certificate_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    return {
        "certificate": _deserialize_certificate(r),
        "fieldsToReveal": _deserialize_fields_to_reveal(r),
        "verifier": r.read_bytes(33),
        "privileged": r.read_optional_bool(),
        "privilegedReason": r.read_string(),
    }

def _deserialize_certificate(r: Reader) -> Dict[str, Any]:
    """Deserialize certificate core fields."""
    cert = {
        "type": r.read_bytes(32),
        "subject": r.read_bytes(33),
        "serialNumber": r.read_bytes(32),
        "certifier": r.read_bytes(33),
        "revocationOutpoint": _deserialize_revocation_outpoint(r),
        "signature": r.read_int_bytes() or b"",
        "fields": _deserialize_fields(r),
    }
    return cert

def _deserialize_revocation_outpoint(r: Reader) -> Dict[str, Any]:
    """Deserialize revocation outpoint."""
    txid = r.read_bytes_reverse(32)
    idx = r.read_varint()
    return {"txid": txid, "index": int(idx)}

def _deserialize_fields(r: Reader) -> Dict[str, str]:
    """Deserialize certificate fields."""
    fcnt = r.read_varint()
    fields = {}
    for _ in range(int(fcnt)):
        k = r.read_int_bytes() or b""
        v = r.read_int_bytes() or b""
        fields[k.decode()] = v.decode()
    return fields

def _deserialize_fields_to_reveal(r: Reader) -> List[str]:
    """Deserialize fields to reveal."""
    ftrcnt = r.read_varint()
    return [(r.read_int_bytes() or b"").decode() for _ in range(int(ftrcnt))]


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
