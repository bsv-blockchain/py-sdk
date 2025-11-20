from typing import Dict, Any, List, Optional

from bsv.wallet.substrates.serializer import Reader, Writer

NEGATIVE_ONE = (1 << 64) - 1


def serialize_list_certificates_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    # certifiers: list of 33-byte compressed pubkeys
    certifiers: Optional[List[bytes]] = args.get("certifiers")
    if certifiers is None:
        w.write_varint(0)
    else:
        w.write_varint(len(certifiers))
        for c in certifiers:
            w.write_bytes(c)
    # types: list of 32-byte
    types: Optional[List[bytes]] = args.get("types")
    if types is None:
        w.write_varint(0)
    else:
        w.write_varint(len(types))
        for t in types:
            w.write_bytes(t)
    # limit, offset
    w.write_optional_uint32(args.get("limit"))
    w.write_optional_uint32(args.get("offset"))
    # privileged, privilegedReason
    w.write_optional_bool(args.get("privileged"))
    w.write_string(args.get("privilegedReason", ""))
    return w.to_bytes()


def deserialize_list_certificates_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    out: Dict[str, Any] = {}
    # certifiers
    cnt = r.read_varint()
    certs: List[bytes] = []
    for _ in range(int(cnt)):
        certs.append(r.read_bytes(33))
    out["certifiers"] = certs
    # types
    tcnt = r.read_varint()
    types: List[bytes] = []
    for _ in range(int(tcnt)):
        types.append(r.read_bytes(32))
    out["types"] = types
    out["limit"] = r.read_optional_uint32()
    out["offset"] = r.read_optional_uint32()
    out["privileged"] = r.read_optional_bool()
    out["privilegedReason"] = r.read_string()
    return out


def serialize_list_certificates_result(result: Dict[str, Any]) -> bytes:
    w = Writer()
    certificates: List[Dict[str, Any]] = result.get("certificates", [])
    total = int(result.get("totalCertificates", len(certificates)))
    if total != len(certificates):
        total = len(certificates)
    w.write_varint(total)
    for cert in certificates:
        _serialize_certificate(w, cert)
    return w.to_bytes()

def _serialize_certificate(w: Writer, cert: Dict[str, Any]):
    """Serialize a single certificate."""
    w.write_int_bytes(cert.get("certificateBytes", b""))
    _serialize_keyring(w, cert.get("keyring"))
    _serialize_verifier(w, cert.get("verifier", b""))

def _serialize_keyring(w: Writer, keyring: Optional[Dict[str, str]]):
    """Serialize certificate keyring."""
    if keyring:
        w.write_byte(1)
        w.write_varint(len(keyring))
        for k, v in keyring.items():
            w.write_string(k)
            w.write_string(v)
    else:
        w.write_byte(0)

def _serialize_verifier(w: Writer, verifier: bytes):
    """Serialize certificate verifier."""
    if verifier:
        w.write_byte(1)
        w.write_int_bytes(verifier)
    else:
        w.write_byte(0)


def deserialize_list_certificates_result(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    total = r.read_varint()
    certificates = [_deserialize_certificate(r) for _ in range(int(total))]
    return {"totalCertificates": int(total), "certificates": certificates}

def _deserialize_certificate(r: Reader) -> Dict[str, Any]:
    """Deserialize a single certificate."""
    item = {"certificateBytes": r.read_int_bytes() or b""}
    if r.read_byte() == 1:
        item["keyring"] = _deserialize_keyring(r)
    if r.read_byte() == 1:
        item["verifier"] = r.read_int_bytes() or b""
    return item

def _deserialize_keyring(r: Reader) -> Dict[str, str]:
    """Deserialize certificate keyring."""
    kcnt = r.read_varint()
    return {r.read_string(): r.read_string() for _ in range(int(kcnt))}
