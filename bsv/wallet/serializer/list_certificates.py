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
        # keep consistent
        total = len(certificates)
    w.write_varint(total)
    for cert in certificates:
        # certificateBytes required for now
        cert_bytes: bytes = cert.get("certificateBytes", b"")
        w.write_int_bytes(cert_bytes)
        # keyring optional
        keyring: Optional[Dict[str, str]] = cert.get("keyring")
        if keyring:
            w.write_byte(1)
            w.write_varint(len(keyring))
            for k, v in keyring.items():
                w.write_string(k)
                w.write_string(v)
        else:
            w.write_byte(0)
        # verifier optional bytes
        verifier: bytes = cert.get("verifier", b"")
        if verifier:
            w.write_byte(1)
            w.write_int_bytes(verifier)
        else:
            w.write_byte(0)
    return w.to_bytes()


def deserialize_list_certificates_result(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    out: Dict[str, Any] = {"certificates": []}
    total = r.read_varint()
    out["totalCertificates"] = int(total)
    for _ in range(int(total)):
        cert_bytes = r.read_int_bytes() or b""
        item: Dict[str, Any] = {"certificateBytes": cert_bytes}
        # keyring presence
        if r.read_byte() == 1:
            kcnt = r.read_varint()
            keyring: Dict[str, str] = {}
            for _i in range(int(kcnt)):
                k = r.read_string()
                v = r.read_string()
                keyring[k] = v
            item["keyring"] = keyring
        # verifier presence
        if r.read_byte() == 1:
            item["verifier"] = r.read_int_bytes() or b""
        out["certificates"].append(item)
    return out
