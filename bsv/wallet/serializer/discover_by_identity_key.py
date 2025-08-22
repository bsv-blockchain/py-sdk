from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer
from .identity_certificate import serialize_identity_certificate, deserialize_identity_certificate_from_reader


def serialize_discover_by_identity_key_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    w.write_bytes(args.get("identityKey", b""))
    w.write_optional_uint32(args.get("limit"))
    w.write_optional_uint32(args.get("offset"))
    w.write_optional_bool(args.get("seekPermission"))
    return w.to_bytes()


def deserialize_discover_by_identity_key_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    return {
        "identityKey": r.read_bytes(33),
        "limit": r.read_optional_uint32(),
        "offset": r.read_optional_uint32(),
        "seekPermission": r.read_optional_bool(),
    }


def serialize_discover_certificates_result(result: Dict[str, Any]) -> bytes:
    w = Writer()
    certs = result.get("certificates", [])
    total = int(result.get("totalCertificates", len(certs)))
    if total != len(certs):
        total = len(certs)
    w.write_varint(total)
    for identity in certs:
        w.write_bytes(serialize_identity_certificate(identity))
    return w.to_bytes()


def deserialize_discover_certificates_result(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    out: Dict[str, Any] = {"certificates": []}
    total = r.read_varint()
    out["totalCertificates"] = int(total)
    for _ in range(int(total)):
        out["certificates"].append(deserialize_identity_certificate_from_reader(r))
    return out
