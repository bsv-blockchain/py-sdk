from typing import Dict, Any, List

from bsv.wallet.substrates.serializer import Reader, Writer
from .identity_certificate import serialize_identity_certificate, deserialize_identity_certificate_from_reader


def serialize_discover_by_attributes_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    attrs: Dict[str, str] = args.get("attributes", {})
    keys = sorted(attrs.keys())
    w.write_varint(len(keys))
    for k in keys:
        w.write_int_bytes(k.encode())
        w.write_int_bytes(attrs[k].encode())
    w.write_optional_uint32(args.get("limit"))
    w.write_optional_uint32(args.get("offset"))
    w.write_optional_bool(args.get("seekPermission"))
    return w.to_bytes()


def deserialize_discover_by_attributes_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    cnt = r.read_varint()
    attrs: Dict[str, str] = {}
    for _ in range(int(cnt)):
        k = (r.read_int_bytes() or b"").decode()
        v = (r.read_int_bytes() or b"").decode()
        attrs[k] = v
    return {
        "attributes": attrs,
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
