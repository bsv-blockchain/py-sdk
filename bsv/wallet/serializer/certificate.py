from typing import Dict, Any

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_certificate_base(cert: Dict[str, Any]) -> bytes:
    """Serialize the certificate base (without signature) to bytes.

    Layout (Go/TS compatible):
    - type: 32 bytes
    - serialNumber: 32 bytes
    - subject: 33 bytes (compressed pubkey)
    - certifier: 33 bytes (compressed pubkey)
    - revocationOutpoint: 32-byte txid LE + varint index
    - fields: map<string,string> sorted by key, each key/value as int-bytes
    """
    w = Writer()
    # Order must match Go: type, serialNumber, subject, certifier
    w.write_bytes(cert.get("type", b""))
    w.write_bytes(cert.get("serialNumber", b""))
    w.write_bytes(cert.get("subject", b""))
    w.write_bytes(cert.get("certifier", b""))
    # Revocation outpoint
    ro = cert.get("revocationOutpoint", {}) or {}
    w.write_bytes_reverse(ro.get("txid", b"\x00" * 32))
    w.write_varint(int(ro.get("index", 0)))
    # Fields (sorted by key)
    fields: Dict[str, str] = cert.get("fields", {}) or {}
    keys = sorted(fields.keys())
    w.write_varint(len(keys))
    for k in keys:
        w.write_int_bytes(k.encode())
        w.write_int_bytes(fields[k].encode())
    return w.to_bytes()


def deserialize_certificate_base(data: bytes) -> Dict[str, Any]:
    """Deserialize bytes into the certificate base (without signature)."""
    r = Reader(data)
    cert: Dict[str, Any] = {}
    cert["type"] = r.read_bytes(32)
    cert["serialNumber"] = r.read_bytes(32)
    cert["subject"] = r.read_bytes(33)
    cert["certifier"] = r.read_bytes(33)
    txid = r.read_bytes_reverse(32)
    idx = r.read_varint()
    cert["revocationOutpoint"] = {"txid": txid, "index": int(idx)}
    # Fields
    fields: Dict[str, str] = {}
    fcnt = r.read_varint()
    for _ in range(int(fcnt)):
        k = r.read_int_bytes() or b""
        v = r.read_int_bytes() or b""
        fields[k.decode()] = v.decode()
    cert["fields"] = fields
    return cert


def serialize_certificate_no_signature(cert: Dict[str, Any]) -> bytes:
    """Alias for serialize_certificate_base for clarity."""
    return serialize_certificate_base(cert)


def serialize_certificate(cert: Dict[str, Any]) -> bytes:
    """Serialize full certificate including trailing signature bytes (no length prefix)."""
    base = bytearray(serialize_certificate_base(cert))
    sig: bytes = cert.get("signature", b"") or b""
    if sig:
        base.extend(sig)
    return bytes(base)


def deserialize_certificate(data: bytes) -> Dict[str, Any]:
    """Deserialize full certificate including optional trailing signature (no length prefix)."""
    # Parse base first
    r = Reader(data)
    cert: Dict[str, Any] = {}
    cert["type"] = r.read_bytes(32)
    cert["serialNumber"] = r.read_bytes(32)
    cert["subject"] = r.read_bytes(33)
    cert["certifier"] = r.read_bytes(33)
    txid = r.read_bytes_reverse(32)
    idx = r.read_varint()
    cert["revocationOutpoint"] = {"txid": txid, "index": int(idx)}
    fields: Dict[str, str] = {}
    fcnt = r.read_varint()
    for _ in range(int(fcnt)):
        k = r.read_int_bytes() or b""
        v = r.read_int_bytes() or b""
        fields[k.decode()] = v.decode()
    cert["fields"] = fields
    # Remaining bytes (if any) are the signature
    remaining = data[r.pos:]
    cert["signature"] = remaining if remaining else b""
    return cert


__all__ = [
    "serialize_certificate_base",
    "deserialize_certificate_base",
    "serialize_certificate_no_signature",
    "serialize_certificate",
    "deserialize_certificate",
]


