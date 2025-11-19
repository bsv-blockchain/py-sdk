"""
Common serialization utilities for discovery certificate results.
"""
from typing import Dict, Any
from bsv.wallet.substrates.serializer import Reader, Writer
from .identity_certificate import serialize_identity_certificate, deserialize_identity_certificate_from_reader


def serialize_discover_certificates_result(result: Dict[str, Any]) -> bytes:
    """
    Serialize discovery certificates result.
    
    Args:
        result: Dict with 'certificates' list and optional 'totalCertificates' count
        
    Returns:
        Serialized bytes
    """
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
    """
    Deserialize discovery certificates result.
    
    Args:
        data: Serialized bytes
        
    Returns:
        Dict with 'totalCertificates' and 'certificates' list
    """
    r = Reader(data)
    out: Dict[str, Any] = {"certificates": []}
    total = r.read_varint()
    out["totalCertificates"] = int(total)
    for _ in range(int(total)):
        out["certificates"].append(deserialize_identity_certificate_from_reader(r))
    return out

