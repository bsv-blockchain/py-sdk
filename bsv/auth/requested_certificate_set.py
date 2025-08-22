import base64
import json
from typing import Dict, List, Optional, Any
from bsv.keys import PublicKey

# Type alias for a 32-byte certificate type identifier (bytes)
CertificateType = bytes  # Should be 32 bytes

class RequestedCertificateTypeIDAndFieldList:
    """
    Maps certificate type IDs (32-byte) to required field names (list of str).
    Handles base64 encoding for JSON keys to match Go implementation.
    """
    def __init__(self, mapping: Optional[Dict[CertificateType, List[str]]] = None):
        self.mapping: Dict[CertificateType, List[str]] = mapping or {}

    def to_json_dict(self) -> Dict[str, List[str]]:
        # Keys are base64-encoded 32-byte values
        return {base64.b64encode(k).decode('ascii'): v for k, v in self.mapping.items()}

    @classmethod
    def from_json_dict(cls, d: Dict[str, List[str]]):
        mapping = {}
        for k, v in d.items():
            decoded = base64.b64decode(k)
            if len(decoded) != 32:
                raise ValueError(f"Expected 32 bytes for certificate type, got {len(decoded)}")
            mapping[decoded] = v
        return cls(mapping)

    def __getitem__(self, key: CertificateType) -> List[str]:
        return self.mapping[key]

    def __setitem__(self, key: CertificateType, value: List[str]):
        self.mapping[key] = value

    def __contains__(self, key: CertificateType) -> bool:
        return key in self.mapping

    def __len__(self):
        return len(self.mapping)

    def items(self):
        return self.mapping.items()

    def is_empty(self):
        return len(self.mapping) == 0

# --- Helper functions ---
def certifier_in_list(certifiers: List[PublicKey], certifier: Optional[PublicKey]) -> bool:
    """
    Checks if the given certifier is in the list of certifiers.
    None is always False.
    """
    if certifier is None:
        return False
    return any(certifier == c for c in certifiers)

def is_empty_public_key(key: Optional[PublicKey]) -> bool:
    """
    Checks if a PublicKey is empty/uninitialized.
    Returns True if key is None or its internal byte array is all zeros.
    """
    if key is None:
        return True
    try:
        serialized = key.serialize()
        return all(b == 0 for b in serialized)
    except Exception:
        return True

class RequestedCertificateSet:
    """
    Represents a set of requested certificates.
    - certifiers: list of PublicKey (must have signed the certificates)
    - certificate_types: RequestedCertificateTypeIDAndFieldList
    """
    def __init__(self, certifiers: Optional[List[PublicKey]] = None, certificate_types: Optional[RequestedCertificateTypeIDAndFieldList] = None):
        self.certifiers: List[PublicKey] = certifiers or []
        self.certificate_types: RequestedCertificateTypeIDAndFieldList = certificate_types or RequestedCertificateTypeIDAndFieldList()

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            'certifiers': [pk.hex() for pk in self.certifiers],
            'certificateTypes': self.certificate_types.to_json_dict(),
        }

    @classmethod
    def from_json_dict(cls, d: Dict[str, Any]):
        certifiers = [PublicKey(pk_hex) for pk_hex in d.get('certifiers', [])]
        certificate_types = RequestedCertificateTypeIDAndFieldList.from_json_dict(d.get('certificateTypes', {}))
        return cls(certifiers, certificate_types)

    def to_json(self) -> str:
        return json.dumps(self.to_json_dict())

    @classmethod
    def from_json(cls, s: str):
        return cls.from_json_dict(json.loads(s))

    def validate(self):
        if not self.certifiers:
            raise ValueError("certifiers list is empty")
        if self.certificate_types.is_empty():
            raise ValueError("certificate types map is empty")
        for cert_type, fields in self.certificate_types.items():
            if not cert_type or len(cert_type) != 32:
                raise ValueError("empty or invalid certificate type specified")
            if not fields:
                raise ValueError(f"no fields specified for certificate type: {base64.b64encode(cert_type).decode('ascii')}")
        # Addition: Check if the certifiers list contains any uninitialized public keys
        for c in self.certifiers:
            if is_empty_public_key(c):
                raise ValueError("certifiers list contains an empty/uninitialized public key")

    def certifier_in_set(self, certifier: Optional[PublicKey]) -> bool:
        """
        Checks if the given certifier is in the set's certifiers list (using the helper).
        """
        return certifier_in_list(self.certifiers, certifier)

    def __repr__(self):
        return f"<RequestedCertificateSet(certifiers={self.certifiers}, certificate_types={self.certificate_types.mapping})>"