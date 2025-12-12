from typing import Dict, Any
import base64

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_identity_certificate(identity: Dict[str, Any]) -> bytes:
    w = Writer()
    # Base certificate bytes as IntBytes
    w.write_int_bytes(identity.get("certificateBytes", b""))
    # CertifierInfo
    ci = identity.get("certifierInfo", {})
    w.write_string(ci.get("name", ""))
    w.write_string(ci.get("iconUrl", ""))
    w.write_string(ci.get("description", ""))
    w.write_byte(int(ci.get("trust", 0)) & 0xFF)
    # PubliclyRevealedKeyring (map<string, base64 string>) sorted by key
    keyring: Dict[str, str] = identity.get("publiclyRevealedKeyring", {}) or {}
    keys = sorted(keyring.keys())
    w.write_varint(len(keys))
    for k in keys:
        w.write_string(k)
        try:
            raw = base64.b64decode(keyring[k])
        except Exception:
            raw = b""
        w.write_int_bytes(raw)
    # DecryptedFields (map<string, string>)
    fields: Dict[str, str] = identity.get("decryptedFields", {}) or {}
    w.write_varint(len(fields))
    for k, v in fields.items():
        w.write_string(k)
        w.write_string(v)
    return w.to_bytes()


def deserialize_identity_certificate_from_reader(r: Reader) -> Dict[str, Any]:
    identity: Dict[str, Any] = {}
    # Base certificate bytes
    cert_bytes = r.read_int_bytes() or b""
    identity["certificateBytes"] = cert_bytes
    # CertifierInfo
    ci = {
        "name": r.read_string(),
        "iconUrl": r.read_string(),
        "description": r.read_string(),
        "trust": r.read_byte(),
    }
    identity["certifierInfo"] = ci
    # PubliclyRevealedKeyring
    klen = r.read_varint()
    keyring: Dict[str, str] = {}
    for _ in range(int(klen)):
        k = r.read_string()
        v = r.read_int_bytes() or b""
        keyring[k] = base64.b64encode(v).decode()
    identity["publiclyRevealedKeyring"] = keyring
    # DecryptedFields
    flen = r.read_varint()
    fields: Dict[str, str] = {}
    for _ in range(int(flen)):
        k = r.read_string()
        v = r.read_string()
        fields[k] = v
    identity["decryptedFields"] = fields
    return identity
