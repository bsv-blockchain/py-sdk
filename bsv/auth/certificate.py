import base64
from typing import Any, Dict, NamedTuple, Optional

from bsv.keys import PrivateKey, PublicKey
from bsv.utils import Reader, Writer, deserialize_ecdsa_der, hash256, serialize_ecdsa_der, unsigned_to_varint


# Simple representation of Outpoint
class Outpoint(NamedTuple):
    txid: str  # 32byte hex string
    index: int


class Certificate:
    def __init__(
        self,
        cert_type: str,
        serial_number: str,
        subject: PublicKey,
        certifier: PublicKey,
        revocation_outpoint: Optional[Outpoint],
        fields: dict[str, str],
        signature: Optional[bytes] = None,
    ):
        self.type = cert_type  # base64 string
        self.serial_number = serial_number  # base64 string
        self.subject = subject
        self.certifier = certifier
        self.revocation_outpoint = revocation_outpoint
        self.fields = fields  # {field_name: base64_encrypted_value}
        self.signature = signature

    @classmethod
    def from_binary(cls, data: bytes) -> "Certificate":
        r = Reader(data)
        cert_type = base64.b64encode(r.read_bytes(32)).decode()
        serial_number = base64.b64encode(r.read_bytes(32)).decode()
        subject = PublicKey(r.read_bytes(33).hex())
        certifier = PublicKey(r.read_bytes(33).hex())
        txid = r.read_bytes(32).hex()
        index = r.read_uint32_le()
        revocation_outpoint = Outpoint(txid, index)
        num_fields = r.read_var_int_num()
        # Guard against a malformed/hostile field count. The Reader used here is
        # non-strict: read_bytes() past EOF returns b"" instead of raising, so an
        # attacker-supplied varint (up to 2**64-1) would otherwise spin this loop
        # the full declared count on a truncated certificate, exhausting CPU
        # (a DoS primitive for any consumer of this public wire-format parser).
        # Each field needs at least one byte on the wire, so a count larger than
        # the bytes remaining cannot describe a well-formed certificate.
        remaining = len(r.getvalue()) - r.tell()
        if num_fields is None or num_fields < 0 or num_fields > remaining:
            raise ValueError(f"Invalid certificate: field count {num_fields} exceeds {remaining} remaining byte(s)")
        fields = {}
        for _ in range(num_fields):
            name_len = r.read_var_int_num()
            remaining = len(r.getvalue()) - r.tell()
            if name_len is None or name_len < 0 or name_len > remaining:
                raise ValueError(
                    f"Invalid certificate: field name length {name_len} exceeds {remaining} remaining byte(s)"
                )
            name = r.read_bytes(name_len).decode()
            value_len = r.read_var_int_num()
            remaining = len(r.getvalue()) - r.tell()
            if value_len is None or value_len < 0 or value_len > remaining:
                raise ValueError(
                    f"Invalid certificate: field value length {value_len} exceeds {remaining} remaining byte(s)"
                )
            value = r.read_bytes(value_len).decode()
            fields[name] = value
        signature = r.read_bytes(72) if not r.eof() else None
        return cls(cert_type, serial_number, subject, certifier, revocation_outpoint, fields, signature)

    def to_binary(self, include_signature: bool = True) -> bytes:
        w = Writer()
        w.write(base64.b64decode(self.type))
        w.write(base64.b64decode(self.serial_number))
        w.write(bytes.fromhex(self.subject.hex()))
        w.write(bytes.fromhex(self.certifier.hex()))
        w.write(bytes.fromhex(self.revocation_outpoint.txid))
        w.write_uint32_le(self.revocation_outpoint.index)
        w.write_var_int_num(len(self.fields))
        for k, v in self.fields.items():
            k_bytes = k.encode()
            v_bytes = v.encode()
            w.write_var_int_num(len(k_bytes))
            w.write(k_bytes)
            w.write_var_int_num(len(v_bytes))
            w.write(v_bytes)
        if include_signature and self.signature:
            w.write(self.signature)
        return w.to_bytes()

    def verify(self) -> bool:
        if not self.signature:
            raise ValueError("Certificate is not signed.")
        # Exclude signature for verification
        data = self.to_binary(include_signature=False)
        # Use DER signature and certifier public key
        return self.certifier.verify(self.signature, data, hash256)

    def sign(self, certifier_wallet: PrivateKey) -> None:
        if self.signature:
            raise ValueError("Certificate already signed.")
        # Set certifier public key
        self.certifier = certifier_wallet.public_key()
        data = self.to_binary(include_signature=False)
        self.signature = certifier_wallet.sign(data, hash256)
