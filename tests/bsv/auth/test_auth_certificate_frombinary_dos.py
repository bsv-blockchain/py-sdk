import base64

import pytest

from bsv.auth.certificate import Certificate, Outpoint
from bsv.keys import PrivateKey
from bsv.utils import Writer


def _valid_header_bytes() -> bytes:
    """Build the fixed 166-byte Certificate header (everything before the
    field-count varint): type(32) + serial(32) + subject(33) + certifier(33)
    + txid(32) + index(4). Real compressed public keys are used so that
    from_binary() parses the header successfully and reaches the field loop.
    """
    w = Writer()
    w.write(b"A" * 32)  # cert type
    w.write(b"B" * 32)  # serial number
    w.write(bytes.fromhex(PrivateKey(10).public_key().hex()))  # subject (33)
    w.write(bytes.fromhex(PrivateKey(11).public_key().hex()))  # certifier (33)
    w.write(b"\x00" * 32)  # revocation txid
    w.write_uint32_le(1)  # revocation index
    header = w.to_bytes()
    assert len(header) == 166
    return header


def test_from_binary_rejects_unbounded_field_count():
    """A crafted certificate that declares a huge field count but carries no
    field data must be rejected promptly, not looped the full declared count.

    The parser uses the non-strict bsv.utils.Reader whose read_bytes() past EOF
    returns b"" (and b"".decode() == "") instead of raising. Without a bound,
    ``for _ in range(num_fields)`` spins the full attacker-controlled count on a
    truncated blob -- a CPU-exhaustion DoS for any consumer that deserializes a
    peer-supplied certificate via the public BRC-52/103 binary wire format.

    5_000_000 is large enough that the unguarded loop would run millions of
    iterations (observable pre-fix); the guard turns it into an immediate
    ValueError, so this test stays fast and deterministic and never hangs.
    """
    num_fields = 5_000_000
    blob = _valid_header_bytes() + b"\xfe" + num_fields.to_bytes(4, "little")

    # num_fields vastly exceeds the bytes available for field data (zero here),
    # so no well-formed certificate could declare it.
    assert num_fields > len(blob)

    with pytest.raises(ValueError):
        Certificate.from_binary(blob)


def test_from_binary_rejects_oversized_field_name_length():
    """Symmetric guard: a declared field name length larger than the remaining
    bytes must be rejected rather than silently reading a truncated/empty name.
    """
    # Declare exactly one field, then a name length far beyond the data present.
    blob = _valid_header_bytes() + b"\x01" + b"\xfe" + (1_000_000).to_bytes(4, "little")

    with pytest.raises(ValueError):
        Certificate.from_binary(blob)


def test_from_binary_still_parses_valid_certificate():
    """The bound must not alter behaviour for well-formed certificates."""
    cert_type = base64.b64encode(b"A" * 32).decode()
    serial = base64.b64encode(b"B" * 32).decode()
    cert = Certificate(
        cert_type,
        serial,
        PrivateKey(10).public_key(),
        PrivateKey(11).public_key(),
        Outpoint(txid=("00" * 32), index=1),
        {
            "name": base64.b64encode(b"Alice").decode(),
            "email": base64.b64encode(b"alice@example.com").decode(),
        },
        signature=None,
    )
    parsed = Certificate.from_binary(cert.to_binary(include_signature=False))
    assert parsed.fields == cert.fields
    assert parsed.type == cert.type
    assert parsed.serial_number == cert.serial_number
