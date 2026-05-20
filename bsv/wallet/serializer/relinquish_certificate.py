from typing import Any, Optional

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_relinquish_certificate_args(args: dict[str, Any]) -> bytes:
    w = Writer()
    w.write_bytes(args.get("type", b""))  # 32 bytes
    w.write_bytes(args.get("serialNumber", b""))  # 32 bytes
    w.write_bytes(args.get("certifier", b""))  # 33 bytes
    return w.to_bytes()


def deserialize_relinquish_certificate_args(data: bytes) -> dict[str, Any]:
    r = Reader(data)
    return {
        "type": r.read_bytes(32),
        "serialNumber": r.read_bytes(32),
        "certifier": r.read_bytes(33),
    }


def serialize_relinquish_certificate_result(_: Optional[dict[str, Any]]) -> bytes:
    # No additional payload
    return b""


def deserialize_relinquish_certificate_result(_: bytes) -> dict[str, Any]:
    return {}
