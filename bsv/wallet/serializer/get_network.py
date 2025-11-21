from typing import Dict, Any, Optional

from bsv.wallet.substrates.serializer import Reader, Writer


def serialize_get_network_args(_: Optional[Dict[str, Any]] = None) -> bytes:
    return b""


def deserialize_get_network_result(data: bytes) -> Dict[str, Any]:
    # Minimal: network as string
    r = Reader(data)
    return {"network": r.read_string() if not r.is_complete() else ""}

def serialize_get_network_result(result: Dict[str, Any]) -> bytes:
    w = Writer()
    w.write_string(str(result.get("network", "")))
    return w.to_bytes()


def serialize_get_version_args(_: Optional[Dict[str, Any]] = None) -> bytes:
    return b""


def deserialize_get_version_result(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    return {"version": r.read_string() if not r.is_complete() else ""}

def serialize_get_version_result(result: Dict[str, Any]) -> bytes:
    w = Writer()
    w.write_string(str(result.get("version", "")))
    return w.to_bytes()


def serialize_get_height_args(_: Optional[Dict[str, Any]] = None) -> bytes:
    return b""


def deserialize_get_height_result(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    return {"height": int(r.read_varint()) if not r.is_complete() else 0}

def serialize_get_height_result(result: Dict[str, Any]) -> bytes:
    w = Writer()
    w.write_varint(int(result.get("height", 0)))
    return w.to_bytes()


def serialize_get_header_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    w.write_varint(int(args.get("height", 0)))
    return w.to_bytes()

def deserialize_get_header_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    return {"height": int(r.read_varint()) if not r.is_complete() else 0}


def deserialize_get_header_result(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    # Minimal: header raw bytes
    return {"header": r.read_int_bytes() or b""}

def serialize_get_header_result(result: Dict[str, Any]) -> bytes:
    w = Writer()
    w.write_int_bytes(result.get("header", b""))
    return w.to_bytes()
