from bsv.wallet.substrates.serializer import (
    serialize_decrypt_args as _serialize_decrypt_args,
    deserialize_decrypt_args as _deserialize_decrypt_args,
    serialize_decrypt_result as _serialize_decrypt_result,
    deserialize_decrypt_result as _deserialize_decrypt_result,
)

def serialize_decrypt_args(args: dict) -> bytes:
    return _serialize_decrypt_args(args)

def deserialize_decrypt_args(data: bytes) -> dict:
    return _deserialize_decrypt_args(data)

def serialize_decrypt_result(result: dict) -> bytes:
    return _serialize_decrypt_result(result)

def deserialize_decrypt_result(data: bytes) -> dict:
    return _deserialize_decrypt_result(data)
