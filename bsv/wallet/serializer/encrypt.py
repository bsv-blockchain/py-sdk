from bsv.wallet.substrates.serializer import (
    deserialize_encrypt_args as _deserialize_encrypt_args,
)
from bsv.wallet.substrates.serializer import (
    deserialize_encrypt_result as _deserialize_encrypt_result,
)
from bsv.wallet.substrates.serializer import (
    serialize_encrypt_args as _serialize_encrypt_args,
)
from bsv.wallet.substrates.serializer import (
    serialize_encrypt_result as _serialize_encrypt_result,
)


def serialize_encrypt_args(args: dict) -> bytes:
    return _serialize_encrypt_args(args)


def deserialize_encrypt_args(data: bytes) -> dict:
    return _deserialize_encrypt_args(data)


def serialize_encrypt_result(result: dict) -> bytes:
    return _serialize_encrypt_result(result)


def deserialize_encrypt_result(data: bytes) -> dict:
    return _deserialize_encrypt_result(data)
