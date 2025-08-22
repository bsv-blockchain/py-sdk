# Re-export serializer APIs from substrates serializer (temporary while migrating)
from bsv.wallet.substrates.serializer import (
    Writer,
    Reader,
    # key related params helpers
    _encode_key_related_params as encode_key_related_params,
    _decode_key_related_params as decode_key_related_params,
    # encrypt/decrypt
    serialize_encrypt_args,
    deserialize_encrypt_args,
    serialize_encrypt_result,
    deserialize_encrypt_result,
    serialize_decrypt_args,
    deserialize_decrypt_args,
    serialize_decrypt_result,
    deserialize_decrypt_result,
)

__all__ = [
    'Writer', 'Reader',
    'encode_key_related_params', 'decode_key_related_params',
    'serialize_encrypt_args', 'deserialize_encrypt_args',
    'serialize_encrypt_result', 'deserialize_encrypt_result',
    'serialize_decrypt_args', 'deserialize_decrypt_args',
    'serialize_decrypt_result', 'deserialize_decrypt_result',
]

# Re-export status helpers for common use
from .status import (
    STATUS_TO_CODE as status_to_code,
    CODE_TO_STATUS as code_to_status,
    write_txid_slice_with_status,
    read_txid_slice_with_status,
)

__all__ += [
    'status_to_code',
    'code_to_status',
    'write_txid_slice_with_status',
    'read_txid_slice_with_status',
]

# Re-export certificate base helpers for convenience
from .certificate import (
    serialize_certificate_base,
    deserialize_certificate_base,
    serialize_certificate,
    deserialize_certificate,
    serialize_certificate_no_signature,
)

__all__ += [
    'serialize_certificate_base',
    'deserialize_certificate_base',
    'serialize_certificate',
    'deserialize_certificate',
    'serialize_certificate_no_signature',
]
