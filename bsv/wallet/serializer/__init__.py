# Re-export serializer APIs from substrates serializer (temporary while migrating)
from bsv.wallet.substrates.serializer import (
    Reader,
    Writer,
    deserialize_decrypt_args,
    deserialize_decrypt_result,
    deserialize_encrypt_args,
    deserialize_encrypt_result,
    serialize_decrypt_args,
    serialize_decrypt_result,
    # encrypt/decrypt
    serialize_encrypt_args,
    serialize_encrypt_result,
)
from bsv.wallet.substrates.serializer import (
    _decode_key_related_params as decode_key_related_params,
)
from bsv.wallet.substrates.serializer import (
    # key related params helpers
    _encode_key_related_params as encode_key_related_params,
)

__all__ = [
    "Reader",
    "Writer",
    "decode_key_related_params",
    "deserialize_decrypt_args",
    "deserialize_decrypt_result",
    "deserialize_encrypt_args",
    "deserialize_encrypt_result",
    "encode_key_related_params",
    "serialize_decrypt_args",
    "serialize_decrypt_result",
    "serialize_encrypt_args",
    "serialize_encrypt_result",
]

# Re-export status helpers for common use
from .status import (
    CODE_TO_STATUS as code_to_status,
)
from .status import (
    STATUS_TO_CODE as status_to_code,
)
from .status import (
    read_txid_slice_with_status,
    write_txid_slice_with_status,
)

__all__ += [
    "code_to_status",
    "read_txid_slice_with_status",
    "status_to_code",
    "write_txid_slice_with_status",
]

# Re-export certificate base helpers for convenience
from .certificate import (
    deserialize_certificate,
    deserialize_certificate_base,
    serialize_certificate,
    serialize_certificate_base,
    serialize_certificate_no_signature,
)

__all__ += [
    "deserialize_certificate",
    "deserialize_certificate_base",
    "serialize_certificate",
    "serialize_certificate_base",
    "serialize_certificate_no_signature",
]
