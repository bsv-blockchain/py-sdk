from typing import Tuple, Optional


def get_certificate_encryption_details(field_name: str, serial_number: Optional[str]) -> Tuple[dict, str]:
    """
    Returns certificate field encryption metadata compatible with TS/Go.
    - protocol_id: {'protocol': 'certificate field encryption', 'security_level': 1}
    - key_id: If serial_number is present, "{serial_number} {field_name}", otherwise field_name
    """
    protocol_id = {
        "protocol": "certificate field encryption",
        "security_level": 1,
    }
    if serial_number:
        key_id = f"{serial_number} {field_name}"
    else:
        key_id = field_name
    return protocol_id, key_id


