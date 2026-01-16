from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, TypedDict, Union

DefinitionType = Literal["basket", "protocol", "certificate"]


class CertificateFieldDescriptor(TypedDict):
    friendlyName: str
    description: str
    type: Literal["text", "imageURL", "other"]
    fieldIcon: str


@dataclass
class BasketDefinitionData:  # NOSONAR - camelCase matches TS/Go registry API
    definition_type: Literal["basket"]
    basket_id: str
    name: str
    icon_url: str
    description: str
    documentation_url: str
    registry_operator: str | None = None


@dataclass
class ProtocolDefinitionData:  # NOSONAR - camelCase matches TS/Go registry API
    definition_type: Literal["protocol"]
    protocol_id: dict[str, Any]  # WalletProtocol-like: {securityLevel, protocol}
    name: str
    icon_url: str
    description: str
    documentation_url: str
    registry_operator: str | None = None


@dataclass
class CertificateDefinitionData:  # NOSONAR - camelCase matches TS/Go registry API
    definition_type: Literal["certificate"]
    type: str
    name: str
    icon_url: str
    description: str
    documentation_url: str
    fields: dict[str, CertificateFieldDescriptor]
    registry_operator: str | None = None


DefinitionData = Union[
    BasketDefinitionData,
    ProtocolDefinitionData,
    CertificateDefinitionData,
]


@dataclass
class TokenData:  # NOSONAR - camelCase matches TS/Go registry API
    txid: str
    output_index: int
    satoshis: int
    locking_script: str
    beef: bytes


RegistryRecord = Union[
    BasketDefinitionData,
    ProtocolDefinitionData,
    CertificateDefinitionData,
]  # will be merged with TokenData at runtime where needed
