from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypedDict, Dict, Union, List, Any

DefinitionType = Literal["basket", "protocol", "certificate"]


class CertificateFieldDescriptor(TypedDict):
    friendlyName: str
    description: str
    type: Literal["text", "imageURL", "other"]
    fieldIcon: str


@dataclass
class BasketDefinitionData:
    definitionType: Literal["basket"]
    basketID: str
    name: str
    iconURL: str
    description: str
    documentationURL: str
    registryOperator: str | None = None


@dataclass
class ProtocolDefinitionData:
    definitionType: Literal["protocol"]
    protocolID: Dict[str, Any]  # WalletProtocol-like: {securityLevel, protocol}
    name: str
    iconURL: str
    description: str
    documentationURL: str
    registryOperator: str | None = None


@dataclass
class CertificateDefinitionData:
    definitionType: Literal["certificate"]
    type: str
    name: str
    iconURL: str
    description: str
    documentationURL: str
    fields: Dict[str, CertificateFieldDescriptor]
    registryOperator: str | None = None


DefinitionData = Union[
    BasketDefinitionData,
    ProtocolDefinitionData,
    CertificateDefinitionData,
]


@dataclass
class TokenData:
    txid: str
    outputIndex: int
    satoshis: int
    lockingScript: str
    beef: bytes


RegistryRecord = Union[
    BasketDefinitionData,
    ProtocolDefinitionData,
    CertificateDefinitionData,
]  # will be merged with TokenData at runtime where needed


