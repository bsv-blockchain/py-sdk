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
    definitionType: Literal["basket"]  # noqa: S117
    basketID: str  # noqa: S117
    name: str
    iconURL: str  # noqa: S117
    description: str
    documentationURL: str  # noqa: S117
    registryOperator: str | None = None  # noqa: S117

    @property
    def definition_type(self) -> Literal["basket"]:
        return self.definitionType

    @property
    def basket_id(self) -> str:
        return self.basketID

    @property
    def icon_url(self) -> str:
        return self.iconURL

    @property
    def documentation_url(self) -> str:
        return self.documentationURL

    @property
    def registry_operator(self) -> str | None:
        return self.registryOperator


@dataclass
class ProtocolDefinitionData:  # NOSONAR - camelCase matches TS/Go registry API
    definitionType: Literal["protocol"]
    protocolID: dict[str, Any]  # WalletProtocol-like: {securityLevel, protocol}
    name: str
    iconURL: str
    description: str
    documentationURL: str
    registryOperator: str | None = None

    @property
    def definition_type(self) -> Literal["protocol"]:
        return self.definitionType

    @property
    def protocol_id(self) -> dict[str, Any]:
        return self.protocolID

    @property
    def icon_url(self) -> str:
        return self.iconURL

    @property
    def documentation_url(self) -> str:
        return self.documentationURL

    @property
    def registry_operator(self) -> str | None:
        return self.registryOperator


@dataclass
class CertificateDefinitionData:  # NOSONAR - camelCase matches TS/Go registry API
    definitionType: Literal["certificate"]  # noqa: S117
    type: str
    name: str
    iconURL: str  # noqa: S117
    description: str
    documentationURL: str  # noqa: S117
    fields: dict[str, CertificateFieldDescriptor]
    registryOperator: str | None = None  # noqa: S117

    @property
    def definition_type(self) -> Literal["certificate"]:
        return self.definitionType

    @property
    def icon_url(self) -> str:
        return self.iconURL

    @property
    def documentation_url(self) -> str:
        return self.documentationURL

    @property
    def registry_operator(self) -> str | None:
        return self.registryOperator


DefinitionData = Union[
    BasketDefinitionData,
    ProtocolDefinitionData,
    CertificateDefinitionData,
]


@dataclass
class TokenData:  # NOSONAR - camelCase matches TS/Go registry API
    txid: str
    outputIndex: int  # noqa: S117
    satoshis: int
    lockingScript: str  # noqa: S117
    beef: bytes

    @property
    def output_index(self) -> int:
        return self.outputIndex

    @property
    def locking_script(self) -> str:
        return self.lockingScript


RegistryRecord = Union[
    BasketDefinitionData,
    ProtocolDefinitionData,
    CertificateDefinitionData,
]  # will be merged with TokenData at runtime where needed
