from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


@dataclass
class LookupQuestion:
    service: str
    query: Dict[str, Any]


@dataclass
class LookupOutput:
    beef: bytes
    outputIndex: int  # NOSONAR - camelCase matches external API format


@dataclass
class LookupAnswer:
    type: str  # 'output-list'
    outputs: List[LookupOutput]


@runtime_checkable
class Backend(Protocol):
    def __call__(self, ctx: Any, service_name: str, query: Dict[str, Any]) -> List[Dict[str, Any]]: ...


class LookupResolver:
    """Overlay-compatible resolver facade.

    Accepts a backend callable compatible with TS/Go signature:
        backend(ctx, service_name, query) -> List[{beef: bytes, outputIndex: int}]
    and returns a typed LookupAnswer with type='output-list'.
    """

    def __init__(self, backend: Optional[Backend] = None) -> None:
        self._backend = backend

    def set_backend(self, backend: Backend) -> None:
        self._backend = backend

    def query(self, ctx: Any, question: LookupQuestion) -> LookupAnswer:
        if self._backend is None:
            return LookupAnswer(type="output-list", outputs=[])
        raw = self._backend(ctx, question.service, question.query) or []
        outputs = [LookupOutput(beef=o.get("beef") or b"", outputIndex=int(o.get("outputIndex") or 0)) for o in raw]
        return LookupAnswer(type="output-list", outputs=outputs)


