"""Structured ingestion status for Phase B.

Errors are deliberately distinct from an empty capture.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IngestionCode(str, Enum):
    OK = "INGESTION_OK"
    EMPTY = "INGESTION_EMPTY"
    INGESTION_ERROR = "INGESTION_ERROR"
    PCAP_PARSE_ERROR = "PCAP_PARSE_ERROR"
    UNSUPPORTED_PACKET = "UNSUPPORTED_PACKET"
    DNS_PARSE_ERROR = "DNS_PARSE_ERROR"


class IngestionError(RuntimeError):
    """A fatal ingestion/parsing failure."""

    def __init__(self, code: IngestionCode, message: str, *, cause: Exception | None = None):
        super().__init__(message)
        self.code = code
        self.cause = cause


@dataclass(frozen=True)
class IngestionResult:
    """Explicitly separates successful empty input from parser failure."""

    flows: list[Any] = field(default_factory=list)
    status: IngestionCode = IngestionCode.OK
    errors: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status in {IngestionCode.OK, IngestionCode.EMPTY}

    @property
    def failed(self) -> bool:
        return not self.ok
