"""Base classes and entity type definitions for PII detection."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Protocol


class EntityType(enum.Enum):
    """All supported PII entity types."""

    # Regex-based entities
    EMAIL = "EMAIL"
    PHONE_NUMBER = "PHONE_NUMBER"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    IBAN = "IBAN"
    IP_ADDRESS = "IP_ADDRESS"
    IPV6_ADDRESS = "IPV6_ADDRESS"
    MAC_ADDRESS = "MAC_ADDRESS"
    API_KEY_AWS = "API_KEY_AWS"
    API_KEY_OPENAI = "API_KEY_OPENAI"
    API_KEY_STRIPE = "API_KEY_STRIPE"
    API_KEY_GITHUB = "API_KEY_GITHUB"
    PASSPORT_NUMBER = "PASSPORT_NUMBER"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    MEDICAL_ID = "MEDICAL_ID"
    DRIVERS_LICENSE = "DRIVERS_LICENSE"
    URL_WITH_AUTH = "URL_WITH_AUTH"
    JWT_TOKEN = "JWT_TOKEN"

    # NLP-based entities
    PERSON_NAME = "PERSON_NAME"
    ORGANIZATION = "ORGANIZATION"
    ADDRESS = "ADDRESS"
    MEDICAL_CONDITION = "MEDICAL_CONDITION"
    LOCATION = "LOCATION"

    # Custom
    CUSTOM = "CUSTOM"


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """A single detected PII entity in text."""

    entity_type: EntityType
    start: int
    end: int
    text: str
    confidence: float = 1.0
    context: str = ""
    engine: str = "unknown"

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class DetectionSummary:
    """Summary of all detections in a single text block."""

    original_text: str
    results: list[DetectionResult] = field(default_factory=list)
    processing_time_ms: float = 0.0

    @property
    def has_pii(self) -> bool:
        return len(self.results) > 0

    @property
    def entity_counts(self) -> dict[EntityType, int]:
        counts: dict[EntityType, int] = {}
        for r in self.results:
            counts[r.entity_type] = counts.get(r.entity_type, 0) + 1
        return counts


class DetectionEngine(Protocol):
    """Protocol for PII detection engines."""

    @property
    def name(self) -> str: ...

    def detect(self, text: str) -> list[DetectionResult]: ...

    def supported_entities(self) -> list[EntityType]: ...
