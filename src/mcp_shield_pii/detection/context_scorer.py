"""Context-aware scoring to reduce false positives in PII detection."""

from __future__ import annotations

import re
from typing import ClassVar

from mcp_shield_pii.detection.base import DetectionResult, EntityType

# Context keywords that boost confidence when found near PII
_CONTEXT_BOOSTERS: dict[EntityType, list[str]] = {
    EntityType.SSN: [
        "ssn", "social security", "social sec", "ss#", "ss #", "tax id",
    ],
    EntityType.CREDIT_CARD: [
        "card", "credit", "debit", "visa", "mastercard", "amex", "payment",
        "cc", "card number", "card no",
    ],
    EntityType.EMAIL: ["email", "e-mail", "mail", "contact", "send to"],
    EntityType.PHONE_NUMBER: [
        "phone", "tel", "telephone", "call", "mobile", "cell", "fax", "contact",
    ],
    EntityType.DATE_OF_BIRTH: [
        "dob", "date of birth", "born", "birthday", "birth date", "birthdate",
    ],
    EntityType.MEDICAL_ID: [
        "mrn", "medical record", "patient id", "patient number", "chart",
    ],
    EntityType.PASSPORT_NUMBER: [
        "passport", "travel document", "passport no", "passport number",
    ],
    EntityType.DRIVERS_LICENSE: [
        "driver", "license", "dl", "dl#", "driving licence", "dmv",
    ],
    EntityType.IBAN: [
        "iban", "bank account", "account number", "swift", "bic",
    ],
    EntityType.IP_ADDRESS: [
        "ip", "address", "server", "host", "client ip", "source ip",
    ],
    EntityType.API_KEY_AWS: ["aws", "amazon", "access key", "secret key"],
    EntityType.API_KEY_OPENAI: ["openai", "api key", "api_key", "token"],
    EntityType.API_KEY_STRIPE: ["stripe", "payment", "api key"],
    EntityType.API_KEY_GITHUB: ["github", "token", "pat", "personal access"],
}

# Context keywords that reduce confidence (likely not PII)
_CONTEXT_REDUCERS: dict[EntityType, list[str]] = {
    EntityType.PHONE_NUMBER: ["version", "v.", "model", "code", "id:", "order"],
    EntityType.DATE_OF_BIRTH: [
        "created", "updated", "modified", "timestamp", "published",
        "released", "version", "deadline",
    ],
    EntityType.IP_ADDRESS: ["version", "v4", "v6", "protocol"],
    EntityType.PASSPORT_NUMBER: ["serial", "model", "part", "sku", "order"],
}


class ContextScorer:
    """Adjusts detection confidence based on surrounding text context.

    Looks at a configurable window of characters around each detection
    for booster or reducer keywords.
    """

    WINDOW_SIZE: ClassVar[int] = 80

    def __init__(self, window_size: int | None = None) -> None:
        self._window = window_size or self.WINDOW_SIZE

    def score(
        self, text: str, results: list[DetectionResult]
    ) -> list[DetectionResult]:
        """Re-score detection results based on surrounding context."""
        scored: list[DetectionResult] = []
        text_lower = text.lower()

        for result in results:
            # Extract context window
            ctx_start = max(0, result.start - self._window)
            ctx_end = min(len(text), result.end + self._window)
            context = text_lower[ctx_start:ctx_end]

            boost = self._calculate_boost(result.entity_type, context)
            new_confidence = min(max(result.confidence + boost, 0.0), 1.0)

            scored.append(
                DetectionResult(
                    entity_type=result.entity_type,
                    start=result.start,
                    end=result.end,
                    text=result.text,
                    confidence=round(new_confidence, 3),
                    context=text[ctx_start:ctx_end],
                    engine=result.engine,
                )
            )

        return scored

    def _calculate_boost(self, entity_type: EntityType, context: str) -> float:
        """Calculate the confidence boost/reduction from context."""
        boost = 0.0

        # Check boosters
        boosters = _CONTEXT_BOOSTERS.get(entity_type, [])
        for keyword in boosters:
            if keyword in context:
                boost += 0.08
                break  # One booster match is enough

        # Check reducers
        reducers = _CONTEXT_REDUCERS.get(entity_type, [])
        for keyword in reducers:
            if keyword in context:
                boost -= 0.15
                break

        # Check for assignment-like patterns (key: value, key=value)
        label_pattern = re.compile(
            r"(?:ssn|email|phone|card|iban|dob|passport|license|mrn|ip)\s*[:=]",
            re.IGNORECASE,
        )
        if label_pattern.search(context):
            boost += 0.10

        return boost
