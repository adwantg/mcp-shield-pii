"""Regex-based PII detection engine with 18+ entity patterns and Luhn validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from mcp_shield_pii.detection.base import DetectionResult, EntityType


def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 2:
        return False
    checksum = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


@dataclass
class _PatternDef:
    """Internal definition for a regex-based PII pattern."""

    entity_type: EntityType
    pattern: re.Pattern[str]
    confidence: float = 0.90
    validator: str | None = None  # name of validation function


class RegexDetectionEngine:
    """Fast, zero-dependency regex detection engine for structured PII.

    Detects 18 entity types including SSNs, credit cards, emails, phones,
    IBANs, API keys, JWT tokens, and more.
    """

    ENGINE_NAME: ClassVar[str] = "regex"

    def __init__(self) -> None:
        self._patterns = self._build_patterns()

    @property
    def name(self) -> str:
        return self.ENGINE_NAME

    def supported_entities(self) -> list[EntityType]:
        return [p.entity_type for p in self._patterns]

    def detect(self, text: str) -> list[DetectionResult]:
        """Run all regex patterns against the text and return matches."""
        results: list[DetectionResult] = []
        for pdef in self._patterns:
            for match in pdef.pattern.finditer(text):
                matched_text = match.group(0)
                confidence = pdef.confidence

                # Run validator if applicable
                if pdef.validator == "luhn":
                    if not _luhn_check(matched_text):
                        confidence *= 0.3  # Drastically lower confidence
                elif pdef.validator == "iban_length":
                    if not self._validate_iban(matched_text):
                        confidence *= 0.4

                results.append(
                    DetectionResult(
                        entity_type=pdef.entity_type,
                        start=match.start(),
                        end=match.end(),
                        text=matched_text,
                        confidence=round(confidence, 3),
                        engine=self.ENGINE_NAME,
                    )
                )
        # Remove overlapping detections, keep highest confidence
        return self._deduplicate(results)

    def _deduplicate(self, results: list[DetectionResult]) -> list[DetectionResult]:
        """Remove overlapping detections, keeping the highest confidence one."""
        if not results:
            return results
        sorted_results = sorted(results, key=lambda r: (-r.confidence, r.start))
        kept: list[DetectionResult] = []
        for result in sorted_results:
            overlaps = False
            for existing in kept:
                if result.start < existing.end and result.end > existing.start:
                    overlaps = True
                    break
            if not overlaps:
                kept.append(result)
        return sorted(kept, key=lambda r: r.start)

    @staticmethod
    def _validate_iban(iban: str) -> bool:
        """Basic IBAN length validation by country code."""
        iban_lengths: dict[str, int] = {
            "DE": 22, "GB": 22, "FR": 27, "ES": 24, "IT": 27, "NL": 18,
            "BE": 16, "AT": 20, "CH": 21, "PL": 28, "PT": 25, "SE": 24,
            "NO": 15, "FI": 18, "DK": 18, "IE": 22, "LU": 20, "CZ": 24,
        }
        clean = iban.replace(" ", "")
        country = clean[:2].upper()
        expected = iban_lengths.get(country)
        if expected is None:
            return True  # Unknown country, don't penalize
        return len(clean) == expected

    @staticmethod
    def _build_patterns() -> list[_PatternDef]:
        """Build all regex patterns for supported entity types."""
        return [
            # Email
            _PatternDef(
                entity_type=EntityType.EMAIL,
                pattern=re.compile(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
                ),
                confidence=0.95,
            ),
            # Phone numbers (international and US formats)
            _PatternDef(
                entity_type=EntityType.PHONE_NUMBER,
                pattern=re.compile(
                    r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
                ),
                confidence=0.85,
            ),
            # SSN
            _PatternDef(
                entity_type=EntityType.SSN,
                pattern=re.compile(
                    r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
                ),
                confidence=0.92,
            ),
            # Credit Card (Visa, MC, Amex, Discover)
            _PatternDef(
                entity_type=EntityType.CREDIT_CARD,
                pattern=re.compile(
                    r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
                    r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,4}\b"
                ),
                confidence=0.90,
                validator="luhn",
            ),
            # IBAN
            _PatternDef(
                entity_type=EntityType.IBAN,
                pattern=re.compile(
                    r"\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,14}\b"
                ),
                confidence=0.88,
                validator="iban_length",
            ),
            # IPv4
            _PatternDef(
                entity_type=EntityType.IP_ADDRESS,
                pattern=re.compile(
                    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
                ),
                confidence=0.80,
            ),
            # IPv6
            _PatternDef(
                entity_type=EntityType.IPV6_ADDRESS,
                pattern=re.compile(
                    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
                    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
                    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
                ),
                confidence=0.80,
            ),
            # MAC Address
            _PatternDef(
                entity_type=EntityType.MAC_ADDRESS,
                pattern=re.compile(
                    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
                ),
                confidence=0.90,
            ),
            # AWS API Key
            _PatternDef(
                entity_type=EntityType.API_KEY_AWS,
                pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
                confidence=0.95,
            ),
            # OpenAI API Key
            _PatternDef(
                entity_type=EntityType.API_KEY_OPENAI,
                pattern=re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
                confidence=0.92,
            ),
            # Stripe API Key
            _PatternDef(
                entity_type=EntityType.API_KEY_STRIPE,
                pattern=re.compile(
                    r"\b(?:sk_live|sk_test|pk_live|pk_test)_[A-Za-z0-9]{10,}\b"
                ),
                confidence=0.95,
            ),
            # GitHub Token
            _PatternDef(
                entity_type=EntityType.API_KEY_GITHUB,
                pattern=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
                confidence=0.95,
            ),
            # Passport Number (US format)
            _PatternDef(
                entity_type=EntityType.PASSPORT_NUMBER,
                pattern=re.compile(r"\b[A-Z]\d{8}\b"),
                confidence=0.70,
            ),
            # Date of Birth (common formats)
            _PatternDef(
                entity_type=EntityType.DATE_OF_BIRTH,
                pattern=re.compile(
                    r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b"
                ),
                confidence=0.65,
            ),
            # Medical ID / MRN
            _PatternDef(
                entity_type=EntityType.MEDICAL_ID,
                pattern=re.compile(r"\bMRN[-:]?\s?\d{4,10}\b", re.IGNORECASE),
                confidence=0.90,
            ),
            # Driver's License (generic US-style)
            _PatternDef(
                entity_type=EntityType.DRIVERS_LICENSE,
                pattern=re.compile(r"\b[A-Z]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b"),
                confidence=0.70,
            ),
            # URL with embedded credentials
            _PatternDef(
                entity_type=EntityType.URL_WITH_AUTH,
                pattern=re.compile(
                    r"https?://[^\s:@]+:[^\s:@]+@[^\s/]+"
                ),
                confidence=0.95,
            ),
            # JWT Token
            _PatternDef(
                entity_type=EntityType.JWT_TOKEN,
                pattern=re.compile(
                    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
                ),
                confidence=0.93,
            ),
        ]
