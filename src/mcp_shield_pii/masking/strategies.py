"""PII masking strategies: redact, partial mask, hash, and pseudo-anonymize."""

from __future__ import annotations

import hashlib
import random
import string
from abc import ABC, abstractmethod
from typing import ClassVar

from mcp_shield_pii.detection.base import DetectionResult, EntityType


class MaskingStrategy(ABC):
    """Base class for all masking strategies."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def mask(self, result: DetectionResult) -> str:
        """Return the masked replacement string for a detected PII entity."""
        ...


class RedactMaskingStrategy(MaskingStrategy):
    """Replace PII with a type-labeled redaction tag.

    Example: john@example.com → <EMAIL_REDACTED>
    """

    STRATEGY_NAME: ClassVar[str] = "redact"

    def __init__(self, template: str = "<{entity_type}_REDACTED>") -> None:
        self._template = template

    @property
    def name(self) -> str:
        return self.STRATEGY_NAME

    def mask(self, result: DetectionResult) -> str:
        return self._template.format(entity_type=result.entity_type.value)


class PartialMaskingStrategy(MaskingStrategy):
    """Partially mask PII, showing first/last characters.

    Example: 123-45-6789 → ***-**-6789
             john@example.com → j***@***.com
    """

    STRATEGY_NAME: ClassVar[str] = "partial"

    def __init__(self, mask_char: str = "*", visible_chars: int = 4) -> None:
        self._mask_char = mask_char
        self._visible_chars = visible_chars

    @property
    def name(self) -> str:
        return self.STRATEGY_NAME

    def mask(self, result: DetectionResult) -> str:
        text = result.text

        # Special handling for known formats
        if result.entity_type == EntityType.EMAIL:
            return self._mask_email(text)
        if result.entity_type == EntityType.SSN:
            return self._mask_ssn(text)
        if result.entity_type == EntityType.CREDIT_CARD:
            return self._mask_credit_card(text)
        if result.entity_type == EntityType.PHONE_NUMBER:
            return self._mask_phone(text)

        # Generic: show last N characters
        if len(text) <= self._visible_chars:
            return self._mask_char * len(text)
        masked_len = len(text) - self._visible_chars
        return self._mask_char * masked_len + text[-self._visible_chars:]

    def _mask_email(self, email: str) -> str:
        parts = email.split("@")
        if len(parts) != 2:
            return self._mask_char * len(email)
        local = parts[0]
        domain = parts[1]
        masked_local = local[0] + self._mask_char * (len(local) - 1)
        domain_parts = domain.split(".")
        if len(domain_parts) >= 2:
            masked_domain = (
                self._mask_char * len(domain_parts[0])
                + "."
                + domain_parts[-1]
            )
        else:
            masked_domain = self._mask_char * len(domain)
        return f"{masked_local}@{masked_domain}"

    def _mask_ssn(self, ssn: str) -> str:
        # 123-45-6789 → ***-**-6789
        digits = [c for c in ssn if c.isdigit()]
        if len(digits) == 9:
            return f"***-**-{''.join(digits[-4:])}"
        return self._mask_char * len(ssn)

    def _mask_credit_card(self, cc: str) -> str:
        digits = [c for c in cc if c.isdigit()]
        if len(digits) >= 12:
            last4 = "".join(digits[-4:])
            return f"****-****-****-{last4}"
        return self._mask_char * len(cc)

    def _mask_phone(self, phone: str) -> str:
        digits = [c for c in phone if c.isdigit()]
        if len(digits) >= 7:
            last4 = "".join(digits[-4:])
            return f"***-***-{last4}"
        return self._mask_char * len(phone)


class HashMaskingStrategy(MaskingStrategy):
    """Replace PII with a deterministic hash.

    Example: john@example.com → SHA256:a1b2c3d4...
    """

    STRATEGY_NAME: ClassVar[str] = "hash"

    def __init__(
        self,
        algorithm: str = "sha256",
        truncate: int = 16,
        salt: str = "",
    ) -> None:
        self._algorithm = algorithm
        self._truncate = truncate
        self._salt = salt

    @property
    def name(self) -> str:
        return self.STRATEGY_NAME

    def mask(self, result: DetectionResult) -> str:
        data = (self._salt + result.text).encode("utf-8")
        if self._algorithm == "sha256":
            h = hashlib.sha256(data).hexdigest()
        elif self._algorithm == "sha3_256":
            h = hashlib.sha3_256(data).hexdigest()
        elif self._algorithm == "md5":
            h = hashlib.md5(data).hexdigest()
        else:
            h = hashlib.sha256(data).hexdigest()

        truncated = h[: self._truncate]
        return f"{self._algorithm.upper()}:{truncated}"


class PseudoAnonymizationStrategy(MaskingStrategy):
    """Replace PII with consistent fake data that preserves semantic meaning.

    The same input always produces the same fake output within a session,
    maintaining referential integrity.

    Example: john@example.com → user_a3f2@anon.example
             john@example.com → user_a3f2@anon.example (consistent!)
    """

    STRATEGY_NAME: ClassVar[str] = "pseudo"

    def __init__(self, seed: int = 42) -> None:
        self._mapping: dict[str, str] = {}
        self._rng = random.Random(seed)
        self._counters: dict[EntityType, int] = {}

    @property
    def name(self) -> str:
        return self.STRATEGY_NAME

    def mask(self, result: DetectionResult) -> str:
        key = f"{result.entity_type.value}:{result.text}"
        if key in self._mapping:
            return self._mapping[key]

        fake = self._generate_fake(result)
        self._mapping[key] = fake
        return fake

    def get_mapping(self) -> dict[str, str]:
        """Return the full real→fake mapping (for reversible redaction)."""
        return dict(self._mapping)

    def _next_id(self, entity_type: EntityType) -> int:
        count = self._counters.get(entity_type, 0) + 1
        self._counters[entity_type] = count
        return count

    def _generate_fake(self, result: DetectionResult) -> str:
        idx = self._next_id(result.entity_type)
        et = result.entity_type

        if et == EntityType.EMAIL:
            return f"user_{idx:04d}@anon.example"
        if et == EntityType.PHONE_NUMBER:
            return f"+1-555-000-{idx:04d}"
        if et == EntityType.SSN:
            return f"000-00-{idx:04d}"
        if et == EntityType.CREDIT_CARD:
            return f"4000-0000-0000-{idx:04d}"
        if et == EntityType.PERSON_NAME:
            names = ["Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Grace"]
            return f"{names[(idx - 1) % len(names)]} Person{idx}"
        if et == EntityType.ORGANIZATION:
            return f"Organization_{idx}"
        if et == EntityType.LOCATION or et == EntityType.ADDRESS:
            return f"{idx} Anon Street, Anytown"
        if et == EntityType.IP_ADDRESS:
            return f"10.0.0.{idx % 255}"
        if et in (
            EntityType.API_KEY_AWS,
            EntityType.API_KEY_OPENAI,
            EntityType.API_KEY_STRIPE,
            EntityType.API_KEY_GITHUB,
        ):
            rand_suffix = "".join(
                self._rng.choices(string.ascii_letters + string.digits, k=16)
            )
            return f"FAKE_KEY_{rand_suffix}"
        if et == EntityType.JWT_TOKEN:
            return "eyJmYWtl.eyJmYWtl.ZmFrZV9zaWduYXR1cmU"

        # Fallback
        return f"<ANON_{et.value}_{idx}>"


def get_strategy(name: str, **kwargs: object) -> MaskingStrategy:
    """Factory function to get a masking strategy by name."""
    strategies: dict[str, type[MaskingStrategy]] = {
        "redact": RedactMaskingStrategy,
        "partial": PartialMaskingStrategy,
        "hash": HashMaskingStrategy,
        "pseudo": PseudoAnonymizationStrategy,
    }
    cls = strategies.get(name)
    if cls is None:
        raise ValueError(
            f"Unknown masking strategy '{name}'. "
            f"Available: {list(strategies.keys())}"
        )
    return cls(**kwargs)  # type: ignore[arg-type]
