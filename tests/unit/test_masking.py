"""Tests for masking strategies."""

import pytest

from mcp_shield_pii.detection.base import DetectionResult, EntityType
from mcp_shield_pii.masking.strategies import (
    HashMaskingStrategy,
    PartialMaskingStrategy,
    PseudoAnonymizationStrategy,
    RedactMaskingStrategy,
    get_strategy,
)


def _make_result(
    entity_type: EntityType = EntityType.EMAIL,
    text: str = "test@example.com",
    start: int = 0,
    end: int = 0,
) -> DetectionResult:
    return DetectionResult(
        entity_type=entity_type,
        start=start,
        end=end or len(text),
        text=text,
    )


class TestRedactStrategy:
    def test_email_redaction(self):
        strategy = RedactMaskingStrategy()
        result = _make_result(EntityType.EMAIL, "john@test.com")
        assert strategy.mask(result) == "<EMAIL_REDACTED>"

    def test_ssn_redaction(self):
        strategy = RedactMaskingStrategy()
        result = _make_result(EntityType.SSN, "123-45-6789")
        assert strategy.mask(result) == "<SSN_REDACTED>"

    def test_custom_template(self):
        strategy = RedactMaskingStrategy(template="[{entity_type}]")
        result = _make_result(EntityType.EMAIL, "a@b.com")
        assert strategy.mask(result) == "[EMAIL]"

    def test_name(self):
        assert RedactMaskingStrategy().name == "redact"


class TestPartialStrategy:
    def test_email_partial(self):
        strategy = PartialMaskingStrategy()
        result = _make_result(EntityType.EMAIL, "john@example.com")
        masked = strategy.mask(result)
        assert masked.startswith("j")
        assert "@" in masked
        assert masked.endswith(".com")

    def test_ssn_partial(self):
        strategy = PartialMaskingStrategy()
        result = _make_result(EntityType.SSN, "123-45-6789")
        assert strategy.mask(result) == "***-**-6789"

    def test_credit_card_partial(self):
        strategy = PartialMaskingStrategy()
        result = _make_result(EntityType.CREDIT_CARD, "4111-1111-1111-1111")
        assert strategy.mask(result) == "****-****-****-1111"

    def test_phone_partial(self):
        strategy = PartialMaskingStrategy()
        result = _make_result(EntityType.PHONE_NUMBER, "555-123-4567")
        assert strategy.mask(result) == "***-***-4567"

    def test_generic_partial(self):
        strategy = PartialMaskingStrategy()
        result = _make_result(EntityType.PERSON_NAME, "John Smith")
        masked = strategy.mask(result)
        assert masked.endswith("mith")

    def test_name(self):
        assert PartialMaskingStrategy().name == "partial"


class TestHashStrategy:
    def test_deterministic(self):
        strategy = HashMaskingStrategy()
        r1 = _make_result(EntityType.EMAIL, "john@test.com")
        r2 = _make_result(EntityType.EMAIL, "john@test.com")
        assert strategy.mask(r1) == strategy.mask(r2)

    def test_different_inputs_different_hashes(self):
        strategy = HashMaskingStrategy()
        r1 = _make_result(EntityType.EMAIL, "john@test.com")
        r2 = _make_result(EntityType.EMAIL, "jane@test.com")
        assert strategy.mask(r1) != strategy.mask(r2)

    def test_sha256_prefix(self):
        strategy = HashMaskingStrategy(algorithm="sha256")
        result = _make_result()
        assert strategy.mask(result).startswith("SHA256:")

    def test_md5(self):
        strategy = HashMaskingStrategy(algorithm="md5")
        result = _make_result()
        assert strategy.mask(result).startswith("MD5:")

    def test_salt(self):
        s1 = HashMaskingStrategy(salt="")
        s2 = HashMaskingStrategy(salt="my_salt")
        result = _make_result()
        assert s1.mask(result) != s2.mask(result)

    def test_name(self):
        assert HashMaskingStrategy().name == "hash"


class TestPseudoAnonymization:
    def test_consistent_mapping(self):
        strategy = PseudoAnonymizationStrategy()
        r1 = _make_result(EntityType.EMAIL, "john@test.com")
        r2 = _make_result(EntityType.EMAIL, "john@test.com")
        assert strategy.mask(r1) == strategy.mask(r2)

    def test_different_inputs_different_fakes(self):
        strategy = PseudoAnonymizationStrategy()
        r1 = _make_result(EntityType.EMAIL, "john@test.com")
        r2 = _make_result(EntityType.EMAIL, "jane@test.com")
        m1 = strategy.mask(r1)
        m2 = strategy.mask(r2)
        assert m1 != m2

    def test_email_format(self):
        strategy = PseudoAnonymizationStrategy()
        result = _make_result(EntityType.EMAIL, "real@corp.com")
        fake = strategy.mask(result)
        assert "@anon.example" in fake

    def test_ssn_format(self):
        strategy = PseudoAnonymizationStrategy()
        result = _make_result(EntityType.SSN, "123-45-6789")
        fake = strategy.mask(result)
        assert fake.startswith("000-00-")

    def test_phone_format(self):
        strategy = PseudoAnonymizationStrategy()
        result = _make_result(EntityType.PHONE_NUMBER, "555-123-4567")
        fake = strategy.mask(result)
        assert "+1-555-000-" in fake

    def test_person_name(self):
        strategy = PseudoAnonymizationStrategy()
        result = _make_result(EntityType.PERSON_NAME, "John Doe")
        fake = strategy.mask(result)
        assert "Person" in fake

    def test_get_mapping(self):
        strategy = PseudoAnonymizationStrategy()
        strategy.mask(_make_result(EntityType.EMAIL, "a@b.com"))
        mapping = strategy.get_mapping()
        assert len(mapping) == 1

    def test_name(self):
        assert PseudoAnonymizationStrategy().name == "pseudo"


class TestGetStrategy:
    def test_get_redact(self):
        s = get_strategy("redact")
        assert s.name == "redact"

    def test_get_partial(self):
        s = get_strategy("partial")
        assert s.name == "partial"

    def test_get_hash(self):
        s = get_strategy("hash")
        assert s.name == "hash"

    def test_get_pseudo(self):
        s = get_strategy("pseudo")
        assert s.name == "pseudo"

    def test_unknown_strategy_raises(self):
        with pytest.raises(ValueError, match="Unknown masking strategy"):
            get_strategy("nonexistent")
