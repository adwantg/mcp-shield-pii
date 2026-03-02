"""Comprehensive tests for the regex detection engine."""

import pytest
from mcp_shield_pii.detection.base import EntityType
from mcp_shield_pii.detection.regex_engine import RegexDetectionEngine, _luhn_check


@pytest.fixture
def engine():
    return RegexDetectionEngine()


class TestLuhnCheck:
    def test_valid_visa(self):
        assert _luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert _luhn_check("5500000000000004") is True

    def test_invalid_number(self):
        assert _luhn_check("1234567890123456") is False

    def test_short_number(self):
        assert _luhn_check("1") is False


class TestEmailDetection:
    def test_simple_email(self, engine):
        results = engine.detect("Contact john@example.com for details")
        assert len(results) == 1
        assert results[0].entity_type == EntityType.EMAIL
        assert results[0].text == "john@example.com"

    def test_multiple_emails(self, engine):
        text = "Email alice@test.org or bob@corp.io"
        results = engine.detect(text)
        emails = [r for r in results if r.entity_type == EntityType.EMAIL]
        assert len(emails) == 2

    def test_complex_email(self, engine):
        results = engine.detect("user.name+tag@sub.domain.com")
        assert len(results) >= 1
        assert results[0].entity_type == EntityType.EMAIL


class TestSSNDetection:
    def test_valid_ssn(self, engine):
        results = engine.detect("SSN: 123-45-6789")
        ssns = [r for r in results if r.entity_type == EntityType.SSN]
        assert len(ssns) == 1
        assert ssns[0].text == "123-45-6789"

    def test_invalid_ssn_000(self, engine):
        # SSNs starting with 000 are invalid
        results = engine.detect("SSN: 000-45-6789")
        ssns = [r for r in results if r.entity_type == EntityType.SSN]
        assert len(ssns) == 0

    def test_invalid_ssn_666(self, engine):
        results = engine.detect("SSN: 666-45-6789")
        ssns = [r for r in results if r.entity_type == EntityType.SSN]
        assert len(ssns) == 0


class TestCreditCardDetection:
    def test_visa(self, engine):
        results = engine.detect("Card: 4111-1111-1111-1111")
        ccs = [r for r in results if r.entity_type == EntityType.CREDIT_CARD]
        assert len(ccs) == 1

    def test_mastercard(self, engine):
        results = engine.detect("Card: 5500 0000 0000 0004")
        ccs = [r for r in results if r.entity_type == EntityType.CREDIT_CARD]
        assert len(ccs) == 1


class TestPhoneDetection:
    def test_us_phone(self, engine):
        results = engine.detect("Call 555-123-4567")
        phones = [r for r in results if r.entity_type == EntityType.PHONE_NUMBER]
        assert len(phones) == 1

    def test_international_phone(self, engine):
        results = engine.detect("Phone: +1-555-123-4567")
        phones = [r for r in results if r.entity_type == EntityType.PHONE_NUMBER]
        assert len(phones) >= 1


class TestAPIKeyDetection:
    def test_aws_key(self, engine):
        results = engine.detect("Key: AKIAIOSFODNN7EXAMPLE")
        assert any(r.entity_type == EntityType.API_KEY_AWS for r in results)

    def test_openai_key(self, engine):
        results = engine.detect("Token: sk-abcdefghijklmnopqrstuvwxyz")
        assert any(r.entity_type == EntityType.API_KEY_OPENAI for r in results)

    def test_stripe_key(self, engine):
        results = engine.detect("Key: sk_live_abcdefghijk")
        assert any(r.entity_type == EntityType.API_KEY_STRIPE for r in results)

    def test_github_token(self, engine):
        token = "ghp_" + "a" * 36
        results = engine.detect(f"Token: {token}")
        assert any(r.entity_type == EntityType.API_KEY_GITHUB for r in results)


class TestIPDetection:
    def test_ipv4(self, engine):
        results = engine.detect("Server at 192.168.1.100")
        assert any(r.entity_type == EntityType.IP_ADDRESS for r in results)

    def test_mac_address(self, engine):
        results = engine.detect("MAC: 00:1A:2B:3C:4D:5E")
        assert any(r.entity_type == EntityType.MAC_ADDRESS for r in results)


class TestMiscDetection:
    def test_jwt_token(self, engine):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        results = engine.detect(f"Token: {jwt}")
        assert any(r.entity_type == EntityType.JWT_TOKEN for r in results)

    def test_url_with_auth(self, engine):
        results = engine.detect("Connect to https://admin:secret@db.example.com/path")
        assert any(r.entity_type == EntityType.URL_WITH_AUTH for r in results)

    def test_medical_id(self, engine):
        results = engine.detect("Patient MRN-123456 admitted")
        assert any(r.entity_type == EntityType.MEDICAL_ID for r in results)

    def test_dob(self, engine):
        results = engine.detect("Born: 1990-01-15")
        assert any(r.entity_type == EntityType.DATE_OF_BIRTH for r in results)


class TestDeduplication:
    def test_no_overlapping_results(self, engine):
        text = "Contact john@example.com at john@example.com"
        results = engine.detect(text)
        # Both occurrences should be detected
        emails = [r for r in results if r.entity_type == EntityType.EMAIL]
        assert len(emails) == 2

    def test_supported_entities(self, engine):
        entities = engine.supported_entities()
        assert len(entities) == 18
        assert EntityType.EMAIL in entities
        assert EntityType.SSN in entities


class TestNoFalsePositives:
    def test_clean_text(self, engine):
        results = engine.detect("Hello, this is a normal sentence without any PII.")
        assert len(results) == 0

    def test_numbers_not_ssn(self, engine):
        # Regular numbers should not match SSN pattern
        results = engine.detect("Order #12345 shipped")
        ssns = [r for r in results if r.entity_type == EntityType.SSN]
        assert len(ssns) == 0
