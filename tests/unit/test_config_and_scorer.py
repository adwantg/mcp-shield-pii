"""Tests for the config loader and context scorer."""

import pytest
import tempfile
from pathlib import Path
from mcp_shield_pii.config.loader import ShieldConfig, load_config
from mcp_shield_pii.detection.base import DetectionResult, EntityType
from mcp_shield_pii.detection.context_scorer import ContextScorer


class TestConfigLoader:
    def test_default_config(self):
        cfg = ShieldConfig()
        assert cfg.default_masking_strategy == "redact"
        assert cfg.default_confidence_threshold == 0.7
        assert cfg.dry_run is False
        assert cfg.enable_regex is True

    def test_load_missing_file(self, tmp_path):
        cfg = load_config(tmp_path / "nonexistent.toml")
        assert isinstance(cfg, ShieldConfig)

    def test_load_toml(self, tmp_path):
        toml_content = """
[shield]
default_masking_strategy = "partial"
dry_run = true
log_level = "DEBUG"

[proxy]
downstream_command = "echo hello"
transport = "stdio"

[detection]
enable_regex = true
enable_nlp = false
enable_context_scoring = false

[entities.SSN]
enabled = true
masking_strategy = "hash"
confidence_threshold = 0.9

[tools.my_tool]
action = "skip"
"""
        config_file = tmp_path / "shield.toml"
        config_file.write_text(toml_content)
        cfg = load_config(config_file)

        assert cfg.default_masking_strategy == "partial"
        assert cfg.dry_run is True
        assert cfg.log_level == "DEBUG"
        assert cfg.downstream_command == "echo hello"
        assert cfg.enable_context_scoring is False
        assert "SSN" in cfg.entity_configs
        assert cfg.entity_configs["SSN"].masking_strategy == "hash"
        assert cfg.entity_configs["SSN"].confidence_threshold == 0.9
        assert len(cfg.tool_rules) == 1
        assert cfg.tool_rules[0].tool_name == "my_tool"
        assert cfg.tool_rules[0].action == "skip"


class TestContextScorer:
    def test_ssn_with_context_boost(self):
        scorer = ContextScorer()
        text = "The patient's SSN: 123-45-6789 is on file"
        result = DetectionResult(
            entity_type=EntityType.SSN,
            start=19, end=30, text="123-45-6789",
            confidence=0.85, engine="regex",
        )
        scored = scorer.score(text, [result])
        assert scored[0].confidence > result.confidence

    def test_phone_with_reducer(self):
        scorer = ContextScorer()
        text = "Version 555-123-4567 released today"
        result = DetectionResult(
            entity_type=EntityType.PHONE_NUMBER,
            start=8, end=20, text="555-123-4567",
            confidence=0.85, engine="regex",
        )
        scored = scorer.score(text, [result])
        assert scored[0].confidence < result.confidence

    def test_context_preserved(self):
        scorer = ContextScorer()
        text = "Email: test@example.com"
        result = DetectionResult(
            entity_type=EntityType.EMAIL,
            start=7, end=23, text="test@example.com",
            confidence=0.90, engine="regex",
        )
        scored = scorer.score(text, [result])
        assert scored[0].context  # Context window should be populated

    def test_label_pattern_boost(self):
        scorer = ContextScorer()
        text = "ssn: 123-45-6789"
        result = DetectionResult(
            entity_type=EntityType.SSN,
            start=5, end=16, text="123-45-6789",
            confidence=0.80, engine="regex",
        )
        scored = scorer.score(text, [result])
        # Both context keyword + label pattern boost
        assert scored[0].confidence > 0.85
