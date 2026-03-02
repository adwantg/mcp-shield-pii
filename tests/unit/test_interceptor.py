"""Tests for the MCP interceptor and pipeline."""

import json
import pytest
from mcp_shield_pii.config.loader import ShieldConfig
from mcp_shield_pii.pipeline import ShieldPipeline
from mcp_shield_pii.proxy import MCPInterceptor


@pytest.fixture
def config():
    return ShieldConfig(
        enable_regex=True,
        enable_nlp=False,
        enable_context_scoring=False,
        default_confidence_threshold=0.5,
        audit_log_file="/tmp/test_audit.jsonl",
    )


@pytest.fixture
def pipeline(config):
    p = ShieldPipeline(config)
    yield p
    p.close()


@pytest.fixture
def interceptor(pipeline):
    return MCPInterceptor(pipeline)


class TestPipeline:
    def test_no_pii(self, pipeline):
        masked, summary = pipeline.process_text("Hello world, no PII here.")
        assert masked == "Hello world, no PII here."
        assert not summary.has_pii

    def test_email_redacted(self, pipeline):
        masked, summary = pipeline.process_text("Contact john@example.com")
        assert summary.has_pii
        assert "john@example.com" not in masked
        assert "REDACTED" in masked

    def test_ssn_redacted(self, pipeline):
        masked, summary = pipeline.process_text("SSN is 123-45-6789")
        assert "123-45-6789" not in masked

    def test_multiple_entities(self, pipeline):
        text = "Email john@test.com, SSN 123-45-6789, call 555-123-4567"
        masked, summary = pipeline.process_text(text)
        assert len(summary.results) >= 3

    def test_dry_run_no_modification(self, config):
        config.dry_run = True
        pipeline = ShieldPipeline(config)
        text = "Email: secret@corp.com"
        masked, summary = pipeline.process_text(text)
        assert masked == text  # Not modified in dry-run
        assert summary.has_pii  # But PII was still detected
        pipeline.close()

    def test_tool_skip_rule(self, config):
        from mcp_shield_pii.config.loader import ToolRuleConfig
        config.tool_rules = [ToolRuleConfig(tool_name="safe_tool", action="skip")]
        pipeline = ShieldPipeline(config)
        assert not pipeline.should_scan_tool("safe_tool")
        assert pipeline.should_scan_tool("other_tool")
        pipeline.close()

    def test_processing_time_tracked(self, pipeline):
        _, summary = pipeline.process_text("Test text with test@email.com")
        assert summary.processing_time_ms > 0


class TestMCPInterceptor:
    def test_passthrough_non_json(self, interceptor):
        result = interceptor.intercept("not json")
        assert result == "not json"

    def test_passthrough_request(self, interceptor):
        msg = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1})
        result = interceptor.intercept(msg)
        assert result == msg

    def test_intercept_tool_result_with_pii(self, interceptor):
        msg = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {"type": "text", "text": "User email is john@secret.com"}
                ]
            }
        })
        result = interceptor.intercept(msg)
        parsed = json.loads(result)
        text = parsed["result"]["content"][0]["text"]
        assert "john@secret.com" not in text

    def test_intercept_no_pii(self, interceptor):
        msg = json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [
                    {"type": "text", "text": "Hello world"}
                ]
            }
        })
        result = interceptor.intercept(msg)
        parsed = json.loads(result)
        assert parsed["result"]["content"][0]["text"] == "Hello world"

    def test_stats_tracking(self, interceptor):
        interceptor.intercept("not json")
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "result": {"content": [{"type": "text", "text": "Email: a@b.com"}]}
        })
        interceptor.intercept(msg)
        stats = interceptor.stats
        assert stats["total_messages"] == 2

    def test_intercept_request_extraction(self, interceptor):
        msg = json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": 1})
        raw, method = interceptor.intercept_request(msg)
        assert method == "tools/call"
