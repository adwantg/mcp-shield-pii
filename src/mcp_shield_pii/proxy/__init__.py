"""JSON-RPC interceptor for MCP CallToolResult responses."""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp_shield_pii.pipeline import ShieldPipeline

logger = logging.getLogger(__name__)


class MCPInterceptor:
    """Intercepts MCP JSON-RPC messages and applies PII redaction.

    Specifically targets CallToolResult responses that contain text content
    which may hold PII. Non-sensitive RPCs pass through untouched.
    """

    # Methods that should bypass redaction entirely
    PASSTHROUGH_METHODS: set[str] = {
        "initialize",
        "initialized",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        "ping",
        "notifications/cancelled",
        "logging/setLevel",
    }

    def __init__(self, pipeline: ShieldPipeline) -> None:
        self._pipeline = pipeline
        self._stats = {"total_messages": 0, "scanned": 0, "passthrough": 0, "errors": 0}

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def intercept(self, raw_message: str) -> str:
        """Intercept a raw JSON-RPC message string.

        Returns the (possibly modified) message string.
        """
        self._stats["total_messages"] += 1

        try:
            message = json.loads(raw_message)
        except json.JSONDecodeError:
            self._stats["passthrough"] += 1
            return raw_message

        # Only intercept responses (have "result" key)
        if "result" not in message:
            self._stats["passthrough"] += 1
            return raw_message

        result = message.get("result", {})

        # Check if this is a CallToolResult with content
        content = result.get("content")
        if not isinstance(content, list):
            self._stats["passthrough"] += 1
            return raw_message

        # Extract tool name from request context if available
        tool_name = result.get("_meta", {}).get("tool_name", "unknown")

        # Check tool rules
        if not self._pipeline.should_scan_tool(tool_name):
            self._stats["passthrough"] += 1
            return raw_message

        # Process each content block
        modified = False
        for i, block in enumerate(content):
            if not isinstance(block, dict):
                continue

            block_type = block.get("type", "")

            if block_type == "text":
                original_text = block.get("text", "")
                if original_text:
                    masked_text, summary = self._pipeline.process_text(
                        original_text, tool_name=tool_name
                    )
                    if summary.has_pii:
                        content[i]["text"] = masked_text
                        modified = True
                        self._stats["scanned"] += 1
                        logger.info(
                            "Redacted %d entities in tool '%s' response",
                            len(summary.results),
                            tool_name,
                        )

            elif block_type == "resource":
                # Resources may contain text content
                resource = block.get("resource", {})
                if isinstance(resource, dict) and resource.get("text"):
                    masked, summary = self._pipeline.process_text(
                        resource["text"], tool_name=tool_name
                    )
                    if summary.has_pii:
                        content[i]["resource"]["text"] = masked
                        modified = True
                        self._stats["scanned"] += 1

        if modified:
            message["result"]["content"] = content
            return json.dumps(message)

        self._stats["passthrough"] += 1
        return raw_message

    def intercept_request(self, raw_message: str) -> tuple[str, str | None]:
        """Intercept a JSON-RPC request to extract method info.

        Returns (raw_message, method_name) — requests pass through unchanged.
        """
        try:
            message = json.loads(raw_message)
            method = message.get("method")
            return raw_message, method
        except json.JSONDecodeError:
            return raw_message, None
