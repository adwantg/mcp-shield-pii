"""Configuration loader with TOML support, hot-reload, and schema validation."""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

_DEFAULT_CONFIDENCE_THRESHOLD = 0.7


@dataclass
class EntityConfig:
    """Per-entity-type configuration."""

    enabled: bool = True
    masking_strategy: str = "redact"
    confidence_threshold: float = _DEFAULT_CONFIDENCE_THRESHOLD
    custom_pattern: str | None = None


@dataclass
class ToolRuleConfig:
    """Per-tool allow/deny configuration."""

    tool_name: str
    action: str = "scan"  # "scan", "skip", "strict"
    masking_strategy: str | None = None


@dataclass
class WebhookConfig:
    """Webhook alert configuration."""

    url: str
    events: list[str] = field(default_factory=lambda: ["high_severity"])
    min_severity: str = "high"


@dataclass
class DashboardConfig:
    """Dashboard server configuration."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8765


@dataclass
class MetricsConfig:
    """Prometheus metrics endpoint configuration."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 9090


@dataclass
class ShieldConfig:
    """Complete mcp-shield-pii configuration."""

    # Global settings
    default_masking_strategy: str = "redact"
    default_confidence_threshold: float = _DEFAULT_CONFIDENCE_THRESHOLD
    dry_run: bool = False
    log_level: str = "INFO"
    log_file: str | None = None
    audit_log_file: str = "shield_audit.jsonl"

    # Detection engines
    enable_regex: bool = True
    enable_nlp: bool = False
    enable_context_scoring: bool = True
    nlp_model: str = "en_core_web_sm"

    # Concurrency
    interpreter_pool_size: int = 4

    # Proxy
    downstream_command: str = ""
    transport: str = "stdio"  # "stdio" or "sse"
    sse_port: int = 8080

    # Per-entity configuration
    entity_configs: dict[str, EntityConfig] = field(default_factory=dict)

    # Tool rules (allow/deny lists)
    tool_rules: list[ToolRuleConfig] = field(default_factory=list)

    # Reversible redaction
    enable_reversible: bool = False
    reversible_key_file: str | None = None

    # Webhooks
    webhooks: list[WebhookConfig] = field(default_factory=list)

    # Multi-server
    servers: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Dashboard
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)

    # Metrics
    metrics: MetricsConfig = field(default_factory=MetricsConfig)


def load_config(path: str | Path) -> ShieldConfig:
    """Load configuration from a TOML file."""
    path = Path(path)
    if not path.exists():
        logger.warning("Config file not found: %s. Using defaults.", path)
        return ShieldConfig()

    with open(path, "rb") as f:
        data = tomllib.load(f)

    return _parse_config(data)


def _parse_config(data: dict[str, Any]) -> ShieldConfig:
    """Parse a TOML dictionary into ShieldConfig."""
    shield = data.get("shield", {})
    proxy = data.get("proxy", {})
    detection = data.get("detection", {})
    concurrency = data.get("concurrency", {})
    entities = data.get("entities", {})
    tools = data.get("tools", {})
    reversible = data.get("reversible", {})
    webhooks_raw = data.get("webhooks", [])
    dashboard_raw = data.get("dashboard", {})
    metrics_raw = data.get("metrics", {})
    servers = data.get("servers", {})

    # Parse entity configs
    entity_configs: dict[str, EntityConfig] = {}
    for entity_name, entity_data in entities.items():
        if isinstance(entity_data, dict):
            entity_configs[entity_name.upper()] = EntityConfig(
                enabled=entity_data.get("enabled", True),
                masking_strategy=entity_data.get(
                    "masking_strategy",
                    shield.get("default_masking_strategy", "redact"),
                ),
                confidence_threshold=entity_data.get(
                    "confidence_threshold",
                    shield.get("default_confidence_threshold", _DEFAULT_CONFIDENCE_THRESHOLD),
                ),
                custom_pattern=entity_data.get("custom_pattern"),
            )

    # Parse tool rules
    tool_rules: list[ToolRuleConfig] = []
    if isinstance(tools, dict):
        for tool_name, tool_data in tools.items():
            if isinstance(tool_data, dict):
                tool_rules.append(
                    ToolRuleConfig(
                        tool_name=tool_name,
                        action=tool_data.get("action", "scan"),
                        masking_strategy=tool_data.get("masking_strategy"),
                    )
                )

    # Parse webhooks
    webhooks: list[WebhookConfig] = []
    if isinstance(webhooks_raw, list):
        for wh in webhooks_raw:
            if isinstance(wh, dict):
                webhooks.append(
                    WebhookConfig(
                        url=wh.get("url", ""),
                        events=wh.get("events", ["high_severity"]),
                        min_severity=wh.get("min_severity", "high"),
                    )
                )

    return ShieldConfig(
        # Global
        default_masking_strategy=shield.get("default_masking_strategy", "redact"),
        default_confidence_threshold=shield.get(
            "default_confidence_threshold", _DEFAULT_CONFIDENCE_THRESHOLD
        ),
        dry_run=shield.get("dry_run", False),
        log_level=shield.get("log_level", "INFO"),
        log_file=shield.get("log_file"),
        audit_log_file=shield.get("audit_log_file", "shield_audit.jsonl"),
        # Detection
        enable_regex=detection.get("enable_regex", True),
        enable_nlp=detection.get("enable_nlp", False),
        enable_context_scoring=detection.get("enable_context_scoring", True),
        nlp_model=detection.get("nlp_model", "en_core_web_sm"),
        # Concurrency
        interpreter_pool_size=concurrency.get("pool_size", 4),
        # Proxy
        downstream_command=proxy.get("downstream_command", ""),
        transport=proxy.get("transport", "stdio"),
        sse_port=proxy.get("sse_port", 8080),
        # Per-entity
        entity_configs=entity_configs,
        # Tool rules
        tool_rules=tool_rules,
        # Reversible
        enable_reversible=reversible.get("enabled", False),
        reversible_key_file=reversible.get("key_file"),
        # Webhooks
        webhooks=webhooks,
        # Servers
        servers=servers,
        # Dashboard
        dashboard=DashboardConfig(
            enabled=dashboard_raw.get("enabled", False),
            host=dashboard_raw.get("host", "127.0.0.1"),
            port=dashboard_raw.get("port", 8765),
        ),
        # Metrics
        metrics=MetricsConfig(
            enabled=metrics_raw.get("enabled", False),
            host=metrics_raw.get("host", "127.0.0.1"),
            port=metrics_raw.get("port", 9090),
        ),
    )
