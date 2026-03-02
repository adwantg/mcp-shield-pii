"""mcp-shield-pii: Real-time PII redaction proxy for MCP clients and servers."""

__version__ = "2.0.0"

from mcp_shield_pii.detection.base import DetectionResult, EntityType
from mcp_shield_pii.detection.regex_engine import RegexDetectionEngine
from mcp_shield_pii.masking.strategies import (
    HashMaskingStrategy,
    MaskingStrategy,
    PartialMaskingStrategy,
    RedactMaskingStrategy,
)
from mcp_shield_pii.config.loader import ShieldConfig, load_config

__all__ = [
    "__version__",
    "DetectionResult",
    "EntityType",
    "RegexDetectionEngine",
    "MaskingStrategy",
    "RedactMaskingStrategy",
    "PartialMaskingStrategy",
    "HashMaskingStrategy",
    "ShieldConfig",
    "load_config",
]
