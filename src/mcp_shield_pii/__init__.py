"""mcp-shield-pii: Real-time PII redaction proxy for MCP clients and servers."""

__version__ = "1.0.0"

from mcp_shield_pii.config.loader import ShieldConfig, load_config
from mcp_shield_pii.detection.base import DetectionResult, EntityType
from mcp_shield_pii.detection.regex_engine import RegexDetectionEngine
from mcp_shield_pii.masking.strategies import (
    HashMaskingStrategy,
    MaskingStrategy,
    PartialMaskingStrategy,
    RedactMaskingStrategy,
)

__all__ = [
    "DetectionResult",
    "EntityType",
    "HashMaskingStrategy",
    "MaskingStrategy",
    "PartialMaskingStrategy",
    "RedactMaskingStrategy",
    "RegexDetectionEngine",
    "ShieldConfig",
    "__version__",
    "load_config",
]
