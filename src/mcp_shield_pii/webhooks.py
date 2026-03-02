"""Webhook alert system for high-severity PII detection events."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from mcp_shield_pii.config.loader import WebhookConfig
from mcp_shield_pii.detection.base import DetectionResult, EntityType

logger = logging.getLogger(__name__)

# Entities considered high severity
HIGH_SEVERITY_ENTITIES: set[EntityType] = {
    EntityType.SSN,
    EntityType.CREDIT_CARD,
    EntityType.MEDICAL_ID,
    EntityType.MEDICAL_CONDITION,
    EntityType.PASSPORT_NUMBER,
    EntityType.API_KEY_AWS,
    EntityType.API_KEY_OPENAI,
    EntityType.API_KEY_STRIPE,
    EntityType.API_KEY_GITHUB,
    EntityType.JWT_TOKEN,
}


def get_severity(entity_type: EntityType) -> str:
    """Determine severity level for an entity type."""
    if entity_type in HIGH_SEVERITY_ENTITIES:
        return "high"
    return "medium"


class WebhookAlert:
    """Send webhook alerts when high-severity PII is detected."""

    def __init__(self, configs: list[WebhookConfig]) -> None:
        self._configs = configs

    async def alert(
        self,
        results: list[DetectionResult],
        tool_name: str,
    ) -> None:
        """Send alerts for matching events."""
        if not self._configs:
            return

        for result in results:
            severity = get_severity(result.entity_type)
            for config in self._configs:
                if severity == "high" and "high_severity" in config.events:
                    await self._send(config, result, tool_name)

    async def _send(
        self,
        config: WebhookConfig,
        result: DetectionResult,
        tool_name: str,
    ) -> None:
        """Send a single webhook POST request."""
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "pii_detected",
            "severity": get_severity(result.entity_type),
            "entity_type": result.entity_type.value,
            "tool_name": tool_name,
            "confidence": result.confidence,
            "engine": result.engine,
            "message": (
                f"High-severity PII ({result.entity_type.value}) detected "
                f"in tool '{tool_name}' with confidence {result.confidence:.2f}"
            ),
        }

        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    config.url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if response.status_code < 300:
                    logger.info("Webhook sent to %s", config.url)
                else:
                    logger.warning(
                        "Webhook failed (%d) for %s",
                        response.status_code,
                        config.url,
                    )
        except ImportError:
            logger.warning("httpx not installed. Webhook alerts disabled.")
        except Exception as e:
            logger.error("Webhook error for %s: %s", config.url, e)
