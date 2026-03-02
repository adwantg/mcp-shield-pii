"""Prometheus-compatible metrics endpoint."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class MetricsCollector:
    """Collects and exposes metrics for mcp-shield-pii.

    Tracks entity counts, processing latency, and pool utilization.
    """

    # Counters
    entities_detected_total: int = 0
    entities_redacted_total: int = 0
    messages_scanned_total: int = 0
    messages_passthrough_total: int = 0
    errors_total: int = 0

    # Latency tracking (in milliseconds)
    _latencies: list[float] = field(default_factory=list)

    # Per-entity counters
    entity_type_counts: dict[str, int] = field(default_factory=dict)

    def record_scan(
        self,
        entity_count: int,
        latency_ms: float,
        entity_types: list[str] | None = None,
    ) -> None:
        """Record a scan event."""
        self.messages_scanned_total += 1
        self.entities_detected_total += entity_count
        self.entities_redacted_total += entity_count
        self._latencies.append(latency_ms)

        # Keep only last 1000 latencies
        if len(self._latencies) > 1000:
            self._latencies = self._latencies[-1000:]

        if entity_types:
            for et in entity_types:
                self.entity_type_counts[et] = self.entity_type_counts.get(et, 0) + 1

    def record_passthrough(self) -> None:
        self.messages_passthrough_total += 1

    def record_error(self) -> None:
        self.errors_total += 1

    @property
    def latency_p50(self) -> float:
        return self._percentile(50)

    @property
    def latency_p95(self) -> float:
        return self._percentile(95)

    @property
    def latency_p99(self) -> float:
        return self._percentile(99)

    def _percentile(self, p: int) -> float:
        if not self._latencies:
            return 0.0
        sorted_lat = sorted(self._latencies)
        idx = int(len(sorted_lat) * p / 100)
        idx = min(idx, len(sorted_lat) - 1)
        return round(sorted_lat[idx], 3)

    def to_prometheus(self) -> str:
        """Export metrics in Prometheus text exposition format."""
        lines: list[str] = [
            "# HELP shield_entities_detected_total Total PII entities detected",
            "# TYPE shield_entities_detected_total counter",
            f"shield_entities_detected_total {self.entities_detected_total}",
            "",
            "# HELP shield_entities_redacted_total Total PII entities redacted",
            "# TYPE shield_entities_redacted_total counter",
            f"shield_entities_redacted_total {self.entities_redacted_total}",
            "",
            "# HELP shield_messages_scanned_total Total messages scanned",
            "# TYPE shield_messages_scanned_total counter",
            f"shield_messages_scanned_total {self.messages_scanned_total}",
            "",
            "# HELP shield_messages_passthrough_total Messages passed without scan",
            "# TYPE shield_messages_passthrough_total counter",
            f"shield_messages_passthrough_total {self.messages_passthrough_total}",
            "",
            "# HELP shield_errors_total Total processing errors",
            "# TYPE shield_errors_total counter",
            f"shield_errors_total {self.errors_total}",
            "",
            "# HELP shield_latency_ms Processing latency in milliseconds",
            "# TYPE shield_latency_ms summary",
            f'shield_latency_ms{{quantile="0.5"}} {self.latency_p50}',
            f'shield_latency_ms{{quantile="0.95"}} {self.latency_p95}',
            f'shield_latency_ms{{quantile="0.99"}} {self.latency_p99}',
            "",
        ]

        # Per-entity type counters
        for entity_type, count in sorted(self.entity_type_counts.items()):
            lines.append(
                f'shield_entity_type_total{{type="{entity_type}"}} {count}'
            )

        return "\n".join(lines) + "\n"


async def start_metrics_server(
    collector: MetricsCollector,
    host: str = "127.0.0.1",
    port: int = 9090,
) -> None:
    """Start a simple HTTP server exposing /metrics endpoint."""
    from aiohttp import web

    async def metrics_handler(request: web.Request) -> web.Response:
        return web.Response(
            text=collector.to_prometheus(),
            content_type="text/plain",
        )

    async def health_handler(request: web.Request) -> web.Response:
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_get("/metrics", metrics_handler)
    app.router.add_get("/health", health_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logger.info("Metrics server started on http://%s:%d/metrics", host, port)
