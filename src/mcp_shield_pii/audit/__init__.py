"""Structured JSON audit logger for PII redaction events."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from mcp_shield_pii.detection.base import DetectionResult

logger = logging.getLogger(__name__)


@dataclass
class AuditEvent:
    """A single audit log entry for a redaction event."""

    timestamp: str
    tool_name: str
    entity_type: str
    original_length: int
    masked_text: str
    confidence: float
    engine: str
    masking_strategy: str
    dry_run: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


class AuditLogger:
    """Structured JSONL audit logger for compliance trail.

    Writes one JSON object per line to the audit log file.
    """

    def __init__(
        self,
        log_file: str | Path = "shield_audit.jsonl",
        dry_run: bool = False,
    ) -> None:
        self._log_file = Path(log_file)
        self._dry_run = dry_run
        self._handle: TextIO | None = None
        self._event_count = 0
        self._open()

    def _open(self) -> None:
        try:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            self._handle = open(self._log_file, "a", encoding="utf-8")
            logger.info("Audit log opened: %s", self._log_file)
        except OSError as e:
            logger.error("Failed to open audit log: %s", e)

    def log_redaction(
        self,
        result: DetectionResult,
        masked_text: str,
        masking_strategy: str,
        tool_name: str = "unknown",
    ) -> None:
        """Log a single redaction event."""
        event = AuditEvent(
            timestamp=datetime.now(UTC).isoformat(),
            tool_name=tool_name,
            entity_type=result.entity_type.value,
            original_length=len(result.text),
            masked_text=masked_text,
            confidence=result.confidence,
            engine=result.engine,
            masking_strategy=masking_strategy,
            dry_run=self._dry_run,
        )
        self._write_event(event)

    def log_scan_summary(
        self,
        tool_name: str,
        total_entities: int,
        entity_counts: dict[str, int],
        processing_time_ms: float,
    ) -> None:
        """Log a summary of a scan operation."""
        summary = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": "scan_summary",
            "tool_name": tool_name,
            "total_entities": total_entities,
            "entity_counts": entity_counts,
            "processing_time_ms": round(processing_time_ms, 3),
            "dry_run": self._dry_run,
        }
        self._write_json(summary)

    def _write_event(self, event: AuditEvent) -> None:
        self._write_json(asdict(event))

    def _write_json(self, data: dict[str, Any]) -> None:
        if self._handle is None:
            return
        try:
            self._handle.write(json.dumps(data, default=str) + "\n")
            self._handle.flush()
            self._event_count += 1
        except OSError as e:
            logger.error("Failed to write audit event: %s", e)

    @property
    def event_count(self) -> int:
        return self._event_count

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
