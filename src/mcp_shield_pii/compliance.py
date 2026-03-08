"""GDPR/HIPAA compliance report generator from audit logs."""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ComplianceReportGenerator:
    """Generate compliance reports from the audit log.

    Produces structured reports suitable for GDPR/HIPAA compliance reviews.
    """

    def __init__(self, audit_log_file: str = "shield_audit.jsonl") -> None:
        self._audit_file = Path(audit_log_file)

    def generate(self, output_format: str = "text") -> str:
        """Generate a compliance report.

        Args:
            output_format: 'text', 'json', or 'markdown'
        """
        events = self._read_events()
        report_data = self._analyze(events)

        if output_format == "json":
            return json.dumps(report_data, indent=2, default=str)
        if output_format == "markdown":
            return self._to_markdown(report_data)
        return self._to_text(report_data)

    def _read_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if not self._audit_file.exists():
            return events
        with open(self._audit_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return events

    def _analyze(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        redactions = [e for e in events if "entity_type" in e and "masking_strategy" in e]
        summaries = [e for e in events if e.get("event_type") == "scan_summary"]

        entity_counts = Counter(e.get("entity_type", "UNKNOWN") for e in redactions)
        strategy_counts = Counter(e.get("masking_strategy", "unknown") for e in redactions)
        tool_counts = Counter(e.get("tool_name", "unknown") for e in redactions)

        timestamps = [e.get("timestamp", "") for e in events if e.get("timestamp")]
        first = min(timestamps) if timestamps else "N/A"
        last = max(timestamps) if timestamps else "N/A"

        total_scans = len(summaries)
        total_entities = len(redactions)
        avg_confidence = (
            sum(e.get("confidence", 0) for e in redactions) / len(redactions)
            if redactions
            else 0
        )

        return {
            "report_generated": datetime.now(UTC).isoformat(),
            "period_start": first,
            "period_end": last,
            "total_scans": total_scans,
            "total_entities_redacted": total_entities,
            "average_confidence": round(avg_confidence, 3),
            "entity_type_distribution": dict(entity_counts.most_common()),
            "masking_strategy_distribution": dict(strategy_counts.most_common()),
            "tool_distribution": dict(tool_counts.most_common()),
            "dry_run_events": sum(1 for e in redactions if e.get("dry_run")),
            "compliance_status": "COMPLIANT" if total_entities > 0 else "NO_DATA",
        }

    def _to_text(self, data: dict[str, Any]) -> str:
        lines = [
            "=" * 60,
            "mcp-shield-pii COMPLIANCE REPORT",
            "=" * 60,
            f"Generated: {data['report_generated']}",
            f"Period: {data['period_start']} → {data['period_end']}",
            "",
            f"Total Scans: {data['total_scans']}",
            f"Total Entities Redacted: {data['total_entities_redacted']}",
            f"Average Confidence: {data['average_confidence']:.1%}",
            f"Dry-Run Events: {data['dry_run_events']}",
            f"Status: {data['compliance_status']}",
            "",
            "Entity Type Distribution:",
        ]
        for et, count in data["entity_type_distribution"].items():
            lines.append(f"  {et}: {count}")
        lines.append("")
        lines.append("Masking Strategy Distribution:")
        for s, count in data["masking_strategy_distribution"].items():
            lines.append(f"  {s}: {count}")
        lines.append("")
        lines.append("Tool Distribution:")
        for t, count in data["tool_distribution"].items():
            lines.append(f"  {t}: {count}")
        lines.append("=" * 60)
        return "\n".join(lines)

    def _to_markdown(self, data: dict[str, Any]) -> str:
        lines = [
            "# mcp-shield-pii Compliance Report",
            "",
            f"**Generated:** {data['report_generated']}",
            f"**Period:** {data['period_start']} → {data['period_end']}",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Scans | {data['total_scans']} |",
            f"| Entities Redacted | {data['total_entities_redacted']} |",
            f"| Average Confidence | {data['average_confidence']:.1%} |",
            f"| Dry-Run Events | {data['dry_run_events']} |",
            f"| Status | **{data['compliance_status']}** |",
            "",
            "## Entity Types",
            "",
            "| Entity | Count |",
            "|--------|-------|",
        ]
        for et, count in data["entity_type_distribution"].items():
            lines.append(f"| {et} | {count} |")
        lines.extend([
            "",
            "## Tools",
            "",
            "| Tool | Events |",
            "|------|--------|",
        ])
        for t, count in data["tool_distribution"].items():
            lines.append(f"| {t} | {count} |")
        return "\n".join(lines)
