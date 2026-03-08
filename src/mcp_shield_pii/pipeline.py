"""Core pipeline that orchestrates detection, scoring, masking, and audit logging."""

from __future__ import annotations

import logging
import time

from mcp_shield_pii.audit import AuditLogger
from mcp_shield_pii.config.loader import ShieldConfig
from mcp_shield_pii.detection.base import DetectionResult, DetectionSummary
from mcp_shield_pii.detection.context_scorer import ContextScorer
from mcp_shield_pii.detection.nlp_engine import NLPDetectionEngine
from mcp_shield_pii.detection.regex_engine import RegexDetectionEngine
from mcp_shield_pii.masking.reversible import ReversibleRedactor
from mcp_shield_pii.masking.strategies import MaskingStrategy, get_strategy

logger = logging.getLogger(__name__)


class ShieldPipeline:
    """The main PII detection and masking pipeline.

    Orchestrates: Detection → Context Scoring → Confidence Filtering →
                  Masking → Audit Logging
    """

    def __init__(self, config: ShieldConfig) -> None:
        self._config = config

        # Detection engines
        self._regex_engine = RegexDetectionEngine() if config.enable_regex else None
        self._nlp_engine: NLPDetectionEngine | None = None
        if config.enable_nlp:
            self._nlp_engine = NLPDetectionEngine(model_name=config.nlp_model)

        # Context scorer
        self._context_scorer: ContextScorer | None = None
        if config.enable_context_scoring:
            self._context_scorer = ContextScorer()

        # Masking
        self._default_strategy = get_strategy(config.default_masking_strategy)
        self._entity_strategies: dict[str, MaskingStrategy] = {}
        for entity_name, entity_cfg in config.entity_configs.items():
            self._entity_strategies[entity_name] = get_strategy(
                entity_cfg.masking_strategy
            )

        # Reversible redaction
        self._reversible: ReversibleRedactor | None = None
        if config.enable_reversible:
            self._reversible = ReversibleRedactor(
                key_file=config.reversible_key_file
            )

        # Audit
        self._audit = AuditLogger(
            log_file=config.audit_log_file,
            dry_run=config.dry_run,
        )

        # Tool rules lookup
        self._tool_rules: dict[str, str] = {}
        for rule in config.tool_rules:
            self._tool_rules[rule.tool_name] = rule.action

    @property
    def config(self) -> ShieldConfig:
        return self._config

    def update_config(self, config: ShieldConfig) -> None:
        """Hot-reload configuration."""
        self._config = config
        self._default_strategy = get_strategy(config.default_masking_strategy)
        logger.info("Pipeline config updated.")

    def should_scan_tool(self, tool_name: str) -> bool:
        """Check if a tool should be scanned based on tool rules."""
        action = self._tool_rules.get(tool_name, "scan")
        return action != "skip"

    def process_text(
        self,
        text: str,
        tool_name: str = "unknown",
    ) -> tuple[str, DetectionSummary]:
        """Process text through the full pipeline.

        Returns: (masked_text, detection_summary)
        """
        start_time = time.perf_counter()

        # Check tool rules
        if not self.should_scan_tool(tool_name):
            return text, DetectionSummary(original_text=text)

        # Step 1: Detection
        all_results: list[DetectionResult] = []

        if self._regex_engine is not None:
            all_results.extend(self._regex_engine.detect(text))

        if self._nlp_engine is not None and self._nlp_engine.available:
            nlp_results = self._nlp_engine.detect(text)
            all_results.extend(nlp_results)

        # Step 2: Context scoring
        if self._context_scorer is not None and all_results:
            all_results = self._context_scorer.score(text, all_results)

        # Step 3: Confidence filtering
        filtered = self._filter_by_confidence(all_results)

        # Step 4: Deduplicate across engines
        filtered = self._deduplicate_cross_engine(filtered)

        # Step 5: Masking
        if self._config.dry_run:
            masked_text = text  # Don't modify in dry-run
        else:
            masked_text = self._apply_masking(text, filtered, tool_name)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Step 6: Audit logging
        self._audit.log_scan_summary(
            tool_name=tool_name,
            total_entities=len(filtered),
            entity_counts={
                r.entity_type.value: 1 for r in filtered
            },
            processing_time_ms=elapsed_ms,
        )

        summary = DetectionSummary(
            original_text=text,
            results=filtered,
            processing_time_ms=elapsed_ms,
        )

        return masked_text, summary

    def _filter_by_confidence(
        self, results: list[DetectionResult]
    ) -> list[DetectionResult]:
        """Filter results by per-entity confidence thresholds."""
        filtered: list[DetectionResult] = []
        for r in results:
            entity_name = r.entity_type.value
            entity_cfg = self._config.entity_configs.get(entity_name)

            # Check if entity type is disabled
            if entity_cfg and not entity_cfg.enabled:
                continue

            threshold = (
                entity_cfg.confidence_threshold
                if entity_cfg
                else self._config.default_confidence_threshold
            )

            if r.confidence >= threshold:
                filtered.append(r)

        return filtered

    def _deduplicate_cross_engine(
        self, results: list[DetectionResult]
    ) -> list[DetectionResult]:
        """Remove overlapping detections across engines."""
        if not results:
            return results
        sorted_results = sorted(results, key=lambda r: (-r.confidence, r.start))
        kept: list[DetectionResult] = []
        for result in sorted_results:
            overlaps = False
            for existing in kept:
                if result.start < existing.end and result.end > existing.start:
                    overlaps = True
                    break
            if not overlaps:
                kept.append(result)
        return sorted(kept, key=lambda r: r.start)

    def _apply_masking(
        self,
        text: str,
        results: list[DetectionResult],
        tool_name: str,
    ) -> str:
        """Apply masking to all detected entities, working from end to start."""
        # Sort by position descending to preserve indices
        sorted_results = sorted(results, key=lambda r: r.start, reverse=True)

        masked = text
        for result in sorted_results:
            strategy = self._get_strategy_for(result)
            replacement = strategy.mask(result)

            # Log each redaction
            self._audit.log_redaction(
                result=result,
                masked_text=replacement,
                masking_strategy=strategy.name,
                tool_name=tool_name,
            )

            masked = masked[: result.start] + replacement + masked[result.end :]

        return masked

    def _get_strategy_for(self, result: DetectionResult) -> MaskingStrategy:
        """Get the masking strategy for a specific entity type."""
        entity_name = result.entity_type.value

        # Check for entity-specific strategy
        if entity_name in self._entity_strategies:
            return self._entity_strategies[entity_name]

        # Check for reversible redaction
        if self._reversible and self._reversible.available:
            return _ReversibleWrapper(self._reversible)

        return self._default_strategy

    def restore_text(self, text: str) -> str | None:
        """Restore reversibly-redacted text (requires key)."""
        if self._reversible:
            return self._reversible.restore_text(text)
        return None

    def close(self) -> None:
        """Clean up resources."""
        self._audit.close()


class _ReversibleWrapper(MaskingStrategy):
    """Adapter that wraps ReversibleRedactor as a MaskingStrategy."""

    def __init__(self, redactor: ReversibleRedactor) -> None:
        self._redactor = redactor

    @property
    def name(self) -> str:
        return "reversible"

    def mask(self, result: DetectionResult) -> str:
        return self._redactor.redact(result)
