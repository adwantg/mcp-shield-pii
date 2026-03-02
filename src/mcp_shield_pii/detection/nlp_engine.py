"""NLP-based PII detection engine using spaCy NER (optional dependency)."""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from mcp_shield_pii.detection.base import DetectionResult, EntityType

logger = logging.getLogger(__name__)

# Mapping from spaCy NER labels to our EntityType
_SPACY_LABEL_MAP: dict[str, EntityType] = {
    "PERSON": EntityType.PERSON_NAME,
    "ORG": EntityType.ORGANIZATION,
    "GPE": EntityType.LOCATION,
    "LOC": EntityType.LOCATION,
    "FAC": EntityType.ADDRESS,
}


class NLPDetectionEngine:
    """NLP-based detection engine using spaCy for named entity recognition.

    This engine detects unstructured PII that regex cannot reliably find:
    person names, organizations, locations, and addresses.

    Requires: pip install mcp-shield-pii[nlp]
    """

    ENGINE_NAME: ClassVar[str] = "nlp"

    def __init__(self, model_name: str = "en_core_web_sm") -> None:
        self._model_name = model_name
        self._nlp: Any = None
        self._available = False
        self._load_model()

    @property
    def name(self) -> str:
        return self.ENGINE_NAME

    @property
    def available(self) -> bool:
        return self._available

    def _load_model(self) -> None:
        """Attempt to load the spaCy model."""
        try:
            import spacy

            try:
                self._nlp = spacy.load(self._model_name)
                self._available = True
                logger.info("NLP engine loaded model: %s", self._model_name)
            except OSError:
                logger.warning(
                    "spaCy model '%s' not found. Run: python -m spacy download %s",
                    self._model_name,
                    self._model_name,
                )
                self._available = False
        except ImportError:
            logger.info(
                "spaCy not installed. NLP detection disabled. "
                "Install with: pip install mcp-shield-pii[nlp]"
            )
            self._available = False

    def supported_entities(self) -> list[EntityType]:
        return [
            EntityType.PERSON_NAME,
            EntityType.ORGANIZATION,
            EntityType.LOCATION,
            EntityType.ADDRESS,
        ]

    def detect(self, text: str) -> list[DetectionResult]:
        """Run NER on the text and return detected entities."""
        if not self._available or self._nlp is None:
            return []

        results: list[DetectionResult] = []
        doc = self._nlp(text)

        for ent in doc.ents:
            entity_type = _SPACY_LABEL_MAP.get(ent.label_)
            if entity_type is None:
                continue

            # Confidence based on entity label reliability
            confidence = self._estimate_confidence(ent)

            results.append(
                DetectionResult(
                    entity_type=entity_type,
                    start=ent.start_char,
                    end=ent.end_char,
                    text=ent.text,
                    confidence=round(confidence, 3),
                    engine=self.ENGINE_NAME,
                )
            )

        return results

    @staticmethod
    def _estimate_confidence(ent: Any) -> float:
        """Estimate confidence based on entity characteristics."""
        base = 0.75

        # Longer entities are usually more reliable
        if len(ent.text.split()) >= 2:
            base += 0.1

        # All-caps names are less likely to be real names
        if ent.text.isupper() and ent.label_ == "PERSON":
            base -= 0.15

        # Single-character entities are noise
        if len(ent.text.strip()) <= 1:
            base = 0.2

        return min(max(base, 0.0), 1.0)
