"""Reversible redaction using AES-256 encryption for authorized recovery."""

from __future__ import annotations

import base64
import json
import logging
import os
from pathlib import Path
from typing import Any

from mcp_shield_pii.detection.base import DetectionResult

logger = logging.getLogger(__name__)


class ReversibleRedactor:
    """AES-256 encrypted mapping store for reversible PII redaction.

    Only authorized key-holders can restore original PII values.
    Requires: pip install cryptography
    """

    def __init__(self, key_file: str | Path | None = None) -> None:
        self._key: bytes | None = None
        self._mapping: dict[str, str] = {}  # token -> encrypted original
        self._counter = 0
        self._available = False
        self._init_encryption(key_file)

    @property
    def available(self) -> bool:
        return self._available

    def _init_encryption(self, key_file: str | Path | None) -> None:
        try:
            from cryptography.fernet import Fernet

            if key_file and Path(key_file).exists():
                self._key = Path(key_file).read_bytes().strip()
                logger.info("Loaded encryption key from: %s", key_file)
            else:
                self._key = Fernet.generate_key()
                if key_file:
                    Path(key_file).write_bytes(self._key)
                    logger.info("Generated and saved encryption key to: %s", key_file)
                else:
                    logger.info("Generated in-memory encryption key (session only).")

            self._available = True
        except ImportError:
            logger.warning(
                "cryptography not installed. Reversible redaction disabled. "
                "Install with: pip install cryptography"
            )
            self._available = False

    def redact(self, result: DetectionResult) -> str:
        """Redact a PII entity and store the encrypted original."""
        if not self._available or self._key is None:
            return f"<{result.entity_type.value}_REDACTED>"

        from cryptography.fernet import Fernet

        fernet = Fernet(self._key)

        # Create a unique token for this entity
        self._counter += 1
        token = f"__SHIELD_{result.entity_type.value}_{self._counter:06d}__"

        # Encrypt the original value
        encrypted = fernet.encrypt(result.text.encode("utf-8")).decode("utf-8")
        self._mapping[token] = encrypted

        return token

    def restore(self, token: str) -> str | None:
        """Restore the original value from a redaction token."""
        if not self._available or self._key is None:
            return None

        from cryptography.fernet import Fernet

        encrypted = self._mapping.get(token)
        if encrypted is None:
            return None

        try:
            fernet = Fernet(self._key)
            return fernet.decrypt(encrypted.encode("utf-8")).decode("utf-8")
        except Exception as e:
            logger.error("Failed to decrypt token %s: %s", token, e)
            return None

    def restore_text(self, text: str) -> str:
        """Restore all redaction tokens in a text string."""
        for token in self._mapping:
            if token in text:
                original = self.restore(token)
                if original:
                    text = text.replace(token, original)
        return text

    def export_mapping(self, path: str | Path) -> None:
        """Export the encrypted mapping to a JSON file."""
        Path(path).write_text(
            json.dumps(self._mapping, indent=2), encoding="utf-8"
        )

    def import_mapping(self, path: str | Path) -> None:
        """Import an encrypted mapping from a JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self._mapping.update(data)
