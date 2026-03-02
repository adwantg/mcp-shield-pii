"""Hot-reload watcher for config files using watchfiles."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable

from mcp_shield_pii.config.loader import ShieldConfig, load_config

logger = logging.getLogger(__name__)


class ConfigWatcher:
    """Watch a TOML config file for changes and trigger reload callbacks.

    Uses watchfiles for efficient filesystem watching.
    """

    def __init__(
        self,
        config_path: str | Path,
        on_reload: Callable[[ShieldConfig], None] | None = None,
    ) -> None:
        self._path = Path(config_path)
        self._on_reload = on_reload
        self._task: asyncio.Task[None] | None = None
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    async def start(self) -> None:
        """Start watching the config file."""
        self._running = True
        self._task = asyncio.create_task(self._watch_loop())
        logger.info("Config watcher started for: %s", self._path)

    async def stop(self) -> None:
        """Stop watching."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Config watcher stopped.")

    async def _watch_loop(self) -> None:
        """Main watch loop using watchfiles."""
        try:
            from watchfiles import awatch

            async for _changes in awatch(self._path):
                if not self._running:
                    break
                logger.info("Config file changed, reloading: %s", self._path)
                try:
                    new_config = load_config(self._path)
                    if self._on_reload:
                        self._on_reload(new_config)
                    logger.info("Config reloaded successfully.")
                except Exception as e:
                    logger.error("Failed to reload config: %s", e)
        except ImportError:
            logger.warning(
                "watchfiles not installed. Hot-reload disabled. "
                "Install with: pip install watchfiles"
            )
        except asyncio.CancelledError:
            pass
