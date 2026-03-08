"""Stdio transport proxy — sits between MCP client and downstream server."""

from __future__ import annotations

import asyncio
import logging
import shlex
import sys

from mcp_shield_pii.proxy import MCPInterceptor

logger = logging.getLogger(__name__)


class StdioProxy:
    """Bidirectional stdio proxy between an MCP client and a downstream server.

    Intercepts server→client responses for PII redaction while passing
    client→server requests transparently.
    """

    def __init__(
        self,
        downstream_command: str,
        interceptor: MCPInterceptor,
    ) -> None:
        self._downstream_cmd = downstream_command
        self._interceptor = interceptor
        self._process: asyncio.subprocess.Process | None = None
        self._running = False

    async def start(self) -> None:
        """Start the proxy, spawning the downstream MCP server."""
        args = shlex.split(self._downstream_cmd)
        logger.info("Starting downstream MCP server: %s", self._downstream_cmd)

        self._process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        self._running = True
        logger.info("Stdio proxy started (PID: %s)", self._process.pid)

        # Run bidirectional forwarding
        await asyncio.gather(
            self._forward_client_to_server(),
            self._forward_server_to_client(),
            self._forward_stderr(),
        )

    async def _forward_client_to_server(self) -> None:
        """Forward stdin (client) → downstream server stdin."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_running_loop().connect_read_pipe(
            lambda: protocol, sys.stdin.buffer
        )

        try:
            while self._running:
                line = await reader.readline()
                if not line:
                    break

                # Pass requests through (we only intercept responses)
                if self._process and self._process.stdin:
                    self._process.stdin.write(line)
                    await self._process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            logger.info("Client connection closed.")
        finally:
            if self._process and self._process.stdin:
                self._process.stdin.close()

    async def _forward_server_to_client(self) -> None:
        """Forward downstream server stdout → stdout (client), with interception."""
        if self._process is None or self._process.stdout is None:
            return

        stdout_writer = asyncio.StreamWriter(
            transport=sys.stdout.buffer,  # type: ignore[arg-type]
            protocol=asyncio.StreamReaderProtocol(asyncio.StreamReader()),
            reader=None,
            loop=asyncio.get_running_loop(),
        )

        try:
            while self._running:
                line = await self._process.stdout.readline()
                if not line:
                    break

                raw = line.decode("utf-8", errors="replace").rstrip("\n")
                if raw:
                    # Intercept and potentially redact
                    processed = self._interceptor.intercept(raw)
                    sys.stdout.write(processed + "\n")
                    sys.stdout.flush()
        except (BrokenPipeError, ConnectionResetError):
            logger.info("Server connection closed.")

    async def _forward_stderr(self) -> None:
        """Forward downstream server stderr → our stderr."""
        if self._process is None or self._process.stderr is None:
            return

        try:
            while self._running:
                line = await self._process.stderr.readline()
                if not line:
                    break
                sys.stderr.buffer.write(line)
                sys.stderr.buffer.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    async def stop(self) -> None:
        """Stop the proxy and terminate the downstream server."""
        self._running = False
        if self._process is not None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except TimeoutError:
                self._process.kill()
            logger.info("Downstream server terminated.")
