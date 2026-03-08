"""CLI entrypoint for mcp-shield-pii."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mcp_shield_pii import __version__

app = typer.Typer(
    name="mcp-shield-pii",
    help="🛡️ Real-time PII redaction proxy for MCP clients and servers.",
    add_completion=False,
)
console = Console()


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


@app.command()
def proxy(
    downstream: str = typer.Option(
        ..., "--downstream", "-d", help="Downstream MCP server command to proxy"
    ),
    config: str | None = typer.Option(
        None, "--config", "-c", help="Path to shield.toml config file"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Log detections without modifying payloads"
    ),
    log_level: str = typer.Option("INFO", "--log-level", help="Logging level"),
) -> None:
    """Start the PII redaction proxy."""
    _setup_logging(log_level)
    from mcp_shield_pii.config.loader import ShieldConfig, load_config
    from mcp_shield_pii.pipeline import ShieldPipeline
    from mcp_shield_pii.proxy import MCPInterceptor
    from mcp_shield_pii.proxy.stdio_proxy import StdioProxy

    cfg = load_config(config) if config else ShieldConfig()
    cfg.downstream_command = downstream
    cfg.dry_run = dry_run

    pipeline = ShieldPipeline(cfg)
    interceptor = MCPInterceptor(pipeline)
    stdio_proxy = StdioProxy(downstream, interceptor)

    console.print(f"[bold green]🛡️ mcp-shield-pii v{__version__}[/bold green]")
    console.print(f"   Downstream: [cyan]{downstream}[/cyan]")
    console.print(f"   Dry-run: {'[yellow]YES[/yellow]' if dry_run else '[green]NO[/green]'}")
    if config:
        console.print(f"   Config: [cyan]{config}[/cyan]")

    try:
        asyncio.run(stdio_proxy.start())
    except KeyboardInterrupt:
        console.print("\n[yellow]Proxy stopped.[/yellow]")
    finally:
        pipeline.close()


@app.command()
def scan(
    text: str = typer.Argument(..., help="Text to scan for PII"),
    strategy: str = typer.Option("redact", "--strategy", "-s", help="Masking strategy"),
    config: str | None = typer.Option(None, "--config", "-c"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Scan a text string for PII and display results."""
    from mcp_shield_pii.config.loader import ShieldConfig, load_config
    from mcp_shield_pii.pipeline import ShieldPipeline

    cfg = load_config(config) if config else ShieldConfig()
    cfg.default_masking_strategy = strategy
    cfg.dry_run = dry_run

    pipeline = ShieldPipeline(cfg)
    masked, summary = pipeline.process_text(text)
    pipeline.close()

    if output_json:
        result = {
            "original": text,
            "masked": masked,
            "dry_run": dry_run,
            "entities": [
                {
                    "type": r.entity_type.value,
                    "text": r.text,
                    "start": r.start,
                    "end": r.end,
                    "confidence": r.confidence,
                    "engine": r.engine,
                }
                for r in summary.results
            ],
            "processing_time_ms": round(summary.processing_time_ms, 3),
        }
        console.print_json(json.dumps(result))
        return

    if not summary.has_pii:
        console.print("[green]✅ No PII detected.[/green]")
        return

    console.print(f"\n[bold red]🔍 Found {len(summary.results)} PII entities:[/bold red]\n")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Type", style="cyan")
    table.add_column("Text", style="red")
    table.add_column("Confidence", justify="right")
    table.add_column("Engine")

    for r in summary.results:
        table.add_row(
            r.entity_type.value,
            r.text,
            f"{r.confidence:.0%}",
            r.engine,
        )

    console.print(table)
    console.print(f"\n[bold]Masked output:[/bold]\n{masked}")
    console.print(f"\n[dim]Processed in {summary.processing_time_ms:.2f}ms[/dim]")


@app.command()
def report(
    audit_log: str = typer.Option(
        "shield_audit.jsonl", "--audit-log", help="Path to audit JSONL file"
    ),
    output_format: str = typer.Option(
        "text", "--format", "-f", help="Output format: text, json, markdown"
    ),
    output_file: str | None = typer.Option(
        None, "--output", "-o", help="Write report to file"
    ),
) -> None:
    """Generate a GDPR/HIPAA compliance report from audit logs."""
    from mcp_shield_pii.compliance import ComplianceReportGenerator

    generator = ComplianceReportGenerator(audit_log_file=audit_log)
    report_text = generator.generate(output_format=output_format)

    if output_file:
        Path(output_file).write_text(report_text, encoding="utf-8")
        console.print(f"[green]Report written to {output_file}[/green]")
    else:
        console.print(report_text)


@app.command()
def dashboard(
    audit_log: str = typer.Option(
        "shield_audit.jsonl", "--audit-log", help="Path to audit JSONL file"
    ),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8765, "--port"),
) -> None:
    """Launch the compliance monitoring dashboard."""
    from mcp_shield_pii.dashboard import DashboardServer

    server = DashboardServer(audit_log_file=audit_log, host=host, port=port)
    console.print(f"[bold green]🛡️ Dashboard starting at http://{host}:{port}[/bold green]")

    try:
        asyncio.run(server.start())
        # Keep running
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Dashboard stopped.[/yellow]")


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"[bold]mcp-shield-pii[/bold] v{__version__}")


@app.command()
def generate_config(
    output: str = typer.Option(
        "shield.toml", "--output", "-o", help="Output config file path"
    ),
) -> None:
    """Generate a sample shield.toml configuration file."""
    sample = '''# mcp-shield-pii configuration
# See: https://github.com/gadwant/mcp-shield-pii

[shield]
default_masking_strategy = "redact"   # redact | partial | hash | pseudo
default_confidence_threshold = 0.7
dry_run = false
log_level = "INFO"
audit_log_file = "shield_audit.jsonl"

[proxy]
downstream_command = "npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb"
transport = "stdio"   # stdio | sse
sse_port = 8080

[detection]
enable_regex = true
enable_nlp = false
enable_context_scoring = true
nlp_model = "en_core_web_sm"

[concurrency]
pool_size = 4

# Per-entity configuration
[entities.SSN]
enabled = true
masking_strategy = "redact"
confidence_threshold = 0.8

[entities.CREDIT_CARD]
enabled = true
masking_strategy = "partial"
confidence_threshold = 0.85

[entities.EMAIL]
enabled = true
masking_strategy = "pseudo"
confidence_threshold = 0.7

[entities.API_KEY_AWS]
enabled = true
masking_strategy = "redact"
confidence_threshold = 0.9

# Tool-specific rules
[tools.trusted_internal_tool]
action = "skip"

[tools.patient_records_api]
action = "strict"
masking_strategy = "redact"

# Reversible redaction (requires: pip install cryptography)
[reversible]
enabled = false
key_file = ".shield_key"

# Webhook alerts
[[webhooks]]
url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
events = ["high_severity"]
min_severity = "high"

# Dashboard
[dashboard]
enabled = false
host = "127.0.0.1"
port = 8765

# Metrics
[metrics]
enabled = false
host = "127.0.0.1"
port = 9090
'''
    Path(output).write_text(sample, encoding="utf-8")
    console.print(f"[green]Sample config written to {output}[/green]")


if __name__ == "__main__":
    app()
