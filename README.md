# mcp-shield-pii

> 🛡️ Real-time PII redaction proxy for MCP clients and servers — zero-latency privacy using Python 3.14 subinterpreters.

**mcp-shield-pii** is an intercepting gateway proxy that sits between your MCP client (e.g., Claude Desktop) and any downstream MCP server. It detects and masks Personally Identifiable Information in real-time before it reaches the LLM's context window, ensuring GDPR/HIPAA compliance with a single `pip install`.

## Why mcp-shield-pii?

When an AI agent requests data from an MCP server, the raw payload — potentially containing SSNs, medical records, or credit cards — flows directly into the LLM. Organizations face potential GDPR/HIPAA fines exceeding hundreds of millions of dollars. **mcp-shield-pii** eliminates this risk at the protocol layer.

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
│ Claude       │────▶│ mcp-shield-pii  │────▶│ Downstream MCP   │
│ Desktop      │◀────│ (PII Redaction)  │◀────│ Server           │
└──────────────┘     └─────────────────┘     └──────────────────┘
                         ▲                           
                    PII masked before               
                    reaching the LLM                
```

## Installation

```bash
pip install mcp-shield-pii
```

For NLP-based detection (names, organizations, addresses):
```bash
pip install mcp-shield-pii[nlp]
python -m spacy download en_core_web_sm
```

## Quick Start

### 1. Scan text for PII

```bash
# Simple scan
mcp-shield-pii scan "Contact john@example.com, SSN 123-45-6789"

# JSON output
mcp-shield-pii scan --json "Patient MRN-123456 at 192.168.1.1"

# Different masking strategies
mcp-shield-pii scan --strategy partial "Card: 4111-1111-1111-1111"
mcp-shield-pii scan --strategy hash "Email: secret@corp.com"
mcp-shield-pii scan --strategy pseudo "Call 555-123-4567"
```

### 2. Start the proxy

```bash
# Basic proxy (stdio transport)
mcp-shield-pii proxy --downstream "npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb"

# With config file
mcp-shield-pii proxy --downstream "python my_server.py" --config shield.toml

# Dry-run mode (log detections, don't modify payloads)
mcp-shield-pii proxy --downstream "npx my-mcp-server" --dry-run
```

### 3. Claude Desktop integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "my-server-shielded": {
      "command": "mcp-shield-pii",
      "args": [
        "proxy",
        "--downstream", "npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb",
        "--config", "/path/to/shield.toml"
      ]
    }
  }
}
```

### 4. Generate a config file

```bash
mcp-shield-pii generate-config --output shield.toml
```

### 5. Generate a compliance report

```bash
mcp-shield-pii report --format markdown --output compliance_report.md
```

### 6. Launch the dashboard

```bash
mcp-shield-pii dashboard --port 8765
# Open http://127.0.0.1:8765
```

## Features

### v1.0 — Core

| Feature | Description |
|---------|-------------|
| **Stdio Proxy** | Intercepts MCP stdio transport between client and downstream server |
| **Regex Engine (18 types)** | Detects SSNs, credit cards, emails, phones, IBANs, API keys, JWTs, and more |
| **NLP Engine** | Optional spaCy NER for person names, organizations, locations, addresses |
| **Masking Strategies** | `redact` (`<REDACTED>`), `partial` (`***-**-6789`), `hash` (`SHA256:a1b2...`), `pseudo` (consistent fakes) |
| **TOML Configuration** | Per-entity rules, per-tool allow/deny lists, confidence thresholds |
| **CallToolResult Interception** | Targets JSON-RPC responses while passing non-sensitive RPCs through |
| **Audit Trail** | JSONL audit log with timestamps, entity types, confidence scores |
| **CLI** | `proxy`, `scan`, `report`, `dashboard`, `generate-config`, `version` |

### v1.1 — Hardening

| Feature | Description |
|---------|-------------|
| **Context-Aware Scoring** | Reduces false positives by analyzing surrounding text |
| **Confidence Thresholds** | Per-entity-type configurable minimum confidence |
| **Tool Allow/Deny Lists** | Skip trusted tools, enforce strict mode on sensitive ones |
| **Dry-Run Mode** | Log what would be redacted without modifying payloads |
| **Hot-Reload Config** | Change rules without restarting the proxy |
| **Prometheus Metrics** | `/metrics` endpoint with latency percentiles and entity counters |

### v2.0 — Enterprise

| Feature | Description |
|---------|-------------|
| **Pseudo-Anonymization** | Consistent fake-data mapping preserving semantic meaning |
| **Reversible Redaction** | AES-256 encrypted mapping — authorized key-holders can restore originals |
| **Compliance Dashboard** | Dark-mode web UI with real-time event table and severity badges |
| **GDPR/HIPAA Reports** | Auto-generated compliance reports (text, JSON, markdown) |
| **Webhook Alerts** | Notify Slack/Teams when high-severity PII is detected |
| **Subinterpreter Pool** | Python 3.14 `concurrent.interpreters` for GIL-free parallel detection |

## Detected Entity Types

### Regex-Based (18 types)

| Entity | Example | Validation |
|--------|---------|------------|
| Email | `user@example.com` | Regex |
| Phone | `+1-555-123-4567` | Regex |
| SSN | `123-45-6789` | Regex + format validation |
| Credit Card | `4111-1111-1111-1111` | Regex + Luhn checksum |
| IBAN | `DE89370400440532013000` | Regex + country-code length |
| IPv4 | `192.168.1.1` | Regex |
| IPv6 | `2001:0db8::1` | Regex |
| MAC Address | `00:1A:2B:3C:4D:5E` | Regex |
| AWS API Key | `AKIA...` | Regex (prefix) |
| OpenAI Key | `sk-...` | Regex (prefix) |
| Stripe Key | `sk_live_...` | Regex (prefix) |
| GitHub Token | `ghp_...` | Regex (prefix) |
| Passport | `A12345678` | Regex |
| Date of Birth | `1990-01-15` | Regex |
| Medical ID | `MRN-123456` | Regex |
| Driver's License | `D123-4567-8901` | Regex |
| URL with Auth | `https://user:pass@host` | Regex |
| JWT Token | `eyJhbG...` | Regex (prefix) |

### NLP-Based (5 types, requires `[nlp]` extra)

| Entity | Example |
|--------|---------|
| Person Name | `John Smith` |
| Organization | `Acme Corp` |
| Address | `123 Main St, Springfield` |
| Location | `New York City` |
| Medical Condition | `Type 2 diabetes` |

## Configuration (shield.toml)

```toml
[shield]
default_masking_strategy = "redact"
default_confidence_threshold = 0.7
dry_run = false

[detection]
enable_regex = true
enable_nlp = false
enable_context_scoring = true

[entities.SSN]
masking_strategy = "redact"
confidence_threshold = 0.8

[entities.EMAIL]
masking_strategy = "pseudo"
confidence_threshold = 0.7

[tools.trusted_internal_tool]
action = "skip"

[tools.patient_records_api]
action = "strict"
masking_strategy = "redact"

[[webhooks]]
url = "https://hooks.slack.com/services/YOUR/WEBHOOK"
events = ["high_severity"]

[dashboard]
enabled = true
port = 8765

[metrics]
enabled = true
port = 9090
```

## Programmatic API

```python
from mcp_shield_pii.detection.regex_engine import RegexDetectionEngine
from mcp_shield_pii.masking.strategies import get_strategy
from mcp_shield_pii.pipeline import ShieldPipeline
from mcp_shield_pii.config.loader import ShieldConfig

# Simple detection
engine = RegexDetectionEngine()
results = engine.detect("Email john@corp.com, SSN 123-45-6789")
for r in results:
    print(f"{r.entity_type.value}: '{r.text}' (confidence: {r.confidence:.0%})")

# Full pipeline
config = ShieldConfig(default_masking_strategy="partial")
pipeline = ShieldPipeline(config)
masked, summary = pipeline.process_text("Contact admin@secret.org, card 4111-1111-1111-1111")
print(masked)  # "Contact a***@***.org, card ****-****-****-1111"
pipeline.close()

# Pseudo-anonymization
config = ShieldConfig(default_masking_strategy="pseudo")
pipeline = ShieldPipeline(config)
masked, _ = pipeline.process_text("Email alice@corp.com then alice@corp.com again")
print(masked)  # Same fake email both times (consistent mapping)
pipeline.close()
```

## Architecture

```
src/mcp_shield_pii/
├── __init__.py          # Public API exports
├── cli.py               # Typer CLI (6 commands)
├── pipeline.py          # Orchestration: detect → score → filter → mask → audit
├── compliance.py        # GDPR/HIPAA report generator
├── webhooks.py          # Async webhook alerts
├── detection/
│   ├── base.py          # EntityType enum, DetectionResult, protocols
│   ├── regex_engine.py  # 18 regex patterns + Luhn/IBAN validation
│   ├── nlp_engine.py    # spaCy NER detection (optional)
│   └── context_scorer.py # Context-aware confidence adjustment
├── masking/
│   ├── strategies.py    # Redact, partial, hash, pseudo-anonymization
│   └── reversible.py    # AES-256 Fernet reversible redaction
├── config/
│   ├── loader.py        # TOML config parser
│   └── watcher.py       # Hot-reload file watcher
├── proxy/
│   ├── __init__.py      # MCP JSON-RPC interceptor
│   └── stdio_proxy.py   # Bidirectional stdio transport
├── concurrency/
│   └── __init__.py      # Subinterpreter pool + ProcessPool fallback
├── metrics/
│   └── __init__.py      # Prometheus metrics + HTTP server
├── audit/
│   └── __init__.py      # JSONL audit logger
└── dashboard/
    └── __init__.py      # Web UI + REST API
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT — see [LICENSE](LICENSE) for details.
