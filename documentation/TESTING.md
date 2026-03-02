# Testing Guide — mcp-shield-pii

## Prerequisites

```bash
# Clone and install
git clone https://github.com/gadwant/mcp-shield-pii.git
cd mcp-shield-pii
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running All Tests

```bash
python -m pytest tests/ -v
```

## Test Suite Breakdown

### 1. Regex Detection Engine (`tests/unit/test_regex_engine.py`)

Tests all 18 entity types detected by the regex engine.

```bash
python -m pytest tests/unit/test_regex_engine.py -v
```

| Test Class | What It Covers |
|------------|---------------|
| `TestLuhnCheck` | Credit card Luhn validation |
| `TestEmailDetection` | Simple, multiple, and complex emails |
| `TestSSNDetection` | Valid SSNs and rejection of invalid prefixes (000, 666) |
| `TestCreditCardDetection` | Visa, Mastercard patterns |
| `TestPhoneDetection` | US and international phone formats |
| `TestAPIKeyDetection` | AWS, OpenAI, Stripe, and GitHub tokens |
| `TestIPDetection` | IPv4 and MAC addresses |
| `TestMiscDetection` | JWT tokens, URLs with auth, medical IDs, dates of birth |
| `TestDeduplication` | No overlapping results across patterns |
| `TestNoFalsePositives` | Clean text produces zero results |

### 2. Masking Strategies (`tests/unit/test_masking.py`)

Tests all four masking strategies and the factory function.

```bash
python -m pytest tests/unit/test_masking.py -v
```

| Test Class | What It Covers |
|------------|---------------|
| `TestRedactStrategy` | Entity-type-labeled redaction tags, custom templates |
| `TestPartialStrategy` | Format-aware partial masking for emails, SSNs, cards, phones |
| `TestHashStrategy` | Deterministic hashing, salt support, algorithm selection |
| `TestPseudoAnonymization` | Consistent fake-data mapping, format preservation |
| `TestGetStrategy` | Factory function for all strategies + error for unknown |

### 3. Config & Context Scorer (`tests/unit/test_config_and_scorer.py`)

```bash
python -m pytest tests/unit/test_config_and_scorer.py -v
```

| Test Class | What It Covers |
|------------|---------------|
| `TestConfigLoader` | Default config, missing file fallback, full TOML parsing |
| `TestContextScorer` | SSN context boost, phone number reducer, label pattern matching |

### 4. Pipeline & MCP Interceptor (`tests/unit/test_interceptor.py`)

```bash
python -m pytest tests/unit/test_interceptor.py -v
```

| Test Class | What It Covers |
|------------|---------------|
| `TestPipeline` | End-to-end: no PII, email redaction, multi-entity, dry-run, tool rules |
| `TestMCPInterceptor` | JSON-RPC passthrough, CallToolResult interception, stats tracking |

## Manual Testing

### Test the CLI scan command

```bash
# Basic scan
mcp-shield-pii scan "My email is test@secret.com and SSN 123-45-6789"

# With JSON output
mcp-shield-pii scan --json "Credit card: 4111-1111-1111-1111"

# With partial masking
mcp-shield-pii scan --strategy partial "Phone: 555-123-4567"

# Dry-run (detect but don't mask)
mcp-shield-pii scan --dry-run "AWS key: AKIAIOSFODNN7EXAMPLE"
```

### Test config generation

```bash
mcp-shield-pii generate-config --output test_shield.toml
cat test_shield.toml
```

### Test compliance report

```bash
# First generate some audit events
mcp-shield-pii scan "SSN 123-45-6789, email admin@corp.com"
mcp-shield-pii scan "Card 4111-1111-1111-1111"

# Generate report
mcp-shield-pii report --format text
mcp-shield-pii report --format markdown --output report.md
mcp-shield-pii report --format json
```

### Test the dashboard

```bash
mcp-shield-pii dashboard --port 8765
# Open http://127.0.0.1:8765 in browser
```

### Test proxy mode

```bash
# With a simple echo server
mcp-shield-pii proxy --downstream "echo hello" --dry-run

# With an actual MCP server
mcp-shield-pii proxy --downstream "npx -y @modelcontextprotocol/server-filesystem /tmp" --config shield.toml
```

## Verification Checklist

- [ ] `python -m pytest tests/ -v` — all tests pass
- [ ] `mcp-shield-pii scan` — detects and redacts PII correctly
- [ ] `mcp-shield-pii scan --json` — produces valid JSON
- [ ] `mcp-shield-pii scan --strategy partial` — partial masking works
- [ ] `mcp-shield-pii scan --strategy hash` — hash masking works
- [ ] `mcp-shield-pii scan --strategy pseudo` — pseudo-anonymization works
- [ ] `mcp-shield-pii scan --dry-run` — detects but doesn't modify
- [ ] `mcp-shield-pii generate-config` — generates valid TOML
- [ ] `mcp-shield-pii report` — generates report from audit logs
- [ ] `mcp-shield-pii version` — prints version
- [ ] Dashboard loads at configured port
