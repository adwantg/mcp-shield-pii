# Contributing to mcp-shield-pii

Thank you for contributing! We welcome bug reports, feature requests, and pull requests to improve the privacy architecture of MCP ecosystems.

## Developer Quick Start

```bash
# Clone the repository
git clone https://github.com/gadwant/mcp-shield-pii.git
cd mcp-shield-pii

# Create a virtual environment using Python 3.14+
python3.14 -m venv .venv
source .venv/bin/activate

# Install editable package with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Quality and Acceptance Gates

To get your PR merged, it must pass these local verification steps:

```bash
# 1. Formatting
ruff format .

# 2. Linting
ruff check .

# 3. Type Checking
mypy src

# 4. Tests and Coverage (minimum 90% required)
python -m pytest

# 5. Security Audit
pip-audit
```

## Pull Request Requirements

We enforce strict validation because this package operates as a security/privacy gateway. By contributing, you agree to:

1. **Keep Latency Zero**: Any new processing (especially NLP or RegEx) must happen within an isolated subinterpreter. Blocking the main async event loop is an instant rejection.
2. **Deterministic Output**: If generating schemas or masking entities, ensure the output size/shape is predictable.
3. **No Drift or Regression**: Test against known MCP RPC payloads to ensure changes don't cause infinite masking loops or unhandled exceptions. 
4. **Update README & Docs**: `README_MAINTENANCE_CONTRACT.md` dictates that any behavior change must include an accompanying `README.md` update.
5. **Python 3.14 Only Constraints**: Be careful not to introduce non-subinterpreter-safe C extensions or shared memory traps across `concurrent.interpreters`.

## Issue Reporting

When reporting an issue, please describe:
1. The type of MCP server you were proxying.
2. The payload structure (sanitized, of course).
3. The expected vs actual behavior regarding PII masking.
