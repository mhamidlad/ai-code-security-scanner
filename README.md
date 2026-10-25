# AI Code Security Scanner

> **AI writes code. I help make that code secure.**

A static analysis tool for identifying common security vulnerabilities in Python and JavaScript code. Built for developers using AI coding assistants who need to verify the security of generated code.

## Why This Exists

AI coding assistants (Copilot, ChatGPT, Cursor, etc.) produce functional code quickly. But *functional* does not mean *secure*. Generated code can contain:

- SQL injection vulnerabilities
- Command injection paths
- Hardcoded credentials
- Unsafe deserialization
- Cross-site scripting (XSS)
- Path traversal
- And more

This scanner catches these issues **before** they reach production.

## What It Detects

### Python Rules (10 rules)

| Rule | Category | Severity | What it finds |
|------|----------|----------|---------------|
| PY001 | SQL Injection | CRITICAL | String concatenation/f-strings in query execution |
| PY002 | Command Injection | CRITICAL | `os.system()`, `os.popen()`, `subprocess` with `shell=True` |
| PY003 | Secrets | HIGH | Hardcoded API keys, passwords, tokens, private keys (redacted in output) |
| PY004 | Deserialization | HIGH | `pickle.loads()`, `yaml.load()` without safe loader, `eval()` |
| PY005 | Cryptography | HIGH | MD5/SHA1 for password hashing, plaintext password comparison |
| PY006 | Path Traversal | HIGH | User input in `open()`, `os.path.join()`, `shutil` operations |
| PY007 | XSS | MEDIUM | `render_template_string()` with f-strings, `mark_safe()` with request data |
| PY008 | SSRF | HIGH | User-controlled URLs in `requests.get()`, `urllib` |
| PY009 | Cryptography | MEDIUM | `random` module for security-sensitive values |
| PY010 | Configuration | HIGH | `DEBUG = True` in production settings |

### JavaScript Rules (9 rules)

| Rule | Category | Severity | What it finds |
|------|----------|----------|---------------|
| JS001 | SQL Injection | CRITICAL | Template literals/concatenation in `db.query()` |
| JS002 | Command Injection | CRITICAL | `exec()`, `execSync()` with user input |
| JS003 | Secrets | HIGH | Hardcoded API keys, passwords, tokens (redacted in output) |
| JS004 | XSS | HIGH | `innerHTML`, `document.write()` with user input |
| JS005 | SSRF | HIGH | User URLs in `fetch()`, `axios` |
| JS006 | Path Traversal | HIGH | User input in `fs.readFile()`, `fs.writeFile()` |
| JS007 | Deserialization | HIGH | `eval()`, `new Function()` with user input |
| JS008 | Cryptography | MEDIUM | MD5/SHA1 via `crypto.createHash()` |
| JS009 | NoSQL Injection | HIGH | User input in MongoDB `findOne()`/`find()` |

## Installation

```bash
# Clone
git clone https://github.com/mhamidlad/ai-code-security-scanner.git
cd ai-code-security-scanner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install
pip install -e ".[dev]"
```

## Quick Start

```bash
# Scan a project
ai-scan scan ./my-project

# Scan with JSON output (for CI/CD)
ai-scan scan ./my-project --format json

# Generate SARIF for GitHub Code Scanning
ai-scan scan ./my-project --format sarif --output results.sarif

# Generate Markdown report
ai-scan scan ./my-project --format markdown --output report.md

# List all available rules
ai-scan rules

# Filter by language
ai-scan scan ./my-project --language python --language javascript

# Set minimum severity
ai-scan scan ./my-project --min-severity HIGH

# Exclude additional directories
ai-scan scan ./my-project --exclude tests --exclude docs
```

## Example Output

### Terminal

```
AI Code Security Scanner
v0.1.0

┌─────────────────────┐
│   Scan Summary       │
├─────────────────────┤
│ Project: ./examples   │
│ Files scanned: 2     │
│ Total findings: 15   │
│   Critical: 3        │
│   High: 7            │
│   Medium: 4          │
│   Low: 1             │
└─────────────────────┘
```

### JSON

```json
{
  "scanner": "ai-code-security-scanner",
  "version": "0.1.0",
  "summary": {
    "total_findings": 15,
    "critical": 3,
    "high": 7,
    "medium": 4,
    "low": 1
  },
  "findings": [...]
}
```

### SARIF

SARIF 2.1.0 output is compatible with GitHub Code Scanning. Upload it as a workflow artifact or use the `github/codeql-action/upload-sarif` action.

## Using with GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e .
      - run: ai-scan scan ./src --format sarif --output results.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Finding Suppression

Create a YAML config to suppress false positives:

```yaml
# suppressions.yaml
suppressions:
  PY003:
    - file: "config/settings.py"
      lines: [24, 25]
      reason: "Test credentials, not production secrets"

exclude_dirs:
  - "migrations"
  - "test_fixtures"
```

```bash
ai-scan scan ./my-project --config suppressions.yaml
```

## Try It on the Examples

The repository includes intentionally vulnerable and secure code:

```bash
# Scan vulnerable examples
ai-scan scan ./examples/vulnerable

# Scan secure examples (should produce minimal/no findings)
ai-scan scan ./examples/secure
```

## Important Limitations

1. **Pattern-based detection**: The scanner uses regex patterns, not full AST analysis. This means it can produce **false positives** and **false negatives**.
2. **No taint tracking**: The scanner does not trace data flow from source to sink.
3. **No semantic analysis**: Patterns match syntactic constructs, not semantic behavior.
4. **Manual verification required**: Every finding is marked `manual_verification_required: true`. Review each finding before acting on it.

> **A clean scan does NOT prove your code is secure.** It only means no known patterns were matched.

## Testing

```bash
# Run all tests
python -m pytest -v

# Run with coverage
python -m pytest -v --cov=ai_scanner --cov-report=term-missing
```

## Project Structure

```
ai-code-security-scanner/
├── src/ai_scanner/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── engine.py           # Scan orchestration
│   ├── models.py           # Data models (Finding, ScanResult, etc.)
│   ├── discovery.py        # File discovery and filtering
│   └── rules/
│       ├── python_rules.py     # 10 Python security rules
│       └── javascript_rules.py # 9 JavaScript security rules
│   └── reporters/
│       ├── terminal.py     # Rich terminal output
│       ├── json_report.py  # JSON for CI/CD
│       ├── sarif_report.py # SARIF 2.1.0
│       └── markdown_report.py # Markdown for PR comments
├── examples/
│   ├── vulnerable/         # Intentionally vulnerable code
│   │   ├── python/app.py
│   │   └── javascript/app.js
│   └── secure/             # Secure implementations for comparison
│       ├── python/app.py
│       └── javascript/app.js
├── tests/                  # pytest test suite
├── .github/workflows/      # CI: test + self-scan
├── pyproject.toml
└── README.md
```

## Design Decisions

1. **Identify risks, not authorship**: The scanner detects security patterns regardless of whether code was written by a human or AI. It does not claim to identify AI-generated code.

2. **Redact secrets in output**: Hardcoded secrets found during scanning are redacted in all report formats. The scanner never prints full credential values.

3. **Multi-format reporting**: Terminal for developers, JSON for CI/CD pipelines, SARIF for GitHub integration, Markdown for PR comments.

4. **Extensible rule system**: Rules follow a consistent dataclass pattern. Adding a new rule is straightforward — define the patterns, register the rule, add tests.

5. **Comment-aware**: Lines starting with `#` (Python) or `//` (JavaScript) are skipped to reduce false positives from commented-out code.

## Roadmap

- [ ] Version 2: TypeScript-specific rules
- [ ] Version 2: Full AST analysis (not just regex)
- [ ] Version 2: Taint tracking
- [ ] Version 2: HTML report format
- [ ] Version 2: Compare findings between commits
- [ ] Version 2: PR diff scanning
- [ ] Integration with Semgrep and Bandit

## Technologies

`Python` `Rich` `Typer` `Pydantic` `Pytest` `SARIF` `GitHub Actions`

## License

MIT — See [LICENSE](LICENSE).

## Need Help Securing Your Application?

This project demonstrates practical approaches to identifying and mitigating
application security risks.

I also work on security reviews and remediation for real-world applications,
including AI-generated code, APIs, dependency risks, and CI/CD pipelines.

If your team needs help with:

- Reviewing AI-generated code for security vulnerabilities
- Investigating and fixing security findings
- Improving automated security testing
- Hardening GitHub Actions and deployment pipelines
- Assessing the security of AI-powered applications

You can reach me at **WhatsApp: +92 316 7417135** or open an issue on this
repository.

For consulting inquiries, please include a short description of your
application, technology stack, and security objectives.

*Security testing is performed only on systems for which appropriate
authorization has been obtained.*

---

### Security First. Evidence Over Assumptions. Fixes Over Findings.

*This scanner identifies suspicious patterns. It does not prove code is secure.*
