# Changelog

## [Unreleased]

## [0.1.0] - 2026-10-25

### Added
- Python security rules (10 rules):
  - PY001: SQL Injection
  - PY002: Command Injection
  - PY003: Hardcoded Secrets (with redaction)
  - PY004: Unsafe Deserialization
  - PY005: Weak Password Hashing
  - PY006: Path Traversal
  - PY007: Cross-Site Scripting (XSS)
  - PY008: Server-Side Request Forgery (SSRF)
  - PY009: Insecure Randomness
  - PY010: Debug Mode Enabled
- JavaScript security rules (9 rules):
  - JS001: SQL Injection
  - JS002: Command Injection
  - JS003: Hardcoded Secrets (with redaction)
  - JS004: Cross-Site Scripting (XSS)
  - JS005: Server-Side Request Forgery (SSRF)
  - JS006: Path Traversal
  - JS007: Unsafe Deserialization
  - JS008: Weak Cryptographic Algorithm
  - JS009: NoSQL Injection
- Report formats: Terminal (Rich), JSON, Markdown, SARIF 2.1.0
- File discovery with exclusion of node_modules, venv, .git, etc.
- CLI with `scan`, `rules`, and `version` commands
- Finding suppression via YAML config
- Vulnerable and secure example code (Python + JavaScript)
- GitHub Actions CI workflow (multi-Python-version testing)
- Self-scan security workflow (Bandit + scanner scanning its own source)
- Comprehensive test suite
- Dependabot configuration
