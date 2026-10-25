"""Python security rules — pattern-based detection for common vulnerabilities.

Each rule follows the same structure:
- rule_id: unique identifier (PY001, PY002, etc.)
- title: short human-readable name
- severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- confidence: HIGH / MEDIUM / LOW
- patterns: regex patterns that indicate the vulnerability
- description: what the rule detects
- impact: what could go wrong if exploited
- remediation: how to fix it
- references: authoritative documentation links
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from ..models import Confidence, Finding, Language, Severity
from ..discovery import FileDiscovery

# ──────────────────────────────────────────────────────────────────────────────
# Rule definitions
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PythonRule:
    """A Python security detection rule."""
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    description: str
    impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    patterns: list[tuple[str, str]] = field(default_factory=list)
    """List of (compiled_regex, pattern_description) tuples."""
    raw_patterns: list[str] = field(default_factory=list)

    def compile_patterns(self):
        self.patterns = [(re.compile(p, re.MULTILINE), p) for p in self.raw_patterns]


# ──────────────────────────────────────────────────────────────────────────────
# Rule definitions
# ──────────────────────────────────────────────────────────────────────────────

RULES: list[PythonRule] = []


def _register(rule: PythonRule) -> PythonRule:
    rule.compile_patterns()
    RULES.append(rule)
    return rule


# PY001: SQL Injection
_register(PythonRule(
    rule_id="PY001",
    title="SQL Injection",
    severity=Severity.CRITICAL,
    confidence=Confidence.MEDIUM,
    category="SQL Injection",
    description=(
        "User-controlled input appears to be concatenated or formatted directly "
        "into a SQL query string. An attacker could inject SQL to read, modify, "
        "or delete data."
    ),
    impact=(
        "Data breach, unauthorized data access, data modification or deletion, "
        "authentication bypass."
    ),
    remediation=(
        "Use parameterized queries with placeholders. Never concatenate user input "
        "into SQL strings. For ORMs, use their query builder API rather than raw "
        "string formatting."
    ),
    references=[
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://docs.python.org/3/library/sqlite3.html#sqlite3.Cursor.execute",
    ],
    raw_patterns=[
        # String concatenation with execute
        r'execute\s*\(\s*["\'].*?["\']\s*\+',
        r'execute\s*\(\s*f["\']',
        r'execute\s*\(\s*["\'].*\{.*\}.*["\'].*format',
        # f-string in execute
        r'\.execute\s*\(\s*f["\']',
        # .format() in execute
        r'\.execute\s*\(\s*["\'].*\{.*\}.*["\']\s*\.format',
        # cursor.execute with % formatting
        r'cursor\.execute\s*\(\s*["\'].*%s.*["\'].*%\s*\(',
        # String concatenation built for query
        r'query\s*=\s*["\'].*?["\']\s*\+',
        r'query\s*=\s*f["\']',
        r'query\s*=\s*["\'].*\{.*\}.*["\']\.format',
    ],
))

# PY002: Command Injection
_register(PythonRule(
    rule_id="PY002",
    title="Command Injection",
    severity=Severity.CRITICAL,
    confidence=Confidence.MEDIUM,
    category="Command Injection",
    description=(
        "User-controlled input is passed to shell execution functions. An attacker "
        "could inject shell metacharacters to execute arbitrary commands."
    ),
    impact="Remote code execution, full system compromise.",
    remediation=(
        "Use subprocess.run() with a list of arguments (shell=False) and validate "
        "input. Avoid os.system(), os.popen(), and shell=True with user input. "
        "Use shlex.quote() if shell interpretation is truly necessary."
    ),
    references=[
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://docs.python.org/3/library/subprocess.html#security-considerations",
        "https://docs.python.org/3/library/shlex.html#shlex.quote",
    ],
    raw_patterns=[
        r'\bos\.system\s*\(\s*[^)]*[%f\+]',
        r'\bos\.popen\s*\(\s*[^)]*[%f\+]',
        r'\bsubprocess\.(run|call|check_output|Popen)\s*\([^)]*shell\s*=\s*True',
        r'\bsubprocess\.(run|call|check_output|Popen)\s*\([^)]*\+',
        r'\bsubprocess\.(run|call|check_output|Popen)\s*\(\s*f["\']',
        r'\bos\.system\s*\(\s*f["\']',
        r'\bos\.system\s*\(\s*["\'].*["\']\s*\+',
    ],
))

# PY003: Hardcoded Secrets
_register(PythonRule(
    rule_id="PY003",
    title="Hardcoded Secret",
    severity=Severity.HIGH,
    confidence=Confidence.LOW,
    category="Secrets",
    description=(
        "A potential secret (API key, password, token) appears to be hardcoded "
        "in source. If committed, it may be exposed to anyone with repository access."
    ),
    impact=(
        "Credential theft, unauthorized API access, data breaches, infrastructure "
        "compromise."
    ),
    remediation=(
        "Move secrets to environment variables or a secret manager. Rotate any "
        "exposed credentials immediately. Add secret detection to CI/CD."
    ),
    references=[
        "https://owasp.org/www-community/controls/Use_of_hard-coded_password",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    ],
    raw_patterns=[
        # API keys
        r'api[_-]?key\s*=\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        r'api[_-]?secret\s*=\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        # AWS
        r'aws[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key)\s*=\s*["\'][a-zA-Z0-9/+=]{16,}["\']',
        # Generic password assignments
        r'password\s*=\s*["\'][^"\']{8,}["\']',
        r'passwd\s*=\s*["\'][^"\']{8,}["\']',
        r'pass\s*=\s*["\'][^"\']{8,}["\']',
        # Tokens
        r'(secret[_-]?token|auth[_-]?token|access[_-]?token)\s*=\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        # Private keys
        r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
        # Stripe
        r'sk_(live|test)_[a-zA-Z0-9]{24,}',
        # Generic API key assignments (catches FAKE_LIVE_KEY_ and similar)
        r'(?i)api[_-]?key\s*=\s*["\'][a-zA-Z0-9_]{20,}["\']',
        # GitHub tokens
        r'ghp_[a-zA-Z0-9]{36,}',
        r'github[_-]?token\s*=\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        # Database connection strings with credentials
        r'(postgres|mysql|mongodb)://[^:\s]+:[^@\s]+@',
    ],
))

# PY004: Unsafe Deserialization
_register(PythonRule(
    rule_id="PY004",
    title="Unsafe Deserialization",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category="Deserialization",
    description=(
        "Untrusted data is passed to pickle, yaml.load, or eval. Deserializing "
        "untrusted data can lead to arbitrary code execution."
    ),
    impact="Remote code execution, arbitrary code execution on the server.",
    remediation=(
        "Never deserialize untrusted data with pickle. Use json.loads() for "
        "untrusted input. For YAML, use yaml.safe_load() instead of yaml.load(). "
        "Never use eval() or exec() on untrusted input."
    ),
    references=[
        "https://docs.python.org/3/library/pickle.html#module-pickle",
        "https://owasp.org/www-community/controls/Deserialization",
        "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
    ],
    raw_patterns=[
        r'\bpickle\.loads?\s*\(',
        r'\byaml\.load\s*\(\s*[^)]*\)',
        r'\byaml\.load\s*\(\s*[^,)]+\)\s*$',  # yaml.load without Loader
        r'\beval\s*\(\s*(request\.|input\(|sys\.|os\.)',
        r'\bexec\s*\(\s*(request\.|input\(|sys\.|os\.)',
        r'\bmarshal\.loads?\s*\(',
        r'\bshelve\.open\s*\(',
    ],
))

# PY005: Weak Password Hashing
_register(PythonRule(
    rule_id="PY005",
    title="Weak Password Hashing",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    category="Cryptography",
    description=(
        "Passwords are hashed using MD5, SHA1, or stored in plaintext. These "
        "methods are unsuitable for password storage."
    ),
    impact=(
        "If the password database is leaked, weak hashes can be cracked rapidly, "
        "exposing user credentials."
    ),
    remediation=(
        "Use bcrypt, scrypt, or argon2 for password hashing. In Python, use "
        "the bcrypt or passlib library. Apply a salt and appropriate work factor."
    ),
    references=[
        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
        "https://docs.python.org/3/library/hashlib.html#hashlib.pbkdf2_hmac",
    ],
    raw_patterns=[
        r'\bhashlib\.md5\s*\(',
        r'\bhashlib\.sha1\s*\(',
        r'\bhashlib\.md5\s*\(\s*[^)]*\.encode',
        r'\bhashlib\.sha1\s*\(\s*[^)]*\.encode',
        r'password\s*==\s*["\']',
        r'password\s*==\s*(request|input|data)',
    ],
))

# PY006: Path Traversal
_register(PythonRule(
    rule_id="PY006",
    title="Path Traversal",
    severity=Severity.HIGH,
    confidence=Confidence.LOW,
    category="Path Traversal",
    description=(
        "User-controlled input is used in file path operations without sanitization. "
        "An attacker could traverse directories to access files outside the intended scope."
    ),
    impact="Unauthorized file access, information disclosure, potential code execution.",
    remediation=(
        "Validate and sanitize file paths. Use os.path.realpath() to resolve the "
        "final path, then verify it stays within the allowed directory. Use "
        "allowlists for filenames."
    ),
    references=[
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Handling_Cheat_Sheet.html",
    ],
    raw_patterns=[
        r'\bopen\s*\(\s*[^)]*(request\.|input\(|sys\.argv|os\.environ)',
        r'\bopen\s*\(\s*[^)]*\.\.',
        r'\bos\.path\.join\s*\([^)]*(request\.|input\(|sys\.argv)',
        r'\bshutil\.copy\s*\([^)]*(request\.|input\(|sys\.argv)',
        r'\bshutil\.copyfile\s*\([^)]*(request\.|input\(|sys\.argv)',
        r'\bos\.remove\s*\(\s*[^)]*(request\.|input\(|sys\.argv)',
        r'\bPath\s*\(\s*[^)]*(request\.|input\(|sys\.argv)',
    ],
))

# PY007: XSS (Cross-Site Scripting) — Flask/Django context
_register(PythonRule(
    rule_id="PY007",
    title="Cross-Site Scripting (XSS)",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    category="XSS",
    description=(
        "User-controlled input is rendered without escaping. An attacker could "
        "inject JavaScript executed in a victim's browser."
    ),
    impact="Session theft, credential theft, defacement, malware delivery.",
    remediation=(
        "Use framework auto-escaping (Jinja2 autoescape, Django escape). Never "
        "use |safe or mark_safe() on untrusted input. Set Content-Type properly "
        "and use Content-Security-Policy headers."
    ),
    references=[
        "https://owasp.org/www-community/attacks/xss/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    raw_patterns=[
        # Flask: render_template_string with f-string or concatenation
        r'render_template_string\s*\(\s*f["\']',
        r'render_template_string\s*\(\s*["\'].*\+',
        # Django: mark_safe with request data
        r'mark_safe\s*\(\s*[^)]*(request\.|GET|POST)',
        # Jinja2 |safe on request
        r'\|\s*safe.*request\.',
        # Response with unescaped input
        r'HttpResponse\s*\(\s*[^)]*(request\.|GET|POST)',
    ],
))

# PY008: SSRF (Server-Side Request Forgery)
_register(PythonRule(
    rule_id="PY008",
    title="Server-Side Request Forgery (SSRF)",
    severity=Severity.HIGH,
    confidence=Confidence.LOW,
    category="SSRF",
    description=(
        "User-controlled URLs are used in outbound HTTP requests. An attacker "
        "could make the server request internal services or cloud metadata endpoints."
    ),
    impact="Access to internal services, cloud credential theft, port scanning from inside.",
    remediation=(
        "Validate and allowlist URLs. Block requests to private IP ranges and "
        "cloud metadata endpoints (169.254.169.254). Use a proxy that enforces "
        "these restrictions."
    ),
    references=[
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
    raw_patterns=[
        r'\brequests\.get\s*\(\s*[^)]*(request\.|input\(|sys\.argv|url)',
        r'\brequests\.post\s*\(\s*[^)]*(request\.|input\(|sys\.argv|url)',
        r'\burllib\.request\.urlopen\s*\(\s*[^)]*(request\.|input\(|sys\.argv)',
        r'\bhttpx\.get\s*\(\s*[^)]*(request\.|input\(|sys\.argv|url)',
        r'\baiohttp.*\.get\s*\(\s*[^)]*(request\.|input\(|sys\.argv|url)',
    ],
))

# PY009: Insecure Randomness
_register(PythonRule(
    rule_id="PY009",
    title="Insecure Random Number Generator",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    category="Cryptography",
    description=(
        "The random module is used for security-sensitive values (tokens, passwords, "
        "session IDs). random is not cryptographically secure."
    ),
    impact="Predictable tokens, session fixation, credential recovery.",
    remediation=(
        "Use the secrets module for security-sensitive random values: "
        "secrets.token_hex(), secrets.token_urlsafe(), secrets.choice()."
    ),
    references=[
        "https://docs.python.org/3/library/secrets.html",
        "https://owasp.org/www-community/controls/Use_of_cryptographically_strong_random_values",
    ],
    raw_patterns=[
        r'\brandom\.choice\s*\(',
        r'\brandom\.randint\s*\(',
        r'\brandom\.random\s*\(',
        r'\brandom\.randrange\s*\(',
    ],
))

# PY010: Debug Mode Enabled
_register(PythonRule(
    rule_id="PY010",
    title="Debug Mode Enabled",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    category="Configuration",
    description=(
        "Debug mode is enabled. In production, this exposes internal error details, "
        "stack traces, and can execute arbitrary code."
    ),
    impact="Information disclosure, remote code execution (Django/Flask debug).",
    remediation="Set DEBUG=False in production. Use environment variables to control this.",
    references=[
        "https://docs.djangoproject.com/en/stable/ref/settings/#debug",
        "https://flask.palletsprojects.com/en/stable/debugging/",
    ],
    raw_patterns=[
        r'\bDEBUG\s*=\s*True',
        r'\bdebug\s*=\s*True',
        r'app\.run\s*\([^)]*debug\s*=\s*True',
    ],
))


def scan_python_file(filepath: str, project_root: str = ".") -> list[Finding]:
    """Run all Python rules against a single file."""
    findings: list[Finding] = []

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return findings

    for i, line in enumerate(lines, 1):
        for rule in RULES:
            for pattern, raw_pattern in rule.patterns:
                match = pattern.search(line)
                if match:
                    # Skip comments (basic heuristic)
                    stripped = line.lstrip()
                    if stripped.startswith("#"):
                        continue

                    rel_path = FileDiscovery.get_relative_path(filepath, project_root)

                    # Redact secrets in evidence
                    evidence = line.strip()
                    if rule.rule_id == "PY003":
                        evidence = _redact_evidence(evidence)

                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        category=rule.category,
                        file=rel_path,
                        line=i,
                        description=rule.description,
                        evidence=evidence,
                        impact=rule.impact,
                        remediation=rule.remediation,
                        references=rule.references,
                        language=Language.PYTHON,
                        detection_method="pattern",
                        manual_verification_required=True,
                    ))
                    break  # One finding per rule per line

    return findings


def _redact_evidence(evidence: str) -> str:
    """Redact potential secret values from evidence strings."""
    import re
    # Redact quoted strings that look like secrets
    evidence = re.sub(
        r'(=|:)\s*["\'][a-zA-Z0-9_\-/+=]{8,}["\']',
        r'\1 "[REDACTED]"',
        evidence,
    )
    # Redact connection string passwords
    evidence = re.sub(
        r'://[^:\s]+:[^@\s]+@',
        '://[REDACTED]:[REDACTED]@',
        evidence,
    )
    return evidence


def get_python_rules() -> list[PythonRule]:
    """Return all registered Python rules."""
    return RULES
