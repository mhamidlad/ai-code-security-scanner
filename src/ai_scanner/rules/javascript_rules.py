"""JavaScript security rules — pattern-based detection for common vulnerabilities."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Confidence, Finding, Language, Severity
from ..discovery import FileDiscovery


@dataclass
class JSRule:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    description: str
    impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    patterns: list[tuple[re.Pattern, str]] = field(default_factory=list)
    raw_patterns: list[str] = field(default_factory=list)

    def compile_patterns(self):
        self.patterns = [(re.compile(p, re.MULTILINE), p) for p in self.raw_patterns]


RULES: list[JSRule] = []


def _register(rule: JSRule) -> JSRule:
    rule.compile_patterns()
    RULES.append(rule)
    return rule


# JS001: SQL Injection
_register(JSRule(
    rule_id="JS001",
    title="SQL Injection",
    severity=Severity.CRITICAL,
    confidence=Confidence.MEDIUM,
    category="SQL Injection",
    description=(
        "User-controlled input is concatenated into a SQL query string. An attacker "
        "could inject SQL to read, modify, or delete data."
    ),
    impact="Data breach, unauthorized data access, authentication bypass.",
    remediation=(
        "Use parameterized queries or prepared statements. In Node.js, use "
        "pg.query() with placeholders or an ORM query builder."
    ),
    references=[
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://node-postgres.com/features/queries#parameterized-query",
    ],
    raw_patterns=[
        r'query\s*\(\s*[`\'"].*?\$\{.*?\}.*?[`\'"]',
        r'query\s*\(\s*[`\'"].*?["\']\s*\+',
        r'query\s*\(\s*`.*\$\{.*\}.*`',
        r'execute\s*\(\s*[`\'"].*?\$\{.*?\}.*?[`\'"]',
        r'\.query\s*\(\s*[`\'"].*?\+\s*(req|params|body|query)',
    ],
))

# JS002: Command Injection
_register(JSRule(
    rule_id="JS002",
    title="Command Injection",
    severity=Severity.CRITICAL,
    confidence=Confidence.MEDIUM,
    category="Command Injection",
    description=(
        "User-controlled input is passed to child_process execution functions. "
        "An attacker could inject shell metacharacters to execute arbitrary commands."
    ),
    impact="Remote code execution, full system compromise.",
    remediation=(
        "Use execFile() or spawn() with an array of arguments (shell=False). "
        "Avoid exec() and never pass user input to shell execution."
    ),
    references=[
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://nodejs.org/api/child_process.html#child_process_asynchronous_process_creation",
    ],
    raw_patterns=[
        r'\bexec\s*\(\s*[^)]*(req\.|params|body|query|`)',
        r'\bexecSync\s*\(\s*[^)]*(req\.|params|body|query|`)',
        r'\bchild_process\.exec\s*\(\s*[^)]*(req\.|`)',
        r'\bexecSync\s*\(\s*`.*\$\{.*\}.*`',
        r'\bexec\s*\(\s*`.*\$\{.*\}.*`',
        r'\bspawn\s*\(\s*[^)]*(req\.|params|body|query)',
    ],
))

# JS003: Hardcoded Secrets
_register(JSRule(
    rule_id="JS003",
    title="Hardcoded Secret",
    severity=Severity.HIGH,
    confidence=Confidence.LOW,
    category="Secrets",
    description=(
        "A potential secret (API key, password, token) is hardcoded in source. "
        "If committed, it may be exposed to anyone with repository access."
    ),
    impact="Credential theft, unauthorized API access, infrastructure compromise.",
    remediation=(
        "Move secrets to environment variables (process.env) or a secret manager. "
        "Rotate exposed credentials. Add .env to .gitignore."
    ),
    references=[
        "https://owasp.org/www-community/controls/Use_of_hard-coded_password",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    ],
    raw_patterns=[
        r'api[_-]?key\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        r'api[_-]?secret\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        r'aws[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key)\s*[:=]\s*["\'][a-zA-Z0-9/+=]{16,}["\']',
        r'password\s*[:=]\s*["\'][^"\']{8,}["\']',
        r'passwd\s*[:=]\s*["\'][^"\']{8,}["\']',
        r'(secret[_-]?token|auth[_-]?token|access[_-]?token)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
        r'sk_(live|test)_[a-zA-Z0-9]{24,}',
        # Generic API key assignments (catches FAKE_LIVE_KEY_ and similar)
        r'(?i)api[_-]?key\s*[:=]\s*["\'][a-zA-Z0-9_]{20,}["\']',
        r'ghp_[a-zA-Z0-9]{36,}',
        r'github[_-]?token\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        r'process\.env\.\w+\s*\|\|\s*["\'][a-zA-Z0-9_\-]{20,}["\']',  # fallback secret
    ],
))

# JS004: XSS — innerHTML / document.write
_register(JSRule(
    rule_id="JS004",
    title="Cross-Site Scripting (XSS)",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category="XSS",
    description=(
        "User-controlled input is written to innerHTML or document.write without "
        "sanitization. An attacker could inject and execute JavaScript."
    ),
    impact="Session theft, credential theft, defacement, malware delivery.",
    remediation=(
        "Use textContent instead of innerHTML. If HTML is required, sanitize with "
        "DOMPurify. Use a framework with auto-escaping (React, Vue, Angular)."
    ),
    references=[
        "https://owasp.org/www-community/attacks/xss/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    raw_patterns=[
        r'\.innerHTML\s*=\s*[^;]*(req\.|params|body|query|location|innerHTML)',
        r'document\.write\s*\(\s*[^)]*(req\.|params|body|query|location)',
        r'\.innerHTML\s*=\s*`.*\$\{.*\}.*`',
        r'document\.write\s*\(\s*`.*\$\{.*\}.*`',
        r'\.outerHTML\s*=\s*[^;]*(req\.|location)',
        r'insertAdjacentHTML\s*\(\s*[^)]*(req\.|location|body)',
    ],
))

# JS005: SSRF
_register(JSRule(
    rule_id="JS005",
    title="Server-Side Request Forgery (SSRF)",
    severity=Severity.HIGH,
    confidence=Confidence.LOW,
    category="SSRF",
    description=(
        "User-controlled URLs are used in outbound HTTP requests. An attacker could "
        "make the server request internal services."
    ),
    impact="Access to internal services, cloud credential theft.",
    remediation=(
        "Validate and allowlist URLs. Block requests to private IP ranges and "
        "metadata endpoints."
    ),
    references=[
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
    raw_patterns=[
        r'\bfetch\s*\(\s*[^)]*(req\.|params|body|query)',
        r'\baxios\.(get|post|put|delete)\s*\(\s*[^)]*(req\.|params|body|query)',
        r'\bhttp\.(get|request)\s*\(\s*[^)]*(req\.|params|body|query)',
        r'\bhttps\.(get|request)\s*\(\s*[^)]*(req\.|params|body|query)',
    ],
))

# JS006: Path Traversal
_register(JSRule(
    rule_id="JS006",
    title="Path Traversal",
    severity=Severity.HIGH,
    confidence=Confidence.LOW,
    category="Path Traversal",
    description=(
        "User-controlled input is used in file path operations. An attacker could "
        "access files outside the intended scope."
    ),
    impact="Unauthorized file access, information disclosure.",
    remediation=(
        "Validate and sanitize paths. Use path.resolve() and verify the result "
        "stays within the allowed directory. Use allowlists."
    ),
    references=[
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Handling_Cheat_Sheet.html",
    ],
    raw_patterns=[
        r'\bfs\.readFile\s*\(\s*[^)]*(req\.|params|body|query)',
        r'\bfs\.readFileSync\s*\(\s*[^)]*(req\.|params|body|query)',
        r'\bfs\.writeFile\s*\(\s*[^)]*(req\.|params|body|query)',
        r'\bfs\.createReadStream\s*\(\s*[^)]*(req\.|params|body|query)',
        r'\bfs\.createWriteStream\s*\(\s*[^)]*(req\.|params|body|query)',
        r'\bpath\.join\s*\([^)]*(req\.|params|body|query)',
    ],
))

# JS007: Insecure Deserialization
_register(JSRule(
    rule_id="JS007",
    title="Unsafe Deserialization",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category="Deserialization",
    description=(
        "Untrusted data is passed to eval() or Function constructor. This can "
        "lead to arbitrary code execution."
    ),
    impact="Remote code execution.",
    remediation=(
        "Never use eval() or new Function() on untrusted input. Use JSON.parse() "
        "for data deserialization."
    ),
    references=[
        "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval",
    ],
    raw_patterns=[
        r'\beval\s*\(\s*(req\.|params|body|query|location)',
        r'\beval\s*\(\s*`.*\$\{.*\}.*`',
        r'new\s+Function\s*\(\s*(req\.|params|body|query)',
        r'\bvm\.runInNewContext\s*\(\s*(req\.|params|body|query)',
        r'\bvm\.runInThisContext\s*\(\s*(req\.|params|body|query)',
    ],
))

# JS008: Weak Crypto
_register(JSRule(
    rule_id="JS008",
    title="Weak Cryptographic Algorithm",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    category="Cryptography",
    description=(
        "MD5 or SHA1 is used for security-sensitive purposes. These algorithms "
        "are broken and should not be used for password hashing or integrity."
    ),
    impact="Hash collisions, credential recovery, data integrity failures.",
    remediation=(
        "Use bcrypt or scrypt for password hashing. Use SHA-256 or SHA-512 for "
        "integrity checks. Use Node.js crypto module with secure algorithms."
    ),
    references=[
        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
        "https://nodejs.org/api/crypto.html",
    ],
    raw_patterns=[
        r'\bcreateHash\s*\(\s*["\'](md5|sha1)["\']',
        r'\bmd5\s*\(',
        r'\bsha1\s*\(',
    ],
))

# JS009: NoSQL Injection
_register(JSRule(
    rule_id="JS009",
    title="NoSQL Injection",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category="SQL Injection",
    description=(
        "User-controlled input is used directly in MongoDB query objects. An attacker "
        "could use operators like $where or $ne to bypass authentication or extract data."
    ),
    impact="Authentication bypass, data exposure, data modification.",
    remediation=(
        "Sanitize all query inputs. Use mongo-sanitize or express-mongo-sanitize. "
        "Type-check values before passing to query operators."
    ),
    references=[
        "https://owasp.org/www-community/attacks/NoSQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
    ],
    raw_patterns=[
        r'\bfindOne\s*\(\s*\{[^}]*req\.',
        r'\bfind\s*\(\s*\{[^}]*req\.',
        r'\bfind\s*\(\s*req\.',
        r'\bfindOne\s*\(\s*req\.',
        r'\$where\s*:',
    ],
))


def scan_js_file(filepath: str, project_root: str = ".") -> list[Finding]:
    """Run all JavaScript rules against a single file."""
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
                    # Skip comments
                    stripped = line.lstrip()
                    if stripped.startswith("//") or stripped.startswith("/*"):
                        continue

                    rel_path = FileDiscovery.get_relative_path(filepath, project_root)

                    evidence = line.strip()
                    if rule.rule_id == "JS003":
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
                        language=Language.JAVASCRIPT,
                        detection_method="pattern",
                        manual_verification_required=True,
                    ))
                    break

    return findings


def _redact_evidence(evidence: str) -> str:
    """Redact potential secret values from evidence."""
    evidence = re.sub(
        r'([:=])\s*["\'][a-zA-Z0-9_\-/+=]{8,}["\']',
        r'\1 "[REDACTED]"',
        evidence,
    )
    return evidence


def get_js_rules() -> list[JSRule]:
    return RULES
