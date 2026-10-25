"""Core data models for findings, severity, confidence, and scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity levels, ordered by impact."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]


class Confidence(str, Enum):
    """How certain we are that this is a real issue."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Language(str, Enum):
    """Supported source languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    """A single security finding from a scan."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    file: str
    line: int
    description: str
    evidence: str
    impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    language: Language = Language.UNKNOWN
    detection_method: str = "pattern"
    manual_verification_required: bool = False
    suppressed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON/reporting."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "language": self.language.value,
            "detection_method": self.detection_method,
            "manual_verification_required": self.manual_verification_required,
            "suppressed": self.suppressed,
        }

    @property
    def display_severity(self) -> str:
        return self.severity.value


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    path: str = "."
    languages: list[Language] = field(
        default_factory=lambda: [Language.PYTHON, Language.JAVASCRIPT]
    )
    min_severity: Severity = Severity.LOW
    exclude_dirs: list[str] = field(
        default_factory=lambda: [
            "node_modules",
            ".git",
            "venv",
            ".venv",
            "env",
            "__pycache__",
            "dist",
            "build",
            ".tox",
            ".eggs",
            "vendor",
        ]
    )
    exclude_patterns: list[str] = field(default_factory=list)
    max_file_size_mb: float = 10.0
    follow_symlinks: bool = False
    suppressions: dict[str, list[dict]] = field(default_factory=dict)

    def is_excluded(self, path: str) -> bool:
        """Check whether a path matches any exclusion."""
        import fnmatch
        import os

        parts = path.replace("\\", "/").split("/")
        for part in parts:
            if part in self.exclude_dirs:
                return True
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False


@dataclass
class ScanResult:
    """Complete result of a scan."""

    project_path: str
    scan_time: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    scanner_version: str = "0.1.0"
    suppressed_count: int = 0

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.active_findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.active_findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.active_findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.active_findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.active_findings if f.severity == Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        return {
            "scanner": "ai-code-security-scanner",
            "version": self.scanner_version,
            "project_path": self.project_path,
            "scan_time": self.scan_time,
            "duration_seconds": round(self.duration_seconds, 3),
            "files_scanned": self.files_scanned,
            "summary": {
                "total_findings": len(self.active_findings),
                "suppressed": self.suppressed_count,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "findings": [f.to_dict() for f in self.active_findings],
        }
