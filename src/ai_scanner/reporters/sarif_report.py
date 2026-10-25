"""SARIF 2.1.0 reporter — for GitHub Code Scanning integration."""

from __future__ import annotations

import json

from ..models import ScanResult, Severity, Finding
from ..rules import PY_RULES, JS_RULES


def _severity_to_sarif(severity: Severity) -> str:
    """Map our severity to SARIF level."""
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }
    return mapping.get(severity, "warning")


def _rule_to_sarif(rule) -> dict:
    """Convert a rule definition to SARIF reporting descriptor."""
    return {
        "id": rule.rule_id,
        "name": rule.title,
        "shortDescription": {"text": rule.description[:200]},
        "fullDescription": {"text": rule.description},
        "helpUri": rule.references[0] if rule.references else None,
        "defaultConfiguration": {
            "level": _severity_to_sarif(rule.severity),
        },
        "properties": {
            "category": rule.category,
            "severity": rule.severity.value,
            "confidence": rule.confidence.value,
            "impact": rule.impact,
            "remediation": rule.remediation,
        },
    }


def _finding_to_result(finding: Finding, run_index: int) -> dict:
    """Convert a finding to a SARIF result object."""
    return {
        "ruleId": finding.rule_id,
        "level": _severity_to_sarif(finding.severity),
        "message": {
            "text": f"{finding.title}: {finding.description}",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": finding.line,
                    },
                },
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": f"{finding.rule_id}:{finding.file}:{finding.line}",
        },
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "category": finding.category,
            "impact": finding.impact,
            "remediation": finding.remediation,
            "evidence": finding.evidence,
            "manual_verification_required": finding.manual_verification_required,
        },
    }


def render_sarif(result: ScanResult) -> str:
    """Render scan results as SARIF 2.1.0 JSON."""
    all_rules = []
    for rule in PY_RULES + JS_RULES:
        sarif_rule = _rule_to_sarif(rule)
        all_rules.append(sarif_rule)

    results = [
        _finding_to_result(f, i) for i, f in enumerate(result.active_findings)
    ]

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI Code Security Scanner",
                        "version": result.scanner_version,
                        "informationUri": "https://github.com/mhamidlad/ai-code-security-scanner",
                        "rules": all_rules,
                    },
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": result.scan_time,
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)
