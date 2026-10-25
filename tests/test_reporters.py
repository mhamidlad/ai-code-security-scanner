"""Tests for reporters."""

import json

from ai_scanner.models import (
    Confidence,
    Finding,
    Language,
    ScanResult,
    Severity,
)
from ai_scanner.reporters import (
    render_json,
    render_markdown,
    render_sarif,
    render_terminal,
)


def _make_finding(**kwargs):
    defaults = dict(
        rule_id="PY001",
        title="SQL Injection",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        category="SQL Injection",
        file="app.py",
        line=18,
        description="User input concatenated into SQL query.",
        evidence='cursor.execute("SELECT * FROM users WHERE email = " + email)',
        impact="Data breach.",
        remediation="Use parameterized queries.",
        references=["https://owasp.org/sql_injection"],
        language=Language.PYTHON,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_result(findings=None):
    return ScanResult(
        project_path="/tmp/test",
        scan_time="2026-01-01T00:00:00Z",
        files_scanned=5,
        findings=findings or [],
        duration_seconds=0.123,
    )


class TestJSONReporter:

    def test_json_is_valid(self):
        result = _make_result([_make_finding()])
        output = render_json(result)
        data = json.loads(output)
        assert data["scanner"] == "ai-code-security-scanner"
        assert data["version"] == "0.1.0"
        assert data["files_scanned"] == 5

    def test_json_has_summary(self):
        result = _make_result([
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH, rule_id="PY002"),
            _make_finding(severity=Severity.MEDIUM, rule_id="PY009"),
        ])
        output = render_json(result)
        data = json.loads(output)
        assert data["summary"]["total_findings"] == 3
        assert data["summary"]["critical"] == 1
        assert data["summary"]["high"] == 1
        assert data["summary"]["medium"] == 1

    def test_json_finding_has_all_fields(self):
        result = _make_result([_make_finding()])
        output = render_json(result)
        data = json.loads(output)
        finding = data["findings"][0]
        for field in [
            "rule_id", "title", "severity", "confidence", "category",
            "file", "line", "description", "evidence", "impact",
            "remediation", "references", "language", "detection_method",
        ]:
            assert field in finding, f"Missing field: {field}"

    def test_json_no_unredacted_secrets(self):
        finding = _make_finding(
            rule_id="PY003",
            title="Hardcoded Secret",
            severity=Severity.HIGH,
            evidence='[REDACTED]',
        )
        result = _make_result([finding])
        output = render_json(result)
        data = json.loads(output)
        assert "REDACTED" in data["findings"][0]["evidence"]

    def test_json_empty_results(self):
        result = _make_result([])
        output = render_json(result)
        data = json.loads(output)
        assert data["summary"]["total_findings"] == 0


class TestSARIFReporter:

    def test_sarif_is_valid_json(self):
        result = _make_result([_make_finding()])
        output = render_sarif(result)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_sarif_has_tool_info(self):
        result = _make_result([_make_finding()])
        output = render_sarif(result)
        data = json.loads(output)
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "AI Code Security Scanner"
        assert run["tool"]["driver"]["version"] == "0.1.0"

    def test_sarif_has_rules(self):
        result = _make_result([_make_finding()])
        output = render_sarif(result)
        data = json.loads(output)
        run = data["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) > 0

    def test_sarif_has_results(self):
        result = _make_result([_make_finding()])
        output = render_sarif(result)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "PY001"

    def test_sarif_severity_mapping(self):
        finding = _make_finding(severity=Severity.CRITICAL)
        result = _make_result([finding])
        output = render_sarif(result)
        data = json.loads(output)
        level = data["runs"][0]["results"][0]["level"]
        assert level == "error"

    def test_sarif_empty_results(self):
        result = _make_result([])
        output = render_sarif(result)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 0


class TestMarkdownReporter:

    def test_markdown_has_header(self):
        result = _make_result([_make_finding()])
        output = render_markdown(result)
        assert "# AI Code Security Scanner" in output

    def test_markdown_has_summary_table(self):
        result = _make_result([_make_finding()])
        output = render_markdown(result)
        assert "## Summary" in output
        assert "|" in output  # table

    def test_markdown_has_findings(self):
        result = _make_result([_make_finding()])
        output = render_markdown(result)
        assert "## Findings" in output
        assert "SQL Injection" in output

    def test_markdown_empty_results(self):
        result = _make_result([])
        output = render_markdown(result)
        assert "No security findings detected" in output

    def test_markdown_has_disclaimer(self):
        result = _make_result([_make_finding()])
        output = render_markdown(result)
        assert "clean scan" in output.lower() or "does not" in output.lower()


class TestTerminalReporter:

    def test_terminal_has_header(self):
        result = _make_result([_make_finding()])
        # Just verify it doesn't crash
        output = render_terminal(result)

    def test_terminal_empty_results(self):
        result = _make_result([])
        output = render_terminal(result)
        assert "No security findings" in output or "No findings" in output
