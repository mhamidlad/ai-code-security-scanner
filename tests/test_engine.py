"""Tests for the scan engine."""

import os

from ai_scanner.engine import ScanEngine
from ai_scanner.models import ScanConfig, Language, Severity


class TestScanEngine:

    def test_scan_single_python_file(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text('password = "SuperSecret12345"\n')

        config = ScanConfig(path=str(tmp_path))
        engine = ScanEngine(config)
        result = engine.scan(str(tmp_path))

        assert result.files_scanned >= 1
        assert len(result.active_findings) > 0
        assert any(f.rule_id == "PY003" for f in result.active_findings)

    def test_scan_single_javascript_file(self, tmp_path):
        f = tmp_path / "app.js"
        f.write_text('const apiKey = "FAKE_LIVE_KEY_1234567890abcdefghijklmnopqrstuv";\n')

        config = ScanConfig(path=str(tmp_path))
        engine = ScanEngine(config)
        result = engine.scan(str(tmp_path))

        assert result.files_scanned >= 1
        assert len(result.active_findings) > 0
        assert any(f.rule_id == "JS003" for f in result.active_findings)

    def test_scan_mixed_project(self, tmp_path):
        # Python file
        (tmp_path / "app.py").write_text(
            'cursor.execute("SELECT * FROM users WHERE email = " + email)\n'
        )
        # JavaScript file
        (tmp_path / "app.js").write_text(
            'db.query(`SELECT * FROM users WHERE id = ${id}`);\n'
        )

        config = ScanConfig(path=str(tmp_path))
        engine = ScanEngine(config)
        result = engine.scan(str(tmp_path))

        assert result.files_scanned >= 2
        rule_ids = {f.rule_id for f in result.active_findings}
        assert "PY001" in rule_ids
        assert "JS001" in rule_ids

    def test_scan_excludes_node_modules(self, tmp_path):
        (tmp_path / "app.py").write_text('password = "SuperSecret12345"\n')
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "lib.js").write_text(
            'const apiKey = "FAKE_LIVE_KEY_1234567890abcdefghijklmnopqrstuv";\n'
        )

        config = ScanConfig(path=str(tmp_path))
        engine = ScanEngine(config)
        result = engine.scan(str(tmp_path))

        # Should only scan the Python file
        assert result.files_scanned == 1
        rule_ids = {f.rule_id for f in result.active_findings}
        assert "JS003" not in rule_ids

    def test_scan_excludes_venv(self, tmp_path):
        (tmp_path / "app.py").write_text('password = "SuperSecret12345"\n')
        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "lib.py").write_text(
            'password = "AnotherSecret123"\n'
        )

        config = ScanConfig(path=str(tmp_path))
        engine = ScanEngine(config)
        result = engine.scan(str(tmp_path))

        # Only the top-level file should be scanned
        assert result.files_scanned == 1

    def test_min_severity_filter(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(
            'password = "SuperSecret12345"\n'  # HIGH
            'token = random.choice("abcdef")\n'  # MEDIUM
        )

        # Only show CRITICAL
        config = ScanConfig(path=str(tmp_path), min_severity=Severity.CRITICAL)
        engine = ScanEngine(config)
        result = engine.scan(str(tmp_path))

        for finding in result.active_findings:
            assert finding.severity == Severity.CRITICAL

    def test_language_filter(self, tmp_path):
        (tmp_path / "app.py").write_text('password = "SuperSecret12345"\n')
        (tmp_path / "app.js").write_text(
            'const apiKey = "FAKE_LIVE_KEY_1234567890abcdefghijklmnopqrstuv";\n'
        )

        # Only Python
        config = ScanConfig(path=str(tmp_path), languages=[Language.PYTHON])
        engine = ScanEngine(config)
        result = engine.scan(str(tmp_path))

        rule_ids = {f.rule_id for f in result.active_findings}
        assert "PY003" in rule_ids
        assert "JS003" not in rule_ids

    def test_scan_result_counts(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(
            'password = "SuperSecret12345"\n'
            'cursor.execute("SELECT * FROM users WHERE email = " + email)\n'
        )

        config = ScanConfig(path=str(tmp_path))
        engine = ScanEngine(config)
        result = engine.scan(str(tmp_path))

        assert result.files_scanned == 1
        assert len(result.active_findings) >= 2
        assert result.high_count + result.critical_count + result.medium_count + result.low_count == len(result.active_findings)

    def test_scan_result_to_dict(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text('password = "SuperSecret12345"\n')

        config = ScanConfig(path=str(tmp_path))
        engine = ScanEngine(config)
        result = engine.scan(str(tmp_path))

        d = result.to_dict()
        assert d["scanner"] == "ai-code-security-scanner"
        assert d["version"] == "0.1.0"
        assert d["files_scanned"] == 1
        assert d["summary"]["total_findings"] >= 1

    def test_scan_empty_directory(self, tmp_path):
        config = ScanConfig(path=str(tmp_path))
        engine = ScanEngine(config)
        result = engine.scan(str(tmp_path))

        assert result.files_scanned == 0
        assert len(result.active_findings) == 0

    def test_scan_nonexistent_path(self, tmp_path):
        nonexistent = str(tmp_path / "does_not_exist")
        config = ScanConfig(path=nonexistent)
        engine = ScanEngine(config)
        result = engine.scan(nonexistent)

        assert result.files_scanned == 0
        assert len(result.active_findings) == 0
