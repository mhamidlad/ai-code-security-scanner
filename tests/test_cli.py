"""Tests for the CLI."""

from pathlib import Path
from typer.testing import CliRunner

from ai_scanner.cli import app

runner = CliRunner()


class TestCLI:

    def test_version(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.stdout

    def test_scan_vulnerable_python(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text('password = "SuperSecret12345"\n')

        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
        assert result.exit_code in (0, 1, 2, 3)  # exit code depends on severity
        # Should have findings in output
        import json
        # The JSON output goes to stdout
        assert "findings" in result.stdout or "findings" in result.output

    def test_scan_empty_dir(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0

    def test_scan_json_format(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text('password = "SuperSecret12345"\n')

        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
        import json
        # Find JSON in output
        json_start = result.stdout.find("{")
        if json_start >= 0:
            data = json.loads(result.stdout[json_start:])
            assert "scanner" in data

    def test_scan_markdown_format(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text('password = "SuperSecret12345"\n')

        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "markdown"])
        assert "AI Code Security Scanner" in result.stdout

    def test_scan_output_to_file(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text('password = "SuperSecret12345"\n')
        output_file = tmp_path / "report.json"

        result = runner.invoke(app, [
            "scan", str(tmp_path),
            "--format", "json",
            "--output", str(output_file),
        ])
        assert output_file.exists()
        import json
        data = json.loads(output_file.read_text())
        assert "findings" in data

    def test_rules_command(self):
        result = runner.invoke(app, ["rules", "--detail"])
        assert result.exit_code == 0
        assert "SQL Injection" in result.stdout
        assert "Python" in result.stdout
        assert "JavaScript" in result.stdout

    def test_rules_python_only(self):
        result = runner.invoke(app, ["rules", "--language", "python", "--detail"])
        assert result.exit_code == 0
        assert "SQL Injection" in result.stdout
        assert "Language: Python" in result.stdout
        assert "Language: JavaScript" not in result.stdout

    def test_rules_javascript_only(self):
        result = runner.invoke(app, ["rules", "--language", "javascript", "--detail"])
        assert result.exit_code == 0
        assert "SQL Injection" in result.stdout
        assert "Language: JavaScript" in result.stdout
        assert "Language: Python" not in result.stdout

    def test_rules_detail(self):
        result = runner.invoke(app, ["rules", "--detail"])
        assert result.exit_code == 0
        assert "Remediation" in result.stdout or "remediation" in result.stdout.lower()

    def test_scan_min_severity(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(
            'password = "SuperSecret12345"\n'  # HIGH
            'token = random.choice("abcdef")\n'  # MEDIUM
        )

        result = runner.invoke(app, [
            "scan", str(tmp_path),
            "--format", "json",
            "--min-severity", "CRITICAL",
        ])
        import json
        json_start = result.stdout.find("{")
        if json_start >= 0:
            data = json.loads(result.stdout[json_start:])
            for finding in data.get("findings", []):
                assert finding["severity"] == "CRITICAL"

    def test_scan_language_filter(self, tmp_path):
        (tmp_path / "app.py").write_text('password = "SuperSecret12345"\n')
        (tmp_path / "app.js").write_text('const apiKey = "FAKE_LIVE_KEY_1234567890abcdefghijklmnopqrstuv";\n')

        result = runner.invoke(app, [
            "scan", str(tmp_path),
            "--format", "json",
            "--language", "python",
        ])
        import json
        json_start = result.stdout.find("{")
        if json_start >= 0:
            data = json.loads(result.stdout[json_start:])
            rule_ids = {f["rule_id"] for f in data.get("findings", [])}
            assert "PY003" in rule_ids
            assert "JS003" not in rule_ids
