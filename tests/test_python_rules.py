"""Tests for Python security rules."""

import os
from pathlib import Path

from ai_scanner.rules import scan_python_file
from ai_scanner.models import Severity, Language

VULN_DIR = Path(__file__).parent / "fixtures" / "vulnerable"
SECURE_DIR = Path(__file__).parent / "fixtures" / "secure"

# Also check the examples directory
EXAMPLES_VULN = Path(__file__).parent.parent / "examples" / "vulnerable" / "python"
EXAMPLES_SECURE = Path(__file__).parent.parent / "examples" / "secure" / "python"


class TestPythonRules:
    """Test individual Python rule detection."""

    def test_sql_injection_string_concat(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text(
            'cursor.execute("SELECT * FROM users WHERE email = " + email)\n'
        )
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY001" in rule_ids

    def test_sql_injection_f_string(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n')
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY001" in rule_ids

    def test_command_injection_os_system(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('os.system("ping " + host)\n')
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY002" in rule_ids

    def test_command_injection_subprocess_shell(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('subprocess.run(f"echo {user_input}", shell=True)\n')
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY002" in rule_ids

    def test_hardcoded_api_key(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('API_KEY = "FAKE_LIVE_KEY_1234567890abcdefghijklmnopqrstuvwxyz"\n')
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY003" in rule_ids

    def test_hardcoded_password(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('password = "MySecretPassword123"\n')
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY003" in rule_ids

    def test_hardcoded_github_token(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('github_token = "FAKE_GITHUB_TOKEN_1234567890abcdefghijklmnopqrstuvwxyz1234567890"\n')
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY003" in rule_ids

    def test_secret_redaction_in_evidence(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('API_KEY = "FAKE_LIVE_KEY_1234567890abcdefghijklmnopqrstuvwxyz"\n')
        findings = scan_python_file(str(f), str(tmp_path))
        for finding in findings:
            if finding.rule_id == "PY003":
                assert "FAKE_LIVE_KEY_1234567890abcdefghij" not in finding.evidence
                assert "REDACTED" in finding.evidence

    def test_unsafe_deserialization_pickle(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("pickle.loads(data)\n")
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY004" in rule_ids

    def test_weak_password_hashing_md5(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("hashlib.md5(password.encode()).hexdigest()\n")
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY005" in rule_ids

    def test_path_traversal_open(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("open(request.args.get('file')).read()\n")
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY006" in rule_ids

    def test_xss_render_template_string(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('render_template_string(f"<h1>Hello {name}</h1>")\n')
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY007" in rule_ids

    def test_ssrf_requests_get(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("requests.get(request.args.get('url'))\n")
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY008" in rule_ids

    def test_insecure_random(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("token = random.choice('abcdefghijklmnopqrstuvwxyz')\n")
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY009" in rule_ids

    def test_debug_mode(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("DEBUG = True\n")
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY010" in rule_ids

    def test_comments_not_flagged(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('# os.system("ping " + host)  # this is a comment\n')
        findings = scan_python_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY002" not in rule_ids

    def test_secure_code_no_findings(self, tmp_path):
        """Ensure secure code doesn't trigger false positives."""
        secure = tmp_path / "secure.py"
        secure.write_text(
            'cursor.execute("SELECT * FROM users WHERE email = ?", (email,))\n'
        )
        findings = scan_python_file(str(secure), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "PY001" not in rule_ids

    def test_vulnerable_example_file(self):
        """Scan the example vulnerable file and verify findings."""
        if EXAMPLES_VULN.exists():
            findings = scan_python_file(str(EXAMPLES_VULN / "app.py"), str(EXAMPLES_VULN))
            rule_ids = {finding.rule_id for finding in findings}
            assert "PY001" in rule_ids  # SQL injection
            assert "PY002" in rule_ids  # Command injection
            assert "PY003" in rule_ids  # Hardcoded secrets
            assert "PY004" in rule_ids  # Unsafe deserialization
            assert "PY005" in rule_ids  # Weak password hashing

    def test_secure_example_file_minimal_findings(self):
        """Scan the example secure file and verify minimal/no findings."""
        if EXAMPLES_SECURE.exists():
            findings = scan_python_file(str(EXAMPLES_SECURE / "app.py"), str(EXAMPLES_SECURE))
            rule_ids = {finding.rule_id for finding in findings}
            # Secure code should not have SQL injection or command injection
            assert "PY001" not in rule_ids
            assert "PY002" not in rule_ids

    def test_findings_have_correct_language(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('password = "SuperSecret12345"\n')
        findings = scan_python_file(str(f), str(tmp_path))
        assert len(findings) > 0
        for finding in findings:
            assert finding.language == Language.PYTHON

    def test_findings_have_severity(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('cursor.execute("SELECT * FROM users WHERE email = " + email)\n')
        findings = scan_python_file(str(f), str(tmp_path))
        assert len(findings) > 0
        for finding in findings:
            assert isinstance(finding.severity, Severity)
            assert finding.severity.weight >= 0
