"""Tests for JavaScript security rules."""

from pathlib import Path

from ai_scanner.rules import scan_js_file
from ai_scanner.models import Severity, Language

EXAMPLES_VULN = Path(__file__).parent.parent / "examples" / "vulnerable" / "javascript"
EXAMPLES_SECURE = Path(__file__).parent.parent / "examples" / "secure" / "javascript"


class TestJavaScriptRules:

    def test_sql_injection_template_literal(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text('db.query(`SELECT * FROM users WHERE email = \'${email}\'`);\n')
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS001" in rule_ids

    def test_sql_injection_concatenation(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text('db.query("SELECT * FROM users WHERE id = " + req.params.id);\n')
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS001" in rule_ids

    def test_command_injection_exec(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text('exec(`ping ${host}`);\n')
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS002" in rule_ids

    def test_command_injection_execSync(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text('execSync(`echo ${userInput}`);\n')
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS002" in rule_ids

    def test_hardcoded_api_key(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text('const apiKey = "FAKE_LIVE_KEY_1234567890abcdefghijklmnopqrstuv";\n')
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS003" in rule_ids

    def test_hardcoded_password(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text('const password = "MySecretPassword123";\n')
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS003" in rule_ids

    def test_xss_innerhtml(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text("element.innerHTML = req.body.content;\n")
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS004" in rule_ids

    def test_xss_document_write(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text("document.write(req.query.html);\n")
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS004" in rule_ids

    def test_ssrf_fetch(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text("fetch(req.query.url);\n")
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS005" in rule_ids

    def test_path_traversal_readfile(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text("fs.readFileSync(req.params.file);\n")
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS006" in rule_ids

    def test_unsafe_eval(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text("eval(req.body.expression);\n")
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS007" in rule_ids

    def test_weak_crypto_md5(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text("crypto.createHash('md5').update(password).digest('hex');\n")
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS008" in rule_ids

    def test_nosql_injection(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text("db.users.findOne({ email: req.body.email });\n")
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS009" in rule_ids

    def test_comments_not_flagged(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text("// db.query(`SELECT * FROM users WHERE email = \'${email}\'`);\n")
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS001" not in rule_ids

    def test_secure_code_no_sql_injection(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text("db.query('SELECT * FROM users WHERE email = ?', [email]);\n")
        findings = scan_js_file(str(f), str(tmp_path))
        rule_ids = {finding.rule_id for finding in findings}
        assert "JS001" not in rule_ids

    def test_secret_redaction(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text('const apiKey = "FAKE_LIVE_KEY_1234567890abcdefghijklmnopqrstuv";\n')
        findings = scan_js_file(str(f), str(tmp_path))
        for finding in findings:
            if finding.rule_id == "JS003":
                assert "FAKE_LIVE_KEY_1234567890abcdefghijklmnop" not in finding.evidence
                assert "REDACTED" in finding.evidence

    def test_vulnerable_example_file(self):
        if EXAMPLES_VULN.exists():
            findings = scan_js_file(str(EXAMPLES_VULN / "app.js"), str(EXAMPLES_VULN))
            rule_ids = {finding.rule_id for finding in findings}
            assert "JS001" in rule_ids  # SQL injection
            assert "JS002" in rule_ids  # Command injection
            assert "JS003" in rule_ids  # Hardcoded secrets
            assert "JS004" in rule_ids  # XSS
            assert "JS006" in rule_ids  # Path traversal

    def test_findings_have_javascript_language(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text('const apiKey = "FAKE_LIVE_KEY_1234567890abcdefghijklmnopqrstuv";\n')
        findings = scan_js_file(str(f), str(tmp_path))
        assert len(findings) > 0
        for finding in findings:
            assert finding.language == Language.JAVASCRIPT
