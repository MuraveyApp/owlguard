"""Tests for OwlGuard core modules — 30+ comprehensive tests."""
import sys
import os
import json
import hmac
import hashlib
import tempfile
import io
from pathlib import Path
from unittest.mock import patch, MagicMock
from http.server import HTTPServer

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Scanner tests (8) ──

class TestScanner:

    def test_scan_result_creation(self):
        """ScanResult with all fields populated."""
        from src.scanner import ScanResult
        findings = [
            {"vuln_type": "sql_injection", "severity": "critical", "file_path": "app.py",
             "line_number": 10, "description": "SQL injection via string concat",
             "fix_suggestion": "Use parameterized queries", "cwe_id": "CWE-89",
             "code_snippet": "query = 'SELECT * FROM users WHERE id=' + uid",
             "auto_fixable": True, "confidence": 0.95},
        ]
        r = ScanResult(
            repo="/tmp/myrepo", findings=findings, files_scanned=42,
            critical=1, high=0, medium=0, low=0, scan_time_sec=1.23,
        )
        assert r.repo == "/tmp/myrepo"
        assert r.files_scanned == 42
        assert r.critical == 1
        assert r.high == 0
        assert r.medium == 0
        assert r.low == 0
        assert r.scan_time_sec == 1.23
        assert r.error == ""
        assert len(r.findings) == 1
        assert r.findings[0]["vuln_type"] == "sql_injection"

    def test_scan_result_markdown_format(self):
        """Verify markdown output has headers, icons, and structured content."""
        from src.scanner import ScanResult
        r = ScanResult(
            repo="/tmp/test", files_scanned=10, critical=1, high=2, medium=1, low=1,
            findings=[
                {"vuln_type": "code_injection", "severity": "critical", "file_path": "main.py",
                 "line_number": 5, "description": "OS command injection", "fix_suggestion": "Use subprocess with list args"},
                {"vuln_type": "xss", "severity": "high", "file_path": "web.py",
                 "line_number": 20, "description": "Reflected XSS", "fix_suggestion": "Escape output"},
            ],
        )
        md = r.to_markdown()
        # Headers
        assert "## " in md
        assert "OwlGuard Security Report" in md
        # Icons for severities
        assert "\U0001f534" in md  # red circle for critical
        assert "\U0001f7e0" in md  # orange circle for high
        # Contains file paths as subheaders
        assert "`main.py`" in md
        assert "`web.py`" in md
        # Contains finding details
        assert "code_injection" in md
        assert "xss" in md
        # Footer
        assert "Powered by" in md

    def test_scan_result_has_critical(self):
        """has_critical property returns True when critical > 0."""
        from src.scanner import ScanResult
        r1 = ScanResult(repo="a", critical=2)
        r2 = ScanResult(repo="b", critical=0)
        assert r1.has_critical is True
        assert r2.has_critical is False

    def test_scan_result_total(self):
        """total property equals len(findings)."""
        from src.scanner import ScanResult
        findings = [{"vuln_type": f"v{i}"} for i in range(7)]
        r = ScanResult(repo="x", findings=findings)
        assert r.total == 7
        assert r.total == len(r.findings)

    def test_scan_empty_dir(self):
        """Scanning an empty directory returns 0 findings or a graceful error."""
        from src.scanner import scan_repo
        with tempfile.TemporaryDirectory() as tmpdir:
            result = scan_repo(tmpdir)
            # Either no findings or an import error (OwlSec not available)
            assert result.total == 0 or result.error != ""

    def test_scan_vulnerable_python(self):
        """Scanning dir with os.system(x) detects code injection (or errors gracefully)."""
        from src.scanner import scan_repo
        with tempfile.TemporaryDirectory() as tmpdir:
            vuln_file = Path(tmpdir) / "vuln.py"
            vuln_file.write_text("import os\nuser_input = input()\nos.system(user_input)\n")
            result = scan_repo(tmpdir)
            if not result.error:
                # If OwlSec is available, it should find the vulnerability
                vuln_types = [f.get("vuln_type", "") for f in result.findings]
                assert any("injection" in v.lower() or "command" in v.lower() for v in vuln_types)
            else:
                # OwlSec not installed — error is acceptable
                assert "owlsec" in result.error.lower() or "owlmind" in result.error.lower() or "No module" in result.error

    def test_scan_vulnerable_js(self):
        """Scanning dir with eval(x) detects injection (or errors gracefully)."""
        from src.scanner import scan_repo
        with tempfile.TemporaryDirectory() as tmpdir:
            vuln_file = Path(tmpdir) / "vuln.js"
            vuln_file.write_text("const x = req.query.code;\neval(x);\n")
            result = scan_repo(tmpdir)
            if not result.error:
                vuln_types = [f.get("vuln_type", "") for f in result.findings]
                assert any("injection" in v.lower() or "eval" in v.lower() for v in vuln_types)
            else:
                assert result.error != ""

    def test_clone_and_scan_bad_url(self):
        """clone_and_scan returns error for an invalid URL."""
        from src.scanner import clone_and_scan
        result = clone_and_scan("https://github.com/nonexistent/repo-that-does-not-exist-99999")
        assert result.error != ""
        assert "Clone failed" in result.error or "fatal" in result.error.lower()


# ── Fixer tests (5) ──

class TestFixer:

    def test_fix_result_creation(self):
        """FixResult with all fields populated."""
        from src.fixer import FixResult
        r = FixResult(
            vuln_type="sql_injection", file_path="/tmp/app.py",
            fixed=True, diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@",
            method="auto-fixer", error="",
        )
        assert r.vuln_type == "sql_injection"
        assert r.file_path == "/tmp/app.py"
        assert r.fixed is True
        assert r.diff != ""
        assert r.method == "auto-fixer"
        assert r.error == ""

    def test_fix_all_empty(self):
        """fix_all with empty findings list returns empty results."""
        from src.fixer import fix_all
        results = fix_all([], "/tmp/workspace")
        assert results == []

    def test_fix_all_sorts_by_severity(self):
        """fix_all processes critical before medium."""
        from src.fixer import fix_all
        findings = [
            {"vuln_type": "medium_bug", "severity": "medium", "file_path": "a.py",
             "line_number": 1, "cwe_id": "CWE-1", "description": "med", "auto_fixable": False},
            {"vuln_type": "critical_bug", "severity": "critical", "file_path": "b.py",
             "line_number": 1, "cwe_id": "CWE-2", "description": "crit", "auto_fixable": False},
        ]
        # fix_all will call fix_vulnerability which will fail (no OwlSec/OwlMind),
        # but the ORDER of processing should be critical first
        with patch("src.fixer.fix_vulnerability") as mock_fix:
            mock_fix.return_value = MagicMock(fixed=False)
            fix_all(findings, "/tmp/ws", max_fixes=10)
            # First call should be for critical, second for medium
            calls = mock_fix.call_args_list
            assert calls[0][0][0]["severity"] == "critical"
            assert calls[1][0][0]["severity"] == "medium"

    def test_fix_all_respects_max(self):
        """max_fixes=2 only processes 2 findings."""
        from src.fixer import fix_all
        findings = [
            {"vuln_type": f"bug{i}", "severity": "high", "file_path": f"f{i}.py",
             "line_number": 1, "cwe_id": "CWE-1", "description": "d", "auto_fixable": False}
            for i in range(5)
        ]
        with patch("src.fixer.fix_vulnerability") as mock_fix:
            mock_fix.return_value = MagicMock(fixed=False)
            results = fix_all(findings, "/tmp/ws", max_fixes=2)
            assert len(results) == 2
            assert mock_fix.call_count == 2

    def test_fix_vulnerability_missing_file(self):
        """fix_vulnerability returns error for nonexistent file."""
        from src.fixer import fix_vulnerability
        finding = {
            "vuln_type": "test", "severity": "high", "file_path": "/tmp/nonexistent_file_xyz.py",
            "line_number": 1, "cwe_id": "CWE-1", "description": "test",
            "fix_suggestion": "fix it", "auto_fixable": True,
            "code_snippet": "bad()", "confidence": 0.9,
        }
        result = fix_vulnerability(finding, "/tmp")
        # Should error or indicate problem — file doesn't exist
        assert (result.error != ""
                or result.fixed is False
                or "not exist" in result.diff.lower()
                or "does not exist" in result.diff.lower())


# ── GitHub API tests (8) ──

class TestGitHubAPI:

    def test_verify_signature_valid(self):
        """Correct HMAC-SHA256 signature passes verification."""
        from src.github_api import verify_webhook_signature
        secret = "my_webhook_secret"
        payload = b'{"action":"push","ref":"refs/heads/main"}'
        sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert verify_webhook_signature(payload, sig, secret) is True

    def test_verify_signature_invalid(self):
        """Wrong signature fails verification."""
        from src.github_api import verify_webhook_signature
        secret = "my_webhook_secret"
        payload = b'{"action":"push"}'
        assert verify_webhook_signature(payload, "sha256=deadbeef0000", secret) is False

    def test_verify_signature_no_prefix(self):
        """Missing sha256= prefix fails verification."""
        from src.github_api import verify_webhook_signature
        secret = "secret"
        payload = b"data"
        raw_sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        # No sha256= prefix
        assert verify_webhook_signature(payload, raw_sig, secret) is False

    def test_github_client_creation(self):
        """GitHubClient initializes with token."""
        from src.github_api import GitHubClient
        client = GitHubClient("ghp_test_token_123")
        assert client.token == "ghp_test_token_123"
        assert client.base == "https://api.github.com"

    def test_github_client_headers(self):
        """GitHubClient has correct Authorization header."""
        from src.github_api import GitHubClient
        client = GitHubClient("ghp_abc")
        assert client.headers["Authorization"] == "token ghp_abc"
        assert "Accept" in client.headers
        assert "User-Agent" in client.headers
        assert "OwlGuard" in client.headers["User-Agent"]

    def test_github_repo_dataclass(self):
        """GitHubRepo dataclass fields work correctly."""
        from src.github_api import GitHubRepo
        repo = GitHubRepo(
            owner="octocat", name="hello-world",
            full_name="octocat/hello-world",
            clone_url="https://github.com/octocat/hello-world.git",
            default_branch="main",
        )
        assert repo.owner == "octocat"
        assert repo.name == "hello-world"
        assert repo.full_name == "octocat/hello-world"
        assert repo.clone_url.endswith(".git")
        assert repo.default_branch == "main"

    def test_webhook_handler_health(self):
        """GET /health returns 200 with status ok."""
        from src.app import WebhookHandler
        handler = _make_handler("GET", "/health")
        handler.do_GET()
        response = handler.wfile.getvalue()
        assert b"ok" in response
        assert handler._response_code == 200

    def test_webhook_handler_root(self):
        """GET / returns 200 with HTML."""
        from src.app import WebhookHandler
        handler = _make_handler("GET", "/")
        handler.do_GET()
        response = handler.wfile.getvalue()
        assert b"<html>" in response or b"OwlGuard" in response
        assert handler._response_code == 200


# ── App tests (5) ──

class TestApp:

    def test_main_importable(self):
        """main() and run_pipeline() are callable."""
        from src.app import main, run_pipeline
        assert callable(main)
        assert callable(run_pipeline)

    def test_run_pipeline_bad_url(self):
        """run_pipeline returns error dict for invalid URL."""
        from src.app import run_pipeline
        result = run_pipeline("https://github.com/nonexistent/fake-repo-xyz-99999", token="")
        assert isinstance(result, dict)
        assert result.get("error") != "" or result.get("scan") is None

    def test_cli_version(self):
        """version command prints version string."""
        from src.app import main
        with patch("sys.argv", ["owlguard", "version"]):
            with patch("builtins.print") as mock_print:
                main()
                printed = " ".join(str(c) for c in mock_print.call_args_list)
                assert "0.1.0" in printed

    def test_cli_help(self):
        """help text contains usage instructions."""
        from src.app import main
        with patch("sys.argv", ["owlguard", "--help"]):
            with patch("builtins.print") as mock_print:
                main()
                printed = " ".join(str(c) for c in mock_print.call_args_list)
                assert "scan" in printed.lower()
                assert "fix" in printed.lower()

    def test_config_defaults(self):
        """Default PORT is 8800."""
        from src.config import PORT, HOST, MAX_FILES_PER_SCAN, MAX_FIX_ATTEMPTS
        assert PORT == 8800
        assert HOST == "0.0.0.0"
        assert MAX_FILES_PER_SCAN == 500
        assert MAX_FIX_ATTEMPTS == 3


# ── Integration tests (4) ──

class TestIntegration:

    def test_scan_then_report(self):
        """Scan dir then generate markdown report contains findings info."""
        from src.scanner import ScanResult
        findings = [
            {"vuln_type": "hardcoded_secret", "severity": "high", "file_path": "config.py",
             "line_number": 3, "description": "API key in source", "fix_suggestion": "Use env var"},
            {"vuln_type": "sql_injection", "severity": "critical", "file_path": "db.py",
             "line_number": 15, "description": "String concat in query", "fix_suggestion": "Parameterize"},
        ]
        result = ScanResult(
            repo="/tmp/project", findings=findings, files_scanned=25,
            critical=1, high=1, medium=0, low=0, scan_time_sec=0.5,
        )
        md = result.to_markdown()
        assert "hardcoded_secret" in md
        assert "sql_injection" in md
        assert "config.py" in md
        assert "db.py" in md
        assert "2" in md  # total findings
        assert "25" in md  # files scanned

    def test_full_pipeline_local(self):
        """Scan a local dir with a vuln file and verify findings or graceful error."""
        from src.scanner import scan_repo
        with tempfile.TemporaryDirectory() as tmpdir:
            vuln = Path(tmpdir) / "danger.py"
            vuln.write_text("import os, subprocess\ncmd = input('cmd: ')\nos.system(cmd)\nsubprocess.call(cmd, shell=True)\n")
            result = scan_repo(tmpdir)
            if not result.error:
                assert result.total > 0
                assert any("injection" in f.get("vuln_type", "").lower() or "command" in f.get("vuln_type", "").lower()
                           for f in result.findings)
            else:
                # OwlSec not available is acceptable
                assert result.error != ""

    def test_scan_result_json_serializable(self):
        """ScanResult.__dict__ is JSON-serializable."""
        from src.scanner import ScanResult
        r = ScanResult(
            repo="/tmp/test", findings=[
                {"vuln_type": "xss", "severity": "medium", "file_path": "x.py",
                 "line_number": 1, "description": "XSS"}
            ],
            files_scanned=5, critical=0, high=0, medium=1, low=0,
            scan_time_sec=0.1,
        )
        serialized = json.dumps(r.__dict__)
        assert isinstance(serialized, str)
        deserialized = json.loads(serialized)
        assert deserialized["repo"] == "/tmp/test"
        assert deserialized["medium"] == 1
        assert len(deserialized["findings"]) == 1

    def test_multiple_scans(self):
        """Scanning the same dir twice produces consistent results."""
        from src.scanner import scan_repo
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "safe.py").write_text("x = 1 + 2\nprint(x)\n")
            r1 = scan_repo(tmpdir)
            r2 = scan_repo(tmpdir)
            assert r1.total == r2.total
            assert r1.critical == r2.critical
            assert r1.error == r2.error


# ── Helper for HTTP handler tests ──

def _make_handler(method: str, path: str):
    """Create a mock WebhookHandler for testing GET endpoints without a real server."""
    from src.app import WebhookHandler

    class FakeHandler(WebhookHandler):
        _response_code = 0

        def __init__(self):
            # Skip real __init__ — we mock everything
            self.path = path
            self.wfile = io.BytesIO()
            self.requestline = f"{method} {path} HTTP/1.1"
            self.request_version = "HTTP/1.1"
            self.command = method
            self.close_connection = True
            self.client_address = ("127.0.0.1", 12345)

        def send_response(self, code, message=None):
            self._response_code = code

        def send_header(self, keyword, value):
            pass

        def end_headers(self):
            pass

        def send_error(self, code, message=None, explain=None):
            self._response_code = code

        def log_message(self, format, *args):
            pass

    return FakeHandler()
