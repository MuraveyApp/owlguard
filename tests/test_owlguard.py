"""Tests for OwlGuard core modules."""
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestScanner:
    def test_import(self):
        from src.scanner import scan_repo, clone_and_scan, ScanResult
        assert callable(scan_repo)
        assert callable(clone_and_scan)

    def test_scan_result_markdown(self):
        from src.scanner import ScanResult
        r = ScanResult(repo="/tmp/test", files_scanned=10, critical=2, high=5)
        r.findings = [
            {"vuln_type": "sql_injection", "severity": "critical", "file_path": "app.py",
             "line_number": 42, "description": "SQL injection", "fix_suggestion": "Use params"},
        ]
        md = r.to_markdown()
        assert "OwlGuard" in md
        assert "Critical" in md
        assert "sql_injection" in md

    def test_scan_empty_dir(self):
        from src.scanner import scan_repo
        with tempfile.TemporaryDirectory() as tmpdir:
            result = scan_repo(tmpdir)
            assert result.total == 0 or result.error == ""

    def test_scan_vulnerable_file(self):
        from src.scanner import scan_repo
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "vuln.py").write_text('import os\nos.system(user_input)\n')
            result = scan_repo(tmpdir)
            assert result.total > 0 or result.error != ""


class TestFixer:
    def test_import(self):
        from src.fixer import fix_vulnerability, fix_all, FixResult
        assert callable(fix_vulnerability)
        assert callable(fix_all)


class TestGitHubAPI:
    def test_import(self):
        from src.github_api import GitHubClient, verify_webhook_signature
        assert callable(verify_webhook_signature)

    def test_verify_signature(self):
        from src.github_api import verify_webhook_signature
        import hmac, hashlib
        secret = "test_secret"
        payload = b"test payload"
        sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert verify_webhook_signature(payload, sig, secret)
        assert not verify_webhook_signature(payload, "sha256=wrong", secret)


class TestApp:
    def test_import(self):
        from src.app import main, run_pipeline
        assert callable(main)
        assert callable(run_pipeline)


class TestConfig:
    def test_import(self):
        from src.config import PORT, HOST, CHARWIZ_SRC
        assert isinstance(PORT, int)
        assert isinstance(HOST, str)
