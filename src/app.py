"""OwlGuard App — GitHub webhook handler + scan/fix pipeline.

Receives GitHub webhooks, scans code, generates fixes, creates PRs.

Usage:
    owlguard                          # Start webhook server
    owlguard scan <repo_url>          # One-shot scan
    owlguard scan <local_path>        # Scan local directory
    owlguard fix <local_path>         # Scan + auto-fix
"""
import json
import logging
import os
import sys
import tempfile
import subprocess
import threading
import time
import traceback
import uuid
from collections import defaultdict
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

from .config import PORT, HOST, GITHUB_WEBHOOK_SECRET
from .scanner import scan_repo, clone_and_scan, ScanResult
from .fixer import fix_all, FixResult
from .github_api import GitHubClient, verify_webhook_signature

# ── Logging ──

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("owlguard")

# ── Globals ──

_start_time = time.monotonic()
_owlsec_available: bool | None = None
_owlmind_available: bool | None = None

# ── Rate Limiting ──

_rate_lock = threading.Lock()
_rate_store: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT = 30  # requests per minute per IP
_RATE_WINDOW = 60  # seconds


def _check_rate_limit(ip: str) -> int:
    """Check rate limit for an IP. Returns remaining requests, or -1 if exceeded."""
    now = time.monotonic()
    with _rate_lock:
        timestamps = _rate_store[ip]
        # Prune old entries
        cutoff = now - _RATE_WINDOW
        _rate_store[ip] = [t for t in timestamps if t > cutoff]
        timestamps = _rate_store[ip]

        if len(timestamps) >= _RATE_LIMIT:
            return -1
        timestamps.append(now)
        return _RATE_LIMIT - len(timestamps)


def _check_availability():
    """Check if OwlSec and OwlMind are importable."""
    global _owlsec_available, _owlmind_available
    from .config import CHARWIZ_SRC
    if CHARWIZ_SRC not in sys.path:
        sys.path.insert(0, CHARWIZ_SRC)
    try:
        import importlib
        importlib.import_module("owlmind.owlsec")
        _owlsec_available = True
    except Exception:
        _owlsec_available = False
    try:
        import importlib
        importlib.import_module("owlmind.graph")
        _owlmind_available = True
    except Exception:
        _owlmind_available = False


# ── Pipeline ──

def run_pipeline(repo_url: str, token: str, pr_number: int = 0,
                 owner: str = "", name: str = "") -> dict:
    """Full OwlGuard pipeline: clone -> scan -> fix -> PR.

    Returns: {"scan": ScanResult, "fixes": [FixResult], "pr_url": str}
    """
    result = {"scan": None, "fixes": [], "pr_url": "", "error": ""}

    # 1. Clone and scan
    logger.info("Scanning %s...", repo_url)
    with tempfile.TemporaryDirectory(prefix="owlguard_") as tmpdir:
        workspace = f"{tmpdir}/repo"
        clone_result = subprocess.run(
            f"git clone --depth 10 {repo_url} {workspace}",
            shell=True, capture_output=True, text=True, timeout=120,
        )
        if clone_result.returncode != 0:
            result["error"] = f"Clone failed: {clone_result.stderr[:200]}"
            logger.error("Clone failed for %s: %s", repo_url, clone_result.stderr[:200])
            return result

        scan = scan_repo(workspace)
        result["scan"] = scan
        logger.info("Found %d findings (%dC %dH %dM) in %s",
                     scan.total, scan.critical, scan.high, scan.medium, repo_url)

        if scan.total == 0:
            return result

        # 2. Fix critical and high vulnerabilities
        critical_high = [f for f in scan.findings if f["severity"] in ("critical", "high")]
        if critical_high:
            logger.info("Fixing %d critical/high findings...", len(critical_high))
            fixes = fix_all(critical_high, workspace, max_fixes=5)
            result["fixes"] = fixes
            fixed_count = sum(1 for f in fixes if f.fixed)
            logger.info("Fixed %d/%d findings", fixed_count, len(fixes))

        # 3. Create PR if we have fixes and GitHub token
        if token and owner and name:
            fixed_results = [f for f in result["fixes"] if f.fixed]
            if fixed_results:
                try:
                    gh = GitHubClient(token)
                    branch = f"owlguard/fix-{int(time.time())}"
                    base_sha = gh.get_default_branch_sha(owner, name)
                    gh.create_branch(owner, name, branch, base_sha)

                    # Create PR
                    body = scan.to_markdown()
                    body += f"\n\n### Fixes Applied\n"
                    for fix in fixed_results:
                        body += f"- **{fix.vuln_type}** in `{fix.file_path}` ({fix.method})\n"

                    pr = gh.create_pr(
                        owner, name,
                        title=f"OwlGuard: Fix {len(fixed_results)} security vulnerabilities",
                        body=body,
                        head=branch,
                    )
                    result["pr_url"] = pr.get("html_url", "")
                    logger.info("PR created: %s", result["pr_url"])
                except Exception as e:
                    result["error"] = f"PR creation failed: {e}"
                    logger.error("PR creation failed: %s", e)

        # 4. If PR requested, post scan report as comment
        if token and owner and name and pr_number and not result["pr_url"]:
            try:
                gh = GitHubClient(token)
                gh.comment_on_pr(owner, name, pr_number, scan.to_markdown())
                logger.info("Posted scan report on PR #%d", pr_number)
            except Exception as e:
                result["error"] = f"Comment failed: {e}"
                logger.error("Comment on PR #%d failed: %s", pr_number, e)

    return result


# ── Webhook Handler ──

class WebhookHandler(BaseHTTPRequestHandler):
    """Handle GitHub webhook events."""

    def do_POST(self):
        if self.path != "/webhook":
            self.send_error(404)
            return

        # Rate limiting
        client_ip = self.client_address[0]
        remaining = _check_rate_limit(client_ip)
        if remaining < 0:
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-RateLimit-Remaining", "0")
            self.end_headers()
            self.wfile.write(b'{"error": "rate limit exceeded"}')
            logger.warning("Rate limit exceeded for %s", client_ip)
            return

        length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(length)

        # Verify signature
        if GITHUB_WEBHOOK_SECRET:
            sig = self.headers.get("X-Hub-Signature-256", "")
            if not verify_webhook_signature(payload, sig, GITHUB_WEBHOOK_SECRET):
                self.send_error(403, "Invalid signature")
                return

        event = self.headers.get("X-GitHub-Event", "")
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON payload: %s", e)
            self.send_error(400, "Invalid JSON")
            return

        # Respond 202 immediately, process in background
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-RateLimit-Remaining", str(remaining))
        self.end_headers()
        self.wfile.write(b'{"status": "accepted"}')

        # Process in background thread
        if event == "push":
            threading.Thread(
                target=self._safe_handle_push, args=(data,), daemon=True
            ).start()
        elif event == "pull_request":
            threading.Thread(
                target=self._safe_handle_pr, args=(data,), daemon=True
            ).start()

    def _safe_handle_push(self, data: dict):
        """Handle push event with error handling."""
        error_id = uuid.uuid4().hex[:8]
        try:
            self._handle_push(data)
        except Exception:
            logger.error("Push handler error [%s]:\n%s", error_id, traceback.format_exc())

    def _safe_handle_pr(self, data: dict):
        """Handle PR event with error handling."""
        error_id = uuid.uuid4().hex[:8]
        try:
            self._handle_pr(data)
        except Exception:
            logger.error("PR handler error [%s]:\n%s", error_id, traceback.format_exc())

    def _handle_push(self, data: dict):
        repo = data.get("repository", {})
        owner = repo.get("owner", {}).get("login", "")
        name = repo.get("name", "")
        clone_url = repo.get("clone_url", "")
        token = os.environ.get("GITHUB_TOKEN", "")

        if clone_url and token:
            run_pipeline(clone_url, token, owner=owner, name=name)

    def _handle_pr(self, data: dict):
        action = data.get("action", "")
        if action not in ("opened", "synchronize"):
            return

        repo = data.get("repository", {})
        pr = data.get("pull_request", {})
        owner = repo.get("owner", {}).get("login", "")
        name = repo.get("name", "")
        clone_url = repo.get("clone_url", "")
        pr_number = pr.get("number", 0)
        token = os.environ.get("GITHUB_TOKEN", "")

        if clone_url and token:
            run_pipeline(clone_url, token, pr_number=pr_number, owner=owner, name=name)

    def do_GET(self):
        client_ip = self.client_address[0]
        remaining = _check_rate_limit(client_ip)
        if remaining < 0:
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-RateLimit-Remaining", "0")
            self.end_headers()
            self.wfile.write(b'{"error": "rate limit exceeded"}')
            return

        if self.path == "/health":
            # Lazy-check availability on first health request
            if _owlsec_available is None:
                _check_availability()

            uptime = int(time.monotonic() - _start_time)
            health = {
                "status": "ok",
                "version": "0.1.0",
                "owlsec": bool(_owlsec_available),
                "owlmind": bool(_owlmind_available),
                "uptime_sec": uptime,
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-RateLimit-Remaining", str(remaining))
            self.end_headers()
            self.wfile.write(json.dumps(health).encode())
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-RateLimit-Remaining", str(remaining))
            self.end_headers()
            self.wfile.write(b"""<html><body style="font-family:monospace;background:#1a1a2e;color:#e0e0e0;text-align:center;padding:100px">
<h1 style="color:#53d8fb">OwlGuard</h1>
<p>finds, fixes, ships.</p>
<p style="color:#666">POST /webhook for GitHub events</p>
</body></html>""")
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        logger.debug("%s", args[0] if args else "")


# ── CLI ──

def main():
    args = sys.argv[1:]

    if not args or args[0] == "serve":
        logger.info("OwlGuard v0.1.0 — finds, fixes, ships.")
        logger.info("Webhook: http://%s:%d/webhook", HOST, PORT)
        logger.info("Health:  http://%s:%d/health", HOST, PORT)
        server = HTTPServer((HOST, PORT), WebhookHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Stopped.")
        return

    if args[0] == "scan":
        target = args[1] if len(args) > 1 else "."
        if target.startswith("http"):
            result = clone_and_scan(target)
        else:
            result = scan_repo(target)
        logger.info("\n%s", result.to_markdown())
        sys.exit(1 if result.has_critical else 0)

    if args[0] == "fix":
        target = args[1] if len(args) > 1 else "."
        scan = scan_repo(target)
        logger.info("Found %d findings. Fixing critical/high...", scan.total)
        critical_high = [f for f in scan.findings if f["severity"] in ("critical", "high")]
        if critical_high:
            fixes = fix_all(critical_high, target, max_fixes=5)
            for f in fixes:
                status = "FIXED" if f.fixed else "FAILED"
                logger.info("  [%s] %s in %s (%s)", status, f.vuln_type, f.file_path, f.method or f.error)
        else:
            logger.info("No critical/high findings to fix.")

    if args[0] == "version":
        print("owlguard 0.1.0")

    if args[0] == "--help" or args[0] == "-h":
        print("""OwlGuard — finds, fixes, ships.

Usage:
  owlguard                    Start webhook server
  owlguard scan <path|url>    Scan repo for vulnerabilities
  owlguard fix <path>         Scan + auto-fix critical/high
  owlguard version            Show version
""")


if __name__ == "__main__":
    main()
