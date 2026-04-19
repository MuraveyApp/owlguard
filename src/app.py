"""OwlGuard App — GitHub webhook handler + scan/fix pipeline.

Receives GitHub webhooks, scans code, generates fixes, creates PRs.

Usage:
    owlguard                          # Start webhook server
    owlguard scan <repo_url>          # One-shot scan
    owlguard scan <local_path>        # Scan local directory
    owlguard fix <local_path>         # Scan + auto-fix
"""
import json
import os
import sys
import tempfile
import subprocess
import time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

from .config import PORT, HOST, GITHUB_WEBHOOK_SECRET
from .scanner import scan_repo, clone_and_scan, ScanResult
from .fixer import fix_all, FixResult
from .github_api import GitHubClient, verify_webhook_signature


# ── Pipeline ──

def run_pipeline(repo_url: str, token: str, pr_number: int = 0,
                 owner: str = "", name: str = "") -> dict:
    """Full OwlGuard pipeline: clone → scan → fix → PR.

    Returns: {"scan": ScanResult, "fixes": [FixResult], "pr_url": str}
    """
    result = {"scan": None, "fixes": [], "pr_url": "", "error": ""}

    # 1. Clone and scan
    print(f"[OwlGuard] Scanning {repo_url}...")
    with tempfile.TemporaryDirectory(prefix="owlguard_") as tmpdir:
        workspace = f"{tmpdir}/repo"
        clone_result = subprocess.run(
            f"git clone --depth 10 {repo_url} {workspace}",
            shell=True, capture_output=True, text=True, timeout=120,
        )
        if clone_result.returncode != 0:
            result["error"] = f"Clone failed: {clone_result.stderr[:200]}"
            return result

        scan = scan_repo(workspace)
        result["scan"] = scan
        print(f"[OwlGuard] Found {scan.total} findings ({scan.critical}C {scan.high}H {scan.medium}M)")

        if scan.total == 0:
            return result

        # 2. Fix critical and high vulnerabilities
        critical_high = [f for f in scan.findings if f["severity"] in ("critical", "high")]
        if critical_high:
            print(f"[OwlGuard] Fixing {len(critical_high)} critical/high findings...")
            fixes = fix_all(critical_high, workspace, max_fixes=5)
            result["fixes"] = fixes
            fixed_count = sum(1 for f in fixes if f.fixed)
            print(f"[OwlGuard] Fixed {fixed_count}/{len(fixes)}")

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
                        body += f"- ✅ **{fix.vuln_type}** in `{fix.file_path}` ({fix.method})\n"

                    pr = gh.create_pr(
                        owner, name,
                        title=f"🦉 OwlGuard: Fix {len(fixed_results)} security vulnerabilities",
                        body=body,
                        head=branch,
                    )
                    result["pr_url"] = pr.get("html_url", "")
                    print(f"[OwlGuard] PR created: {result['pr_url']}")
                except Exception as e:
                    result["error"] = f"PR creation failed: {e}"

        # 4. If PR requested, post scan report as comment
        if token and owner and name and pr_number and not result["pr_url"]:
            try:
                gh = GitHubClient(token)
                gh.comment_on_pr(owner, name, pr_number, scan.to_markdown())
                print(f"[OwlGuard] Posted scan report on PR #{pr_number}")
            except Exception as e:
                result["error"] = f"Comment failed: {e}"

    return result


# ── Webhook Handler ──

class WebhookHandler(BaseHTTPRequestHandler):
    """Handle GitHub webhook events."""

    def do_POST(self):
        if self.path != "/webhook":
            self.send_error(404)
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
        data = json.loads(payload)

        # Respond immediately
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "accepted"}')

        # Process async
        if event == "push":
            self._handle_push(data)
        elif event == "pull_request":
            self._handle_pr(data)

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
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "version": "0.1.0"}).encode())
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<html><body style="font-family:monospace;background:#1a1a2e;color:#e0e0e0;text-align:center;padding:100px">
<h1 style="color:#53d8fb">OwlGuard</h1>
<p>finds, fixes, ships.</p>
<p style="color:#666">POST /webhook for GitHub events</p>
</body></html>""")
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        print(f"[OwlGuard] {args[0]}" if args else "")


# ── CLI ──

def main():
    args = sys.argv[1:]

    if not args or args[0] == "serve":
        print(f"🦉 OwlGuard v0.1.0 — finds, fixes, ships.")
        print(f"Webhook: http://{HOST}:{PORT}/webhook")
        print(f"Health:  http://{HOST}:{PORT}/health")
        server = HTTPServer((HOST, PORT), WebhookHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")
        return

    if args[0] == "scan":
        target = args[1] if len(args) > 1 else "."
        if target.startswith("http"):
            result = clone_and_scan(target)
        else:
            result = scan_repo(target)
        print(result.to_markdown())
        sys.exit(1 if result.has_critical else 0)

    if args[0] == "fix":
        target = args[1] if len(args) > 1 else "."
        scan = scan_repo(target)
        print(f"Found {scan.total} findings. Fixing critical/high...")
        critical_high = [f for f in scan.findings if f["severity"] in ("critical", "high")]
        if critical_high:
            fixes = fix_all(critical_high, target, max_fixes=5)
            for f in fixes:
                status = "✅" if f.fixed else "❌"
                print(f"  {status} {f.vuln_type} in {f.file_path} ({f.method or f.error})")
        else:
            print("No critical/high findings to fix.")

    if args[0] == "version":
        print("owlguard 0.1.0")

    if args[0] == "--help" or args[0] == "-h":
        print("""🦉 OwlGuard — finds, fixes, ships.

Usage:
  owlguard                    Start webhook server
  owlguard scan <path|url>    Scan repo for vulnerabilities
  owlguard fix <path>         Scan + auto-fix critical/high
  owlguard version            Show version
""")


if __name__ == "__main__":
    main()
