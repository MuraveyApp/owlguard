"""OwlGuard Scanner — connects OwlSec to scan repositories."""
import sys
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass, field

from .config import CHARWIZ_SRC, MAX_FILES_PER_SCAN


@dataclass
class ScanResult:
    """Result of scanning a repository."""
    repo: str
    findings: list[dict] = field(default_factory=list)
    files_scanned: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    scan_time_sec: float = 0.0
    error: str = ""

    @property
    def has_critical(self) -> bool:
        return self.critical > 0

    @property
    def total(self) -> int:
        return len(self.findings)

    def to_markdown(self) -> str:
        lines = [f"## 🦉 OwlGuard Security Report\n"]
        lines.append(f"**{self.total}** findings in **{self.files_scanned}** files\n")
        if self.critical:
            lines.append(f"🔴 **{self.critical} Critical**")
        if self.high:
            lines.append(f"🟠 **{self.high} High**")
        if self.medium:
            lines.append(f"🟡 **{self.medium} Medium**")
        if self.low:
            lines.append(f"🟢 **{self.low} Low**")
        lines.append("")

        # Group by file
        by_file: dict[str, list] = {}
        for f in self.findings:
            fp = f.get("file_path", "?")
            by_file.setdefault(fp, []).append(f)

        for fp, vulns in sorted(by_file.items()):
            lines.append(f"### `{fp}`")
            for v in vulns:
                sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(v.get("severity", ""), "⚪")
                lines.append(f"- {sev_icon} **{v.get('vuln_type', '?')}** (L{v.get('line_number', '?')}) — {v.get('description', '')[:120]}")
                if v.get("fix_suggestion"):
                    lines.append(f"  - 💡 Fix: {v['fix_suggestion'][:100]}")
            lines.append("")

        lines.append("---")
        lines.append("*Powered by [OwlGuard](https://owlguard.dev) — finds, fixes, ships.*")
        return "\n".join(lines)


def scan_repo(repo_path: str, skip_tests: bool = True) -> ScanResult:
    """Scan a local repository with OwlSec."""
    import time

    # Ensure OwlSec is importable
    if CHARWIZ_SRC not in sys.path:
        sys.path.insert(0, CHARWIZ_SRC)

    try:
        from owlmind.owlsec import OwlSec

        start = time.time()
        sec = OwlSec()
        report = sec.scan(repo_path, skip_tests=skip_tests, dry_run=True)
        elapsed = time.time() - start

        findings = []
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in report.vulnerabilities:
            by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
            findings.append({
                "vuln_type": v.vuln_type,
                "severity": v.severity,
                "cwe_id": v.cwe_id,
                "file_path": v.file_path,
                "line_number": v.line_number,
                "code_snippet": v.code_snippet,
                "description": v.description,
                "fix_suggestion": v.fix_suggestion,
                "auto_fixable": v.auto_fixable,
                "confidence": v.confidence,
            })

        return ScanResult(
            repo=repo_path,
            findings=findings,
            files_scanned=report.total_files_scanned,
            critical=by_sev["critical"],
            high=by_sev["high"],
            medium=by_sev["medium"],
            low=by_sev["low"],
            scan_time_sec=elapsed,
        )
    except Exception as e:
        return ScanResult(repo=repo_path, error=str(e))


def clone_and_scan(repo_url: str, branch: str = "main") -> ScanResult:
    """Clone a GitHub repo to temp dir and scan it."""
    with tempfile.TemporaryDirectory(prefix="owlguard_") as tmpdir:
        result = subprocess.run(
            f"git clone --depth 1 -b {branch} {repo_url} {tmpdir}/repo",
            shell=True, capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            return ScanResult(repo=repo_url, error=f"Clone failed: {result.stderr[:200]}")

        return scan_repo(f"{tmpdir}/repo")
