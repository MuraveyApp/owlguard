"""OwlGuard Fixer — uses OwlMind to generate fixes for vulnerabilities."""
import sys
from pathlib import Path
from dataclasses import dataclass, field

from .config import CHARWIZ_SRC, MAX_FIX_ATTEMPTS


@dataclass
class FixResult:
    """Result of fixing vulnerabilities."""
    vuln_type: str
    file_path: str
    fixed: bool = False
    diff: str = ""
    method: str = ""  # "auto-fixer" or "owlmind"
    error: str = ""


def fix_vulnerability(finding: dict, workspace: str) -> FixResult:
    """Fix a single vulnerability. Tries auto-fixer first, then OwlMind."""
    vuln_type = finding.get("vuln_type", "")
    file_path = finding.get("file_path", "")

    # Step 1: Try OwlSec auto-fixer (fast, deterministic)
    if finding.get("auto_fixable"):
        result = _try_auto_fix(finding, workspace)
        if result.fixed:
            return result

    # Step 2: Use OwlMind pipeline (slow, AI-powered, handles complex cases)
    return _try_owlmind_fix(finding, workspace)


def _try_auto_fix(finding: dict, workspace: str) -> FixResult:
    """Try OwlSec's built-in auto-fixer."""
    if CHARWIZ_SRC not in sys.path:
        sys.path.insert(0, CHARWIZ_SRC)

    try:
        from owlmind.owlsec import OwlSec
        from owlmind.owlsec import Vulnerability

        vuln = Vulnerability(
            vuln_type=finding["vuln_type"],
            severity=finding["severity"],
            cwe_id=finding["cwe_id"],
            file_path=finding["file_path"],
            line_number=finding["line_number"],
            code_snippet=finding.get("code_snippet", ""),
            description=finding.get("description", ""),
            fix_suggestion=finding.get("fix_suggestion", ""),
            auto_fixable=True,
        )

        sec = OwlSec()
        # Read original file
        fp = Path(finding["file_path"])
        if not fp.is_absolute():
            fp = Path(workspace) / fp
        if not fp.exists():
            return FixResult(vuln_type=finding["vuln_type"], file_path=str(fp), error="File not found")

        original = fp.read_text()

        # Apply fix
        report = sec.scan(str(fp.parent), fix=True, dry_run=False)

        # Check if file changed
        new_content = fp.read_text()
        if new_content != original:
            # Generate diff
            import difflib
            diff = "\n".join(difflib.unified_diff(
                original.splitlines(), new_content.splitlines(),
                fromfile=f"a/{fp.name}", tofile=f"b/{fp.name}", lineterm="",
            ))
            return FixResult(
                vuln_type=finding["vuln_type"], file_path=str(fp),
                fixed=True, diff=diff, method="auto-fixer",
            )
        return FixResult(vuln_type=finding["vuln_type"], file_path=str(fp), error="Auto-fixer did not change file")

    except Exception as e:
        return FixResult(vuln_type=finding.get("vuln_type", ""), file_path=finding.get("file_path", ""), error=str(e))


def _try_owlmind_fix(finding: dict, workspace: str) -> FixResult:
    """Use OwlMind pipeline to generate a fix."""
    if CHARWIZ_SRC not in sys.path:
        sys.path.insert(0, CHARWIZ_SRC)

    try:
        from owlmind.graph import GraphRunner

        goal = (
            f"Fix security vulnerability in {finding['file_path']}:\n"
            f"Type: {finding['vuln_type']} ({finding['cwe_id']})\n"
            f"Line: {finding['line_number']}\n"
            f"Description: {finding['description']}\n"
            f"Suggested fix: {finding.get('fix_suggestion', 'Apply secure coding practices')}\n"
            f"\nFix ONLY this vulnerability. Do not refactor other code. Run tests after."
        )

        runner = GraphRunner()
        state = runner.run(
            goal=goal,
            workspace=workspace,
            max_iterations=MAX_FIX_ATTEMPTS,
            skip_tester=False,
        )

        if state.final_verdict and "APPROVED" in state.final_verdict.upper():
            return FixResult(
                vuln_type=finding["vuln_type"],
                file_path=finding["file_path"],
                fixed=True,
                diff=state.code_changes or "",
                method="owlmind",
            )
        return FixResult(
            vuln_type=finding["vuln_type"],
            file_path=finding["file_path"],
            error=f"OwlMind verdict: {state.final_verdict}",
        )

    except Exception as e:
        return FixResult(vuln_type=finding.get("vuln_type", ""), file_path=finding.get("file_path", ""), error=str(e))


def fix_all(findings: list[dict], workspace: str, max_fixes: int = 10) -> list[FixResult]:
    """Fix multiple vulnerabilities, prioritized by severity."""
    # Sort by severity: critical first
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "low"), 4))

    results = []
    for finding in sorted_findings[:max_fixes]:
        result = fix_vulnerability(finding, workspace)
        results.append(result)

    return results
