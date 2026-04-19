"""OwlGuard Fixer — two-pass fix: auto-fixers first, OwlMind for complex cases.

Pass 1: OwlSec auto-fixers (30 types) — instant, deterministic, free
Pass 2: OwlMind AI pipeline — for what auto-fixers can't handle
"""
import sys
import difflib
import logging
from pathlib import Path
from dataclasses import dataclass, field

from .config import CHARWIZ_SRC, MAX_FIX_ATTEMPTS

logger = logging.getLogger("owlguard.fixer")


@dataclass
class FixResult:
    """Result of fixing a vulnerability."""
    vuln_type: str
    file_path: str
    fixed: bool = False
    diff: str = ""
    method: str = ""  # "auto-fixer" or "owlmind"
    error: str = ""


def fix_all(findings: list[dict], workspace: str, max_fixes: int = 10) -> list[FixResult]:
    """Fix vulnerabilities in two passes.

    Pass 1: Try OwlSec auto-fixers on ALL auto_fixable findings (instant)
    Pass 2: Use OwlMind AI for remaining critical/high (slower, costs $)
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "low"), 4))

    results = []
    remaining = []

    # Pass 1: Auto-fixers (instant, free)
    logger.info("Pass 1: Auto-fixers...")
    for finding in sorted_findings[:max_fixes]:
        if finding.get("auto_fixable"):
            result = _try_auto_fix(finding, workspace)
            results.append(result)
            if not result.fixed:
                remaining.append(finding)
        else:
            remaining.append(finding)

    fixed_pass1 = sum(1 for r in results if r.fixed)
    logger.info(f"Pass 1 complete: {fixed_pass1} fixed by auto-fixers")

    # Pass 2: OwlMind AI for remaining critical/high
    if remaining:
        critical_remaining = [f for f in remaining if f["severity"] in ("critical", "high")]
        if critical_remaining:
            logger.info(f"Pass 2: OwlMind AI for {len(critical_remaining)} remaining findings...")
            for finding in critical_remaining[:3]:  # Max 3 AI fixes (expensive)
                result = _try_owlmind_fix(finding, workspace)
                results.append(result)

    fixed_total = sum(1 for r in results if r.fixed)
    logger.info(f"Total: {fixed_total}/{len(results)} fixed")
    return results


def fix_vulnerability(finding: dict, workspace: str) -> FixResult:
    """Fix a single vulnerability. Auto-fixer first, then OwlMind."""
    if finding.get("auto_fixable"):
        result = _try_auto_fix(finding, workspace)
        if result.fixed:
            return result
    return _try_owlmind_fix(finding, workspace)


def _try_auto_fix(finding: dict, workspace: str) -> FixResult:
    """Try OwlSec's built-in auto-fixer (30 types)."""
    if CHARWIZ_SRC not in sys.path:
        sys.path.insert(0, CHARWIZ_SRC)

    try:
        from owlmind.owlsec.fixer import SecurityFixer

        fixer = SecurityFixer()

        # Map OwlGuard finding to OwlSec vuln format
        vuln = {
            "type": finding["vuln_type"],
            "file": finding["file_path"],
            "line": finding["line_number"],
            "code": finding.get("code_snippet", ""),
        }

        # Read original for diff
        fp = Path(finding["file_path"])
        if not fp.is_absolute():
            fp = Path(workspace) / fp
        if not fp.exists():
            return FixResult(vuln_type=finding["vuln_type"], file_path=str(fp), error="File not found")

        original = fp.read_text()

        # Apply fix
        fix_result = fixer.fix(workspace, vuln, dry_run=False)

        if fix_result.success:
            # Generate diff
            new_content = fp.read_text() if fp.exists() else fix_result.fixed_code
            diff = "\n".join(difflib.unified_diff(
                original.splitlines(), new_content.splitlines(),
                fromfile=f"a/{fp.name}", tofile=f"b/{fp.name}", lineterm="",
            ))
            return FixResult(
                vuln_type=finding["vuln_type"],
                file_path=str(fp),
                fixed=True,
                diff=diff,
                method="auto-fixer",
            )

        return FixResult(
            vuln_type=finding["vuln_type"],
            file_path=str(fp),
            error=fix_result.description or "Auto-fixer could not fix",
        )

    except Exception as e:
        logger.error(f"Auto-fix error: {e}")
        return FixResult(
            vuln_type=finding.get("vuln_type", ""),
            file_path=finding.get("file_path", ""),
            error=str(e),
        )


def _try_owlmind_fix(finding: dict, workspace: str) -> FixResult:
    """Use OwlMind 4-stage pipeline for complex fixes."""
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
            f"\nFix ONLY this vulnerability. Do not refactor other code."
        )

        runner = GraphRunner()
        state = runner.run(
            goal=goal,
            workspace=workspace,
            max_iterations=MAX_FIX_ATTEMPTS,
            skip_tester=False,
        )

        verdict = (state.final_verdict or "").upper()
        if "APPROVED" in verdict:
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
            error=f"OwlMind: {state.final_verdict}",
        )

    except Exception as e:
        logger.error(f"OwlMind error: {e}")
        return FixResult(
            vuln_type=finding.get("vuln_type", ""),
            file_path=finding.get("file_path", ""),
            error=str(e),
        )
