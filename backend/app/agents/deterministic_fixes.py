"""Small, audited fixes for source patterns ShieldLabs can prove it understands.

These transformations intentionally cover a narrow set of patterns.  Returning
``None`` means that the caller must use the LLM/manual-review route instead of
pretending that an uncertain transformation is safe.
"""

from __future__ import annotations

import re
from pathlib import Path


_SECRET_ASSIGNMENT = re.compile(
    r"^(?P<name>[A-Z][A-Z0-9_]*)\s*=\s*(?P<quote>['\"]).*?(?P=quote)\s*$"
)
_REDIRECT_LINE = re.compile(
    r"^\s*return\s+redirect\(request\.(?:args|form|values)\.get\(['\"]url['\"]\)\)\s*$"
)


def deterministic_fix(finding: dict) -> dict | None:
    """Return a verified fix payload for a supported finding, or ``None``.

    The payload may update ``vulnerable_code`` when a scanner regex captured
    only part of a complete Python statement.  That lets Auto-PR replace the
    actual statement rather than attempting an unsafe partial rewrite.
    """
    vuln_type = finding.get("vuln_type")
    code = (finding.get("vulnerable_code") or "").strip()

    if vuln_type == "Hardcoded Secrets":
        match = _SECRET_ASSIGNMENT.fullmatch(code)
        if not match:
            return None
        name = match.group("name")
        import_prefix = "" if _has_os_import(finding) else "import os\n"
        return {
            "fixed_code": f'{import_prefix}{name} = os.environ["{name}"]',
            "fix_explanation": (
                "The literal secret is removed from source and read from the "
                "process environment at runtime. Rotate the exposed value and "
                "configure the replacement outside version control."
            ),
            "remediation_time": "5 minutes",
            "fix_source": "deterministic",
        }

    if vuln_type == "Unvalidated Redirects":
        source_line = _read_source_line(finding)
        if not source_line or not _REDIRECT_LINE.fullmatch(source_line):
            return None
        return {
            "vulnerable_code": source_line.strip(),
            "fixed_code": (
                "target = request.args.get('url', '/')\n"
                "if not target.startswith('/') or target.startswith('//'):\n"
                "    target = '/'\n"
                "return redirect(target)"
            ),
            "fix_explanation": (
                "Only single-slash relative paths are accepted, preventing external "
                "and protocol-relative redirect targets."
            ),
            "remediation_time": "15 minutes",
            "fix_source": "deterministic",
        }

    return None


def _read_source_line(finding: dict) -> str | None:
    """Read the full statement line for narrowly supported transformations."""
    path = finding.get("file_path")
    line_number = finding.get("line_number")
    if not path or not isinstance(line_number, int) or line_number < 1:
        return None
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    return lines[line_number - 1] if line_number <= len(lines) else None


def _has_os_import(finding: dict) -> bool:
    """Only emit ``os.environ`` when the scanned module already imports os."""
    path = finding.get("file_path")
    if not path:
        return False
    try:
        source = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return bool(re.search(r"^\s*import\s+os(?:\s|$|#)", source, re.MULTILINE))
