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
_SQL_QUERY_ASSIGNMENT = re.compile(
    r"^(?P<indent>\s*)query\s*=\s*f(?P<quote>['\"])(?P<select>.*?)(?P=quote)\s*$"
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
        return {
            "fixed_code": f'{name} = os.environ["{name}"]',
            "fix_explanation": (
                "The literal secret is removed from source and read from the "
                "process environment at runtime. Rotate the exposed value and "
                "configure the replacement outside version control."
            ),
            "remediation_time": "5 minutes",
            "fix_source": "deterministic",
        }

    if vuln_type == "SQL Injection":
        return _deterministic_sql_fix(finding)

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
    path = finding.get("_scan_file_path") or finding.get("file_path")
    line_number = finding.get("line_number")
    if not path or not isinstance(line_number, int) or line_number < 1:
        return None
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    return lines[line_number - 1] if line_number <= len(lines) else None


def _read_source_lines(finding: dict) -> list[str] | None:
    """Read the scanned source file while the pipeline checkout is retained."""
    path = finding.get("_scan_file_path") or finding.get("file_path")
    if not path:
        return None
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None


def _deterministic_sql_fix(finding: dict) -> dict | None:
    """Fix a narrow two-line DB-API pattern: query assignment + execute(query)."""
    lines = _read_source_lines(finding)
    line_number = finding.get("line_number")
    if not lines or not isinstance(line_number, int) or line_number < 1:
        return None
    if line_number >= len(lines):
        return None

    query_line = lines[line_number - 1]
    execute_line = lines[line_number]
    query_match = _SQL_QUERY_ASSIGNMENT.fullmatch(query_line)
    execute_match = re.fullmatch(
        r"(?P<indent>\s*)(?P<target>(?:\w+\s*=\s*)?)(?P<cursor>\w+)\.execute\(\s*query\s*\)\s*",
        execute_line,
    )
    if not query_match or not execute_match:
        return None

    expressions = re.findall(r"\{([^{}!:\n]+)(?:![^{}:\n]+)?(?::[^{}\n]+)?\}", query_line)
    if len(expressions) != 1:
        return None
    parameter = expressions[0].strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?", parameter):
        return None

    raw_sql = query_match.group("select")
    parameterized_sql = re.sub(r"\{[^{}]+\}", "?", raw_sql, count=1)
    quote = query_match.group("quote")
    vulnerable_code = f"{query_line}\n{execute_line}"
    replacement = (
        f"{query_match.group('indent')}query = {quote}{parameterized_sql}{quote}\n"
        f"{execute_match.group('indent')}{execute_match.group('target')}"
        f"{execute_match.group('cursor')}.execute(query, ({parameter},))"
    )
    return {
        "vulnerable_code": vulnerable_code,
        "fixed_code": replacement,
        "fix_explanation": (
            "The query construction and execution are patched together so user "
            "input is passed as a bound parameter instead of being interpolated "
            "into the SQL string."
        ),
        "remediation_time": "15 minutes",
        "fix_source": "deterministic",
    }
