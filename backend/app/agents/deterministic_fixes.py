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
    r"^\s*(?P<query_var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*f(?P<quote>['\"])(?P<sql>.*)(?P=quote)\s*$"
)
_SQL_EXECUTE_QUERY = re.compile(
    r"^\s*(?P<receiver>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\.execute\(\s*(?P<query_var>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$"
)
_SQL_INTERPOLATION = re.compile(r"\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}")


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

    if vuln_type == "SQL Injection":
        return _deterministic_sql_fix(finding)

    return None


def _deterministic_sql_fix(finding: dict) -> dict | None:
    """Fix a narrow adjacent query assignment + execute(query) SQLi pattern."""
    lines = _read_source_lines(finding, count=2)
    if len(lines) < 2:
        return None
    query_line, execute_line = lines[0], lines[1]
    query_match = _SQL_QUERY_ASSIGNMENT.fullmatch(query_line)
    execute_match = _SQL_EXECUTE_QUERY.fullmatch(execute_line)
    if not query_match or not execute_match:
        return None
    if query_match.group("query_var") != execute_match.group("query_var"):
        return None

    sql = query_match.group("sql")
    interpolations = list(_SQL_INTERPOLATION.finditer(sql))
    if len(interpolations) != 1:
        return None
    param_name = interpolations[0].group("name")
    placeholder_sql = re.sub(
        rf"(['\"])\{{{re.escape(param_name)}\}}\1|\{{{re.escape(param_name)}\}}",
        "?",
        sql,
        count=1,
    )
    if _SQL_INTERPOLATION.search(placeholder_sql):
        return None

    query_var = query_match.group("query_var")
    receiver = execute_match.group("receiver")
    safe_sql = placeholder_sql.replace('"', '\\"')
    vulnerable_code = f"{query_line.strip()}\n{execute_line.strip()}"
    fixed_code = (
        f'{query_var} = "{safe_sql}"\n'
        f"{receiver}.execute({query_var}, ({param_name},))"
    )
    return {
        "vulnerable_code": vulnerable_code,
        "fixed_code": fixed_code,
        "fix_explanation": (
            "The f-string SQL construction and its immediate execution are replaced "
            "together with a parameterized query using bound parameters."
        ),
        "remediation_time": "15 minutes",
        "fix_source": "deterministic",
    }


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


def _read_source_lines(finding: dict, count: int) -> list[str]:
    path = finding.get("_scan_file_path") or finding.get("file_path")
    line_number = finding.get("line_number")
    if not path or not isinstance(line_number, int) or line_number < 1:
        return []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    start = line_number - 1
    return lines[start:start + count]
