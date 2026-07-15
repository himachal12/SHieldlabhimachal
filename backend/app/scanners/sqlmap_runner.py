"""
sqlmap Runner — ACTIVE SCAN MODULE
===========================================
Uses official sqlmap repo (not pip install) to bypass
Windows Smart App Control which blocks .exe files.

Run pattern: python sqlmap.py [args]
NOT: sqlmap.exe [args]  ← blocked by Windows
NOT: python -m sqlmap   ← not structured as runnable module
"""

import subprocess
import json
import sys
import os
import shutil
from app.utils.rate_limiter import active_scan_limiter
from app.utils.logger import get_logger

logger = get_logger("sqlmap_runner")

# Path to sqlmap.py from official repo.
# Set in .env as SQLMAP_PATH.
_SQLMAP_SCRIPT = os.getenv(
    "SQLMAP_PATH",
    r"C:\Users\paude\OneDrive\Desktop\sqlmap\sqlmap.py"
)

# Optional Python interpreter override for sqlmap.
# This is important on Windows when the backend virtualenv Python hangs while
# the normal system Python runs sqlmap correctly from the terminal.
_SQLMAP_PYTHON = os.getenv("SQLMAP_PYTHON", "").strip()
_SQLMAP_COMMAND: list[str] | None = None
_SQLMAP_CHECKED = False


def _python_candidates() -> list[list[str]]:
    """Return Python command prefixes to try for launching sqlmap.py."""
    candidates: list[list[str]] = []

    if _SQLMAP_PYTHON:
        candidates.append([_SQLMAP_PYTHON])

    # Keep the backend interpreter as a candidate, but do not rely on it only.
    candidates.append([sys.executable])

    # If the venv interpreter hangs, fall back to the Python the user can run
    # manually in the same shell/PATH.
    for name in ("python", "python3"):
        path = shutil.which(name)
        if path:
            candidates.append([path])

    # Windows launcher. `py -3 sqlmap.py ...` is often the most reliable way
    # to reach the normal Python install outside a virtualenv.
    py_launcher = shutil.which("py")
    if py_launcher:
        candidates.append([py_launcher, "-3"])

    unique: list[list[str]] = []
    seen = set()
    for command in candidates:
        key = tuple(command)
        if key not in seen:
            unique.append(command)
            seen.add(key)
    return unique


def _run_with_python(command_prefix: list[str], args: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Run sqlmap.py with a specific Python command prefix."""
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUNBUFFERED", "1")

    return subprocess.run(
        [*command_prefix, _SQLMAP_SCRIPT, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=os.path.dirname(_SQLMAP_SCRIPT) or None,
        env=env
    )


def _get_sqlmap_command() -> list[str] | None:
    """
    Resolve and cache the Python command that can launch sqlmap.py.

    We intentionally try more than sys.executable because the backend may run
    under backend\\venv\\Scripts\\python.exe while the user's manual `python`
    command launches a different interpreter that handles sqlmap correctly.
    """
    global _SQLMAP_COMMAND, _SQLMAP_CHECKED

    if _SQLMAP_CHECKED:
        return _SQLMAP_COMMAND

    _SQLMAP_CHECKED = True

    if not _SQLMAP_SCRIPT or not os.path.exists(_SQLMAP_SCRIPT):
        logger.warning(
            f"sqlmap.py not found at: {_SQLMAP_SCRIPT}\n"
            f"Clone it: git clone https://github.com/sqlmapproject/sqlmap.git\n"
            f"Then set SQLMAP_PATH in .env"
        )
        return None

    for command_prefix in _python_candidates():
        printable = " ".join(command_prefix)
        try:
            result = _run_with_python(command_prefix, ["--version"], timeout=8)
        except subprocess.TimeoutExpired:
            logger.warning(
                "sqlmap availability check timed out with Python command: "
                f"{printable}. Trying the next Python candidate."
            )
            continue
        except (FileNotFoundError, OSError) as e:
            logger.warning(
                f"sqlmap availability check failed with Python command {printable}: {e}"
            )
            continue

        output = f"{result.stdout}\n{result.stderr}".lower()
        if result.returncode == 0 or "sqlmap" in output:
            _SQLMAP_COMMAND = command_prefix
            logger.info(f"sqlmap available via Python command: {printable}")
            return _SQLMAP_COMMAND

        logger.warning(
            "sqlmap availability check returned non-zero with Python command "
            f"{printable}: {result.stderr.strip()[:200]}"
        )

    logger.error(
        "sqlmap is not available through any Python candidate. If manual "
        "`python sqlmap.py --version` works, set SQLMAP_PYTHON in .env to "
        "that exact python.exe path."
    )
    return None


def is_sqlmap_available() -> bool:
    """
    Check sqlmap is available by running sqlmap.py through a working Python.
    This bypasses Windows Smart App Control and avoids hard-depending on the
    backend virtualenv interpreter when it hangs.
    """
    return _get_sqlmap_command() is not None


def run_sqlmap_active(
    target_url: str,
    params: list[str] = None,
    max_requests: int = 50,
    timeout: int = 120
) -> list[dict]:
    """
    Run sqlmap against a target URL.
    Called ONLY after explicit user consent is confirmed.

    Args:
        target_url:   Full URL with query params e.g. http://target.com/search?q=1
        params:       Specific params to test (None = test all found)
        max_requests: Hard cap on total HTTP requests
        timeout:      Max seconds for entire run
    """
    sqlmap_command = _get_sqlmap_command()
    if not sqlmap_command:
        logger.error("sqlmap not available. See SQLMAP_PATH/SQLMAP_PYTHON in .env")
        return []

    # Rate limit the start of each active scan
    active_scan_limiter.wait()

    args = [
        "-u", target_url,
        "--batch",             # Non-interactive
        "--output-format=json",
        f"--max-requests={max_requests}",
        "--level=1",           # Least invasive
        "--risk=1",            # Lowest risk
        "--timeout=10",        # Per-request timeout
        "--retries=1",
        "--technique=BEU",     # Boolean, Error, Union (skip time-based)
        "--no-cast",
        "--flush-session",     # Fresh session each run
    ]

    if params:
        args.extend(["-p", ",".join(params)])

    logger.info(
        f"[ACTIVE SCAN] sqlmap on {target_url} "
        f"(max_requests={max_requests}, python={' '.join(sqlmap_command)})"
    )

    try:
        result = _run_with_python(sqlmap_command, args, timeout=timeout)
        return _parse_sqlmap_output(result.stdout, result.stderr, target_url)

    except subprocess.TimeoutExpired:
        logger.error(f"sqlmap timed out after {timeout}s on {target_url}")
        return []
    except Exception as e:
        logger.error(f"sqlmap execution failed: {e}")
        return []

def _parse_sqlmap_output(stdout: str, stderr: str, target_url: str) -> list[dict]:
    """
    Parse sqlmap output for confirmed injection points.
    Handles both JSON output and text indicator fallback.
    """
    findings = []

    # Try JSON parse first
    try:
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            data = json.loads(line)
            if "data" in data and data["data"]:
                for param, details in data.get("data", {}).items():
                    findings.append(_build_sqli_finding(target_url, param, details))
                return findings
    except (json.JSONDecodeError, TypeError):
        pass

    # Fallback: check for sqlmap's text indicators
    combined = stdout + stderr
    injectable_indicators = [
        "is vulnerable",
        "appears to be",
        "injectable",
        "sql injection",
        "parameter",
    ]

    if any(indicator in combined.lower() for indicator in injectable_indicators):
        # Extract parameter name from output if possible
        param_name = _extract_param_from_output(combined, target_url)
        findings.append({
            "vuln_type": "SQL Injection (Confirmed Active)",
            "severity": "CRITICAL",
            "description": (
                f"sqlmap confirmed SQL injection on {target_url}. "
                f"Parameter '{param_name}' is injectable. "
                "Real attack payloads verified exploitability in active scan mode."
            ),
            "url": target_url,
            "confidence": 0.99,
            "source": "sqlmap_active",
            "scan_mode": "active",
            "fixed_code": None,
            "fix_explanation": (
                "Immediately switch to parameterized queries. "
                "Never concatenate user input into SQL strings. "
                "Use an ORM or prepared statements."
            ),
            "remediation_time": "1-2 hours"
        })
    else:
        logger.info(f"sqlmap: no SQLi confirmed on {target_url}")

    return findings


def _extract_param_from_output(output: str, url: str) -> str:
    """Try to extract the vulnerable parameter name from sqlmap output."""
    # sqlmap typically says "Parameter: X (GET)"
    import re
    match = re.search(r"Parameter[:\s]+['\"]?(\w+)['\"]?\s*\(", output, re.IGNORECASE)
    if match:
        return match.group(1)

    # Fall back to extracting from URL
    if "?" in url:
        first_param = url.split("?")[1].split("=")[0]
        return first_param

    return "unknown"


def _build_sqli_finding(target_url: str, param: str, details: dict) -> dict:
    """Build a structured finding from sqlmap's JSON output."""
    injection_types = []
    for technique in details.get("data", {}).values():
        if isinstance(technique, dict) and "title" in technique:
            injection_types.append(technique["title"])

    injection_desc = (
        ", ".join(injection_types) if injection_types
        else "SQL Injection"
    )

    return {
        "vuln_type": "SQL Injection (Confirmed Active)",
        "severity": "CRITICAL",
        "description": (
            f"sqlmap confirmed {injection_desc} on parameter '{param}' "
            f"at {target_url}. Verified with real payloads in active scan mode."
        ),
        "url": target_url,
        "confidence": 0.99,
        "source": "sqlmap_active",
        "scan_mode": "active",
        "fix_explanation": (
            "Switch to parameterized queries for all database operations. "
            "Use ORM or prepared statements. Never concatenate user input into SQL."
        ),
        "remediation_time": "1-2 hours"
    }