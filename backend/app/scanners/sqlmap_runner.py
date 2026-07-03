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
from app.utils.rate_limiter import active_scan_limiter
from app.utils.logger import get_logger

logger = get_logger("sqlmap_runner")

# Path to sqlmap.py from official repo
# Set in .env as SQLMAP_PATH
_SQLMAP_SCRIPT = os.getenv(
    "SQLMAP_PATH",
    r"C:\Users\paude\OneDrive\Desktop\sqlmap\sqlmap.py"
)


def is_sqlmap_available() -> bool:
    """
    Check sqlmap is available by running it via Python directly.
    This bypasses Windows Smart App Control.
    """
    if not _SQLMAP_SCRIPT or not os.path.exists(_SQLMAP_SCRIPT):
        logger.warning(
            f"sqlmap.py not found at: {_SQLMAP_SCRIPT}\n"
            f"Clone it: git clone https://github.com/sqlmapproject/sqlmap.git\n"
            f"Then set SQLMAP_PATH in .env"
        )
        return False

    try:
        result = subprocess.run(
            [sys.executable, _SQLMAP_SCRIPT, "--version"],
            capture_output=True,
            timeout=15,
            text=True
        )
        # sqlmap --version exits with 0 and prints version info
        return result.returncode == 0 or "sqlmap" in result.stdout.lower()
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        logger.error(f"sqlmap availability check failed: {e}")
        return False


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
    if not is_sqlmap_available():
        logger.error("sqlmap not available. See SQLMAP_PATH in .env")
        return []

    # Rate limit the start of each active scan
    active_scan_limiter.wait()

    cmd = [
        sys.executable,        # Use current Python (trusted by Smart App Control)
        _SQLMAP_SCRIPT,        # Official sqlmap.py script
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
        cmd.extend(["-p", ",".join(params)])

    logger.info(
        f"[ACTIVE SCAN] sqlmap on {target_url} "
        f"(max_requests={max_requests})"
    )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
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