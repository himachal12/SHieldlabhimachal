"""
sqlmap Runner — ACTIVE SCAN MODULE
===========================================
⚠️  THIS MODULE ONLY RUNS WHEN THE USER HAS EXPLICITLY CONSENTED
    TO ACTIVE SCANNING. IT IS NEVER CALLED IN PASSIVE MODE.
===========================================

sqlmap sends real SQL injection payloads to a target application.
This is active exploitation testing -- use only on systems you own
or have explicit written authorization to test.

Integration approach:
- Passive mode (default): ShieldLabs detects SQL injection in SOURCE CODE
  via Bandit + AST analysis (Day 4). No live payloads sent.
- Active mode (opt-in): sqlmap confirms exploitability on a LIVE TARGET
  with real payloads. Requires explicit per-scan user consent.

This two-tier approach means:
  (1) Default behavior is always safe
  (2) Power users who own their targets can run full confirmation testing
  (3) We satisfy the original project spec without ethical compromise
"""

import subprocess
import json
import sys
import shutil
import os
from app.utils.rate_limiter import active_scan_limiter
from app.utils.logger import get_logger

logger = get_logger("sqlmap_runner")

# sqlmap is a Python tool -- prefer python -m sqlmap (avoids Windows
# Application Control blocking, same fix as Bandit on Day 4)
_SQLMAP_PATH = os.getenv("SQLMAP_PATH", "sqlmap")


def is_sqlmap_available() -> bool:
    """Check sqlmap is reachable."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "sqlmap", "--version"],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def run_sqlmap_active(
    target_url: str,
    params: list[str] = None,
    max_requests: int = 50,
    timeout: int = 120
) -> list[dict]:
    """
    Run sqlmap against a target URL in active scan mode.

    ⚠️  ONLY CALL THIS AFTER EXPLICIT USER CONSENT HAS BEEN RECORDED.
        The web scanner orchestrator enforces this -- do not call directly.

    Args:
        target_url: Full URL including query params to test
                    e.g. "http://example.com/search?q=test"
        params:     Specific parameters to test (None = test all)
        max_requests: Cap on total HTTP requests sqlmap sends (prevents abuse)
        timeout:    Max seconds for the whole run

    Returns:
        List of finding dicts for confirmed SQLi vulnerabilities
    """
    if not is_sqlmap_available():
        logger.error("sqlmap not available via 'python -m sqlmap'. Install with: pip install sqlmap")
        return []

    # Rate limit the START of each active scan
    active_scan_limiter.wait()

    cmd = [
        sys.executable, "-m", "sqlmap",
        "-u", target_url,
        "--batch",                      # non-interactive (no prompts)
        "--output-format=json",
        "--answers=all",                # auto-answer all prompts with default
        f"--max-requests={max_requests}",  # hard cap on requests sent
        "--level=1",                    # lowest test level (least invasive)
        "--risk=1",                     # lowest risk level (no dangerous tests)
        "--no-cast",                    # faster, simpler payloads
        "--timeout=10",                 # per-request timeout
        "--retries=1",
        "--technique=BEU",              # Boolean, Error, Union based only
                                        # (skip time-based -- too slow/disruptive)
    ]

    if params:
        cmd.extend(["-p", ",".join(params)])

    logger.info(f"[ACTIVE SCAN] Running sqlmap on {target_url} (max_requests={max_requests})")

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
    sqlmap's --output-format=json is not always perfectly structured,
    so we parse for key indicator strings as a fallback too.
    """
    findings = []

    # Try JSON parse first
    try:
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            data = json.loads(line)

            # sqlmap JSON output structure varies by version --
            # look for the "data" key that contains injection results
            if "data" in data and data["data"]:
                for param, details in data.get("data", {}).items():
                    findings.append(_build_sqli_finding(target_url, param, details))
                return findings
    except (json.JSONDecodeError, TypeError):
        pass

    # Fallback: parse stdout text for sqlmap's indicator strings
    # "Parameter: X (GET/POST)" followed by "Type: ..." indicates confirmed injection
    if "is vulnerable" in stdout.lower() or "sqlinjection" in stdout.lower():
        findings.append({
            "vuln_type": "SQL Injection (Confirmed Active)",
            "severity": "CRITICAL",
            "description": (
                f"sqlmap confirmed SQL injection vulnerability on {target_url}. "
                "Active testing with real payloads verified exploitability."
            ),
            "url": target_url,
            "confidence": 0.99,
            "source": "sqlmap_active",
            "scan_mode": "active",
            "fix_source": "static_guide",
            "fix_explanation": (
                "Use parameterized queries for ALL database operations. "
                "Never concatenate user input into SQL strings. "
                "Consider a WAF as an additional layer."
            ),
            "remediation_time": "1-2 hours"
        })

    if not findings:
        logger.info(f"sqlmap found no confirmed SQLi on {target_url}")

    return findings


def _build_sqli_finding(target_url: str, param: str, details: dict) -> dict:
    """Build a structured finding from sqlmap's JSON output."""
    injection_types = []
    for technique in details.get("data", {}).values():
        if isinstance(technique, dict) and "title" in technique:
            injection_types.append(technique["title"])

    injection_desc = ", ".join(injection_types) if injection_types else "SQL Injection"

    return {
        "vuln_type": "SQL Injection (Confirmed Active)",
        "severity": "CRITICAL",
        "description": (
            f"sqlmap confirmed {injection_desc} on parameter '{param}' at {target_url}. "
            f"Vulnerability verified with real payloads in active scan mode."
        ),
        "url": target_url,
        "confidence": 0.99,
        "source": "sqlmap_active",
        "scan_mode": "active",
        "fix_explanation": (
            "Immediately switch to parameterized queries for all database operations. "
            "Use an ORM or prepared statements. Never concatenate user input into SQL."
        ),
        "remediation_time": "1-2 hours"
    }