"""
Bandit Runner
Wraps the Bandit CLI tool, runs it against a codebase, and maps its
test IDs into our own vuln_type vocabulary so downstream code doesn't
need to know Bandit's internal naming scheme.
"""

import subprocess
import sys
import json
from app.utils.logger import get_logger

logger = get_logger("bandit_runner")

# Map Bandit's internal test IDs to our vuln_type categories.
# Reference: https://bandit.readthedocs.io/en/latest/plugins/index.html
BANDIT_TO_VULN_TYPE = {
    "B105": "Hardcoded Secrets",
    "B106": "Hardcoded Secrets",
    "B107": "Hardcoded Secrets",

    "B303": "Weak Cryptography",
    "B324": "Weak Cryptography",
    "B304": "Weak Cryptography",
    "B305": "Weak Cryptography",

    "B608": "SQL Injection",
    "B610": "SQL Injection",
    "B611": "SQL Injection",

    "B602": "Command Injection",
    "B603": "Command Injection",
    "B604": "Command Injection",
    "B605": "Command Injection",
    "B606": "Command Injection",
    "B607": "Command Injection",
    "B102": "Command Injection",
    "B307": "Command Injection",

    "B301": "Insecure Deserialization",
    "B302": "Insecure Deserialization",
    "B506": "Insecure Deserialization",

    "B701": "XSS Vulnerabilities",

    "B201": "Insecure Configuration",
}

# Bandit's confidence labels -> our confidence score
CONFIDENCE_MAP = {
    "HIGH": 0.9,
    "MEDIUM": 0.6,
    "LOW": 0.35,
}


def run_bandit(repo_path: str, timeout: int = 120) -> list[dict]:
    """
    Run Bandit against a directory and return findings in our internal format.

    Args:
        repo_path: Path to the codebase to scan
        timeout: Max seconds before giving up

    Returns:
        List of finding dictionaries
    """

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-r",
                repo_path,
                "-f",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        # Bandit returns a non-zero exit code when it FINDS issues.
        # That's expected, so don't check result.returncode.

        if not result.stdout:
            logger.warning(
                f"Bandit produced no stdout. stderr: {result.stderr[:300]}"
            )
            return []

        data = json.loads(result.stdout)

    except subprocess.TimeoutExpired:
        logger.error(f"Bandit scan timed out after {timeout}s on {repo_path}")
        return []

    except json.JSONDecodeError:
        logger.error(
            f"Bandit output was not valid JSON: {result.stdout[:300]}"
        )
        return []

    except (FileNotFoundError, OSError) as e:
        logger.error(f"Failed to run Bandit via subprocess: {e}")
        return []

    findings = []

    for issue in data.get("results", []):

        test_id = issue.get("test_id")

        vuln_type = BANDIT_TO_VULN_TYPE.get(
            test_id,
            f"Other ({issue.get('test_name', test_id)})"
        )

        severity = issue.get("issue_severity", "MEDIUM").upper()
        confidence_label = issue.get("issue_confidence", "MEDIUM").upper()

        findings.append(
            {
                "vuln_type": vuln_type,
                "severity": severity,
                "file_path": issue.get("filename"),
                "line_number": issue.get("line_number"),
                "description": issue.get("issue_text"),
                "vulnerable_code": (issue.get("code") or "").strip(),
                "confidence": CONFIDENCE_MAP.get(confidence_label, 0.5),
                "source": "bandit",
                "bandit_test_id": test_id,
            }
        )

    logger.info(f"Bandit found {len(findings)} raw issues in {repo_path}")

    return findings