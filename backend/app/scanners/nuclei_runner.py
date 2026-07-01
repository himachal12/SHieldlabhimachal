"""
Nuclei Runner — Passive scan module (template-based vulnerability detection)
"""

import subprocess
import json
import shutil
import os
from app.utils.logger import get_logger

logger = get_logger("nuclei_runner")

_NUCLEI_PATH = (
    os.getenv("NUCLEI_PATH")
    or shutil.which("nuclei")
    or shutil.which("nuclei.exe")
    or r"C:\Users\paude\OneDrive\Desktop\nuclie\nuclei.exe"
)

NUCLEI_TAGS = ["exposure", "misconfiguration"]
NUCLEI_SEVERITIES = ["critical", "high", "medium", "low"]


def is_nuclei_available() -> bool:
    if not _NUCLEI_PATH:
        return False

    try:
        result = subprocess.run(
            [_NUCLEI_PATH, "--version"],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0

    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def run_nuclei(target: str, timeout: int = 300) -> list[dict]:
    """
    Run passive Nuclei templates against the target.
    """

    if not is_nuclei_available():
        logger.warning(
            f"Nuclei not found at '{_NUCLEI_PATH}'. Set NUCLEI_PATH in .env."
        )
        return []

    if not target.startswith(("http://", "https://")):
        target_url = f"http://{target}"
    else:
        target_url = target

    try:
        result = subprocess.run(
            [
                _NUCLEI_PATH,
                "-u", target_url,
                "-tags", ",".join(NUCLEI_TAGS),
                "-severity", ",".join(NUCLEI_SEVERITIES),
                "-j",                    # JSON output
                "-silent",               # suppress banner
                "-no-color",             # cleaner output
                "-timeout", "5",         # timeout per HTTP request
                "-rate-limit", "50",     # requests/sec
                "-no-interactsh",        # disable OOB server connection
                "-duc",                  # disable update check
            ],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if not result.stdout.strip():
            logger.info(f"Nuclei: no findings for {target_url}")

            if result.stderr.strip():
                logger.debug(f"Nuclei stderr: {result.stderr[:300]}")

            return []

        return _parse_nuclei_output(result.stdout)

    except subprocess.TimeoutExpired:
        logger.error(
            f"Nuclei timed out after {timeout}s on {target_url}. "
            "Consider reducing NUCLEI_TAGS or increasing timeout in nuclei_runner.py"
        )
        return []

    except (OSError, FileNotFoundError) as e:
        logger.error(f"Nuclei execution failed: {e}")
        return []


def _parse_nuclei_output(stdout: str) -> list[dict]:
    findings = []

    for line in stdout.strip().split("\n"):
        line = line.strip()

        if not line:
            continue

        try:
            item = json.loads(line)

        except json.JSONDecodeError:
            continue

        severity_raw = item.get("info", {}).get("severity", "low").upper()

        severity = (
            severity_raw
            if severity_raw in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            else "LOW"
        )

        template_id = item.get("template-id", "unknown")
        matched_url = item.get("matched-at", item.get("host", ""))

        description = (
            item.get("info", {}).get("description")
            or item.get("info", {}).get("name", template_id)
        )

        findings.append(
            {
                "vuln_type": _map_template_to_vuln_type(template_id, item),
                "severity": severity,
                "description": description,
                "url": matched_url,
                "confidence": 0.85,
                "source": "nuclei",
                "nuclei_template_id": template_id,
            }
        )

    logger.info(f"Nuclei: {len(findings)} findings")

    return findings


def _map_template_to_vuln_type(template_id: str, item: dict) -> str:
    tid = template_id.lower()

    if any(x in tid for x in ["git", "env", "backup", "config", "credential", "exposure"]):
        return "Exposed Sensitive Files"

    if any(x in tid for x in ["default-login", "default-credential"]):
        return "Default Credentials"

    if any(x in tid for x in ["misconfiguration", "debug", "admin"]):
        return "Insecure Configuration"

    if "tech" in tid:
        return "Technology Detection"

    tags = item.get("info", {}).get("tags", [])

    if "exposure" in tags:
        return "Exposed Sensitive Files"

    return f"Web Vulnerability ({template_id})"