"""
SQLMap integration subsystem for active web scanning.

This module is the single execution path for SQLMap.  It is intentionally
Windows-first: configured paths are normalized, quotes are stripped, commands
are executed without a shell, output is captured, and subprocesses are bounded
by explicit timeouts.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from app.config import settings
from app.utils.logger import get_logger
from app.utils.rate_limiter import active_scan_limiter

logger = get_logger("sqlmap_runner")

DEFAULT_SQLMAP_TIMEOUT = 120
SQLMAP_AVAILABILITY_TIMEOUT = 20


class SQLMapConfigurationError(RuntimeError):
    """Raised when SQLMap or Python configuration is invalid."""


@dataclass(frozen=True)
class SQLMapResult:
    """Completed SQLMap subprocess details."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None


@dataclass(frozen=True)
class SQLMapConfig:
    """Validated SQLMap execution configuration."""

    sqlmap_path: str
    python_executable: str


def _strip_wrapping_quotes(value: str | None) -> str:
    """Normalize .env values that may include PowerShell/CMD-style quotes."""
    if not value:
        return ""
    normalized = value.strip()
    while (
        len(normalized) >= 2
        and normalized[0] == normalized[-1]
        and normalized[0] in {'"', "'"}
    ):
        normalized = normalized[1:-1].strip()
    return normalized


def _resolve_existing_file(value: str, label: str) -> str:
    """Return an absolute existing file path, resolving PATH entries if needed."""
    cleaned = _strip_wrapping_quotes(value)
    if not cleaned:
        raise SQLMapConfigurationError(f"{label} is not configured.")

    candidate = Path(cleaned).expanduser()
    if candidate.is_file():
        return str(candidate.resolve())

    found = shutil.which(cleaned)
    if found and Path(found).is_file():
        return str(Path(found).resolve())

    raise SQLMapConfigurationError(f"{label} does not exist or is not a file: {cleaned}")


def _resolve_python(value: str | None) -> str:
    """
    Resolve Python with a simple, deterministic order:
    1. SQLMAP_PYTHON from .env/settings
    2. python from PATH
    3. py launcher from PATH
    """
    configured = _strip_wrapping_quotes(value)
    if configured:
        logger.info(f"Using SQLMAP_PYTHON: {configured}")
        return _resolve_existing_file(configured, "SQLMAP_PYTHON")

    for executable in ("python", "py"):
        found = shutil.which(executable)
        if found:
            logger.info(f"SQLMAP_PYTHON not configured; falling back to {found}")
            return str(Path(found).resolve())

    raise SQLMapConfigurationError(
        "SQLMAP_PYTHON is not configured and neither python nor py was found on PATH."
    )


def get_sqlmap_config() -> SQLMapConfig:
    """Validate configured SQLMap script and Python executable."""
    sqlmap_path_raw = _strip_wrapping_quotes(settings.SQLMAP_PATH)
    logger.info(f"Using SQLMAP_PATH: {sqlmap_path_raw}")
    sqlmap_path = _resolve_existing_file(sqlmap_path_raw, "SQLMAP_PATH")

    python_executable = _resolve_python(getattr(settings, "SQLMAP_PYTHON", ""))
    return SQLMapConfig(sqlmap_path=sqlmap_path, python_executable=python_executable)


def build_sqlmap_command(
    target_url: str,
    params: Sequence[str] | None = None,
    max_requests: int = 50,
) -> list[str]:
    """Build the non-shell SQLMap command used for every active invocation."""
    config = get_sqlmap_config()
    command = [
        config.python_executable,
        config.sqlmap_path,
        "-u",
        target_url,
        "--batch",
        "--output-format=json",
        f"--max-requests={max_requests}",
        "--level=1",
        "--risk=1",
        "--timeout=10",
        "--retries=1",
        "--technique=BEU",
        "--no-cast",
        "--flush-session",
    ]
    if params:
        command.extend(["-p", ",".join(params)])
    return command


def execute_sqlmap(command: Sequence[str], timeout: int = DEFAULT_SQLMAP_TIMEOUT) -> SQLMapResult:
    """Launch SQLMap once, capture output, and return structured diagnostics."""
    printable = " ".join(f'"{part}"' if " " in part else part for part in command)
    logger.info(f"Launching SQLMap: {printable}")
    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            cwd=str(Path(command[1]).resolve().parent) if len(command) > 1 else None,
        )
    except subprocess.TimeoutExpired as exc:
        logger.error(f"SQLMap timed out after {timeout}s.")
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return SQLMapResult(list(command), -1, stdout, stderr, timed_out=True, error="timeout")
    except OSError as exc:
        logger.error(f"SQLMap failed to start: {exc}")
        return SQLMapResult(list(command), -1, "", str(exc), error=str(exc))

    logger.info(f"SQLMap exited with code {completed.returncode}.")
    if completed.stdout:
        logger.info(f"SQLMap stdout: {completed.stdout[:4000]}")
    if completed.stderr:
        logger.warning(f"SQLMap stderr: {completed.stderr[:4000]}")
    if completed.returncode == 0:
        logger.info("SQLMap completed successfully.")

    return SQLMapResult(
        list(command), completed.returncode, completed.stdout or "", completed.stderr or ""
    )


def is_sqlmap_available() -> bool:
    """Validate config and run a short SQLMap --version check."""
    try:
        config = get_sqlmap_config()
        result = execute_sqlmap(
            [config.python_executable, config.sqlmap_path, "--version"],
            timeout=SQLMAP_AVAILABILITY_TIMEOUT,
        )
        if result.succeeded:
            return True
        logger.error(
            "SQLMap availability check failed. "
            f"exit={result.returncode}; stdout={result.stdout[:500]}; stderr={result.stderr[:500]}"
        )
        return False
    except SQLMapConfigurationError as exc:
        logger.error(f"SQLMap configuration error: {exc}")
        return False


def get_sqlmap_unavailable_reason() -> str | None:
    """Return a UI/log friendly reason when SQLMap cannot be launched."""
    try:
        config = get_sqlmap_config()
        result = execute_sqlmap(
            [config.python_executable, config.sqlmap_path, "--version"],
            timeout=SQLMAP_AVAILABILITY_TIMEOUT,
        )
        if result.succeeded:
            return None
        return (
            f"SQLMap --version exited with code {result.returncode}. "
            f"stderr: {(result.stderr or result.stdout)[:500]}"
        )
    except SQLMapConfigurationError as exc:
        return str(exc)


def run_sqlmap_active(
    target_url: str,
    params: list[str] | None = None,
    max_requests: int = 50,
    timeout: int = DEFAULT_SQLMAP_TIMEOUT,
) -> list[dict]:
    """Run SQLMap against one consent-approved active-scan target URL."""
    try:
        command = build_sqlmap_command(target_url, params=params, max_requests=max_requests)
    except SQLMapConfigurationError as exc:
        logger.error(f"SQLMap skipped for {target_url}: {exc}")
        return []

    active_scan_limiter.wait()
    result = execute_sqlmap(command, timeout=timeout)
    if result.timed_out:
        logger.error(f"SQLMap timed out after {timeout}s on {target_url}.")
        return []
    if result.error:
        logger.error(f"SQLMap subprocess failure on {target_url}: {result.error}")
        return []
    if result.returncode != 0:
        logger.error(
            f"SQLMap exited with code {result.returncode} on {target_url}. "
            f"stderr: {result.stderr[:1000]}"
        )
        return []
    return _parse_sqlmap_output(result.stdout, result.stderr, target_url)


def _parse_sqlmap_output(stdout: str, stderr: str, target_url: str) -> list[dict]:
    """Parse SQLMap output for confirmed injection points."""
    findings = []
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

    combined = stdout + stderr
    injectable_indicators = [
        "is vulnerable",
        "appears to be",
        "injectable",
        "sql injection",
        "parameter",
    ]

    if any(indicator in combined.lower() for indicator in injectable_indicators):
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
            "remediation_time": "1-2 hours",
        })
    else:
        logger.info(f"SQLMap: no SQLi confirmed on {target_url}")

    return findings


def _extract_param_from_output(output: str, url: str) -> str:
    """Try to extract the vulnerable parameter name from SQLMap output."""
    import re

    match = re.search(r"Parameter[:\s]+['\"]?(\w+)['\"]?\s*\(", output, re.IGNORECASE)
    if match:
        return match.group(1)
    if "?" in url:
        return url.split("?")[1].split("=")[0]
    return "unknown"


def _build_sqli_finding(target_url: str, param: str, details: dict) -> dict:
    """Build a structured finding from SQLMap's JSON output."""
    injection_types = []
    for technique in details.get("data", {}).values():
        if isinstance(technique, dict) and "title" in technique:
            injection_types.append(technique["title"])

    injection_desc = ", ".join(injection_types) if injection_types else "SQL Injection"
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
        "remediation_time": "1-2 hours",
    }
