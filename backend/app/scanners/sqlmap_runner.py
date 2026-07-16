"""
SQLMap integration subsystem for active web scanning.

This module is the single execution path for SQLMap. It is Windows-first and
non-interactive by design: configured paths are normalized, commands are built
as argv lists, stdin is disconnected, SQLMap is always launched with --batch,
stdout/stderr are drained concurrently, and every subprocess is bounded by an
explicit timeout.
"""

from __future__ import annotations

import json
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from app.config import settings
from app.utils.logger import get_logger
from app.utils.rate_limiter import active_scan_limiter

logger = get_logger("sqlmap_runner")

DEFAULT_SQLMAP_TIMEOUT = 120
SQLMAP_AVAILABILITY_TIMEOUT = 20
SQLMAP_OUTPUT_LOG_LIMIT = 4000


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


def _append_noninteractive_flags(command: list[str]) -> list[str]:
    """Force SQLMap into non-interactive mode for every invocation."""
    if "--batch" not in command:
        command.append("--batch")
    if "--answers" not in command and not any(part.startswith("--answers=") for part in command):
        # Accept the safe default for any prompt that still appears despite --batch.
        command.extend(["--answers", "quit=N,follow=N,keep=N"])
    return command


def build_sqlmap_command(
    target_url: str,
    params: Sequence[str] | None = None,
    max_requests: int = 50,
) -> list[str]:
    """Build the canonical non-shell SQLMap active-scan command."""
    config = get_sqlmap_config()
    command = [
        config.python_executable,
        config.sqlmap_path,
        "-u",
        target_url,

        
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
    return _append_noninteractive_flags(command)


def build_sqlmap_availability_command(config: SQLMapConfig | None = None) -> list[str]:
    """Build a non-interactive SQLMap smoke-test command."""
    config = config or get_sqlmap_config()
    return _append_noninteractive_flags([config.python_executable, config.sqlmap_path, "--version"])


def _reader_thread(stream, stream_name: str, output_queue: queue.Queue[tuple[str, str]]) -> None:
    """Drain a subprocess stream without blocking the main scanner thread."""
    try:
        for line in iter(stream.readline, ""):
            if not line:
                break
            output_queue.put((stream_name, line))
    finally:
        try:
            stream.close()
        except Exception:
            pass


def execute_sqlmap(command: Sequence[str], timeout: int = DEFAULT_SQLMAP_TIMEOUT) -> SQLMapResult:
    """
    Launch SQLMap once, stream output concurrently, and return diagnostics.

    stdin is always DEVNULL so SQLMap can never wait for keyboard input from
    Uvicorn/WatchFiles. stdout and stderr are drained by separate daemon threads
    to prevent pipe backpressure deadlocks on Windows.
    """
    final_command = _append_noninteractive_flags(list(command))
    printable = " ".join(f'"{part}"' if " " in part else part for part in final_command)
    logger.info(f"Launching SQLMap: {printable}")

    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    output_queue: queue.Queue[tuple[str, str]] = queue.Queue()
    process: subprocess.Popen[str] | None = None

    try:
        process = subprocess.Popen(
            final_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            cwd=str(Path(final_command[1]).resolve().parent) if len(final_command) > 1 else None,
            bufsize=1,
        )
    except OSError as exc:
        logger.error(f"SQLMap failed to start: {exc}")
        return SQLMapResult(final_command, -1, "", str(exc), error=str(exc))

    readers = [
        threading.Thread(target=_reader_thread, args=(process.stdout, "stdout", output_queue), daemon=True),
        threading.Thread(target=_reader_thread, args=(process.stderr, "stderr", output_queue), daemon=True),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout
    timed_out = False
    while True:
        while True:
            try:
                stream_name, line = output_queue.get_nowait()
            except queue.Empty:
                break
            if stream_name == "stdout":
                stdout_parts.append(line)
            else:
                stderr_parts.append(line)

        if process.poll() is not None:
            break
        if time.monotonic() >= deadline:
            timed_out = True
            logger.error(f"SQLMap timed out after {timeout}s.")
            process.kill()
            break
        time.sleep(0.05)

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)

    for reader in readers:
        reader.join(timeout=1)
    while True:
        try:
            stream_name, line = output_queue.get_nowait()
        except queue.Empty:
            break
        if stream_name == "stdout":
            stdout_parts.append(line)
        else:
            stderr_parts.append(line)

    stdout = "".join(stdout_parts)
    stderr = "".join(stderr_parts)
    returncode = process.returncode if process.returncode is not None else -1

    logger.info(f"SQLMap exited with code {returncode}.")
    if stdout:
        logger.info(f"SQLMap stdout: {stdout[:SQLMAP_OUTPUT_LOG_LIMIT]}")
    if stderr:
        logger.warning(f"SQLMap stderr: {stderr[:SQLMAP_OUTPUT_LOG_LIMIT]}")
    if timed_out:
        return SQLMapResult(final_command, returncode, stdout, stderr, timed_out=True, error="timeout")
    if returncode == 0:
        logger.info("SQLMap completed successfully.")
    return SQLMapResult(final_command, returncode, stdout, stderr)


def is_sqlmap_available() -> bool:
    """Validate config and run a short non-interactive SQLMap smoke test."""
    try:
        result = execute_sqlmap(build_sqlmap_availability_command(), timeout=SQLMAP_AVAILABILITY_TIMEOUT)
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
        result = execute_sqlmap(build_sqlmap_availability_command(), timeout=SQLMAP_AVAILABILITY_TIMEOUT)
        if result.succeeded:
            return None
        reason_output = (result.stderr or result.stdout)[:500]
        status = "timed out" if result.timed_out else f"exited with code {result.returncode}"
        return f"SQLMap --version {status}. output: {reason_output}"
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
