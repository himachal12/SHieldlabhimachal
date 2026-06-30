"""
Code Scanner Orchestrator
Runs Bandit (for generic SAST categories) + custom detectors (for
framework-level categories) and returns one unified findings list.
"""

import os
from app.scanners.bandit_runner import run_bandit
from app.scanners.pattern_detector import ALL_DETECTORS
from app.utils.logger import get_logger

logger = get_logger("code_scanner")

EXCLUDED_DIRS = {'node_modules', '.git', 'venv', 'env', '__pycache__', 'dist', 'build'}


def scan_codebase(repo_path: str) -> list[dict]:
    """
    Run the full code scanning pipeline against a directory.

    Returns:
        List of raw finding dicts, unsorted, unfiltered.
        (False-positive filtering happens later in semantic_analyzer.py)
    """
    findings = run_bandit(repo_path)

    custom_count = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for file in files:
            if not file.endswith('.py'):
                continue  # custom detectors are Flask/Python-specific for now

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    source = f.read()
            except Exception as e:
                logger.warning(f"Could not read {file_path}: {e}")
                continue

            for detector in ALL_DETECTORS:
                new_findings = detector(file_path, source)
                findings.extend(new_findings)
                custom_count += len(new_findings)

    bandit_count = len(findings) - custom_count
    logger.info(
        f"Code scan complete: {len(findings)} total findings "
        f"({bandit_count} from Bandit, {custom_count} custom)"
    )
    return findings