"""
Code Parser
Orchestrates: get code files -> parse each -> assemble structured code map.

NOTE: This is plain Python, not a CrewAI Agent. AST parsing is deterministic —
there's no decision-making for an LLM to do here. Real CrewAI agents start
at the Severity Reasoning stage (Day 7+), where actual judgment is involved.
"""

from app.utils.repo_handler import (
    download_github_repo, extract_zip, get_all_code_files, cleanup_temp_repo
)
from app.scanners.ast_parser import parse_python_file
from app.utils.logger import get_logger

logger = get_logger("code_parser")


class CodeParser:
    """Parses an entire codebase (from GitHub URL, ZIP, or local path) into structured JSON."""

    def parse_from_github(self, url: str, branch: str = None) -> dict:
        """Clone a GitHub repo and parse it. Cleans up the clone afterward."""
        repo_path = download_github_repo(url, branch)
        try:
            return self.parse_local_path(repo_path)
        finally:
            cleanup_temp_repo(repo_path)

    def parse_from_zip(self, zip_path: str) -> dict:
        """Extract a ZIP upload and parse it. Cleans up the extraction afterward."""
        extracted_path = extract_zip(zip_path)
        try:
            return self.parse_local_path(extracted_path)
        finally:
            cleanup_temp_repo(extracted_path)

    def parse_local_path(self, path: str) -> dict:
        """
        Parse all code files at a given local path (no download/extract step).
        Used directly for our test fixture, and internally by the above two methods.
        """
        code_files = get_all_code_files(path)

        parsed_files = []
        skipped_files = []

        for file_path in code_files:
            if file_path.endswith('.py'):
                parsed = parse_python_file(file_path)
                if "error" in parsed:
                    skipped_files.append(parsed)
                else:
                    parsed_files.append(parsed)
            else:
                # JS/Go: not parsed at AST level yet (Day 4 handles JS via regex)
                skipped_files.append({"file": file_path, "reason": "language not AST-supported yet"})

        # Roll up summary stats — useful for logging and later for the severity agent
        total_functions = sum(len(f["functions"]) for f in parsed_files)
        total_dangerous_calls = sum(len(f["dangerous_calls"]) for f in parsed_files)

        result = {
            "root_path": path,
            "total_files_found": len(code_files),
            "total_files_parsed": len(parsed_files),
            "total_functions": total_functions,
            "total_dangerous_calls": total_dangerous_calls,
            "files": parsed_files,
            "skipped": skipped_files
        }

        logger.info(
            f"Parsed {len(parsed_files)}/{len(code_files)} files, "
            f"{total_functions} functions, {total_dangerous_calls} dangerous calls flagged"
        )

        return result