"""
Auto-PR Agent
=============
Takes completed scan findings that have AI-generated fixes,
applies them to the actual GitHub repository, and opens a
Pull Request so the developer just has to click "Merge."

Key design decisions:
1. EXACT text matching only — no fuzzy matching. If the
   vulnerable code isn't found exactly, we skip that fix
   and report it honestly. Wrong fix in wrong place is
   worse than no fix.

2. Only touches CODE findings — web findings (missing headers,
   open ports) have no code to change in a repo.

3. Groups fixes by file — if 3 vulns are in app.py, we
   open app.py once, apply all 3 fixes, save once. Not 3
   separate file operations.

4. Fresh clone — we re-download the repo to ensure we're
   working on current code, not whatever was scanned earlier.

5. Token is caller-provided — never stored in our DB.
   It's the developer's token for their repo.
"""

import ast
import os
import re
import subprocess
import sys
import uuid
import shutil
import tempfile
import json
from pathlib import Path
from github import Github, GithubException
from app.utils.logger import get_logger
from app.patches import source_sha256
from app.scanners.pattern_detector import detect_hardcoded_secrets, detect_unvalidated_redirects

logger = get_logger("auto_pr")


def _remediation_status(applied_count: int, skipped_count: int) -> str:
    """Describe whether a requested remediation was complete or partial."""
    if applied_count == 0:
        return "not_created"
    return "complete" if skipped_count == 0 else "partial"


def _calls_in_tree(tree: ast.AST, name: str) -> list[ast.Call]:
    """Return calls whose final function/attribute name matches ``name``."""
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == name:
                calls.append(node)
            elif isinstance(node.func, ast.Attribute) and node.func.attr == name:
                calls.append(node)
    return calls


def _validate_vulnerability_fix(
    vuln_type: str, candidate: str, target_code: str | None = None
) -> tuple[bool, dict]:
    """Apply conservative, deterministic security checks for generated fixes.

    Syntax validity alone cannot establish that an AI patch fixes the security
    issue. These guards cover the patch categories for which an unsafe pattern
    is unambiguous. A patch which cannot satisfy a guard is kept out of the PR
    and left for manual review.
    """
    # Category checks apply to the generated replacement only. Checking the
    # entire candidate file rejects a correct finding when a different finding
    # of the same category remains elsewhere in that file.
    scope = target_code if target_code is not None else candidate
    checks = {}
    try:
        tree = ast.parse(scope)
    except SyntaxError:
        # The caller records the more useful syntax error separately.
        return True, {"status": "not_run", "checks": checks, "reason": "Security checks deferred to syntax validation."}

    source_lower = scope.lower()
    if vuln_type == "Hardcoded Secrets":
        assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
        if any(
            isinstance(value := assignment.value, ast.Constant)
            and isinstance(value.value, str)
            and value.value
            for assignment in assignments
        ):
            checks["secret_literal_removed"] = "failed"
            return False, {
                "status": "rejected_security_regression",
                "checks": checks,
                "reason": "Secret patch still contains a string literal assignment.",
            }
        if "os.environ" not in scope:
            checks["secret_environment_lookup"] = "failed"
            return False, {
                "status": "rejected_security_regression",
                "checks": checks,
                "reason": "Secret patch does not read the value from the process environment.",
            }
        checks["secret_literal_removed"] = "passed"
        checks["secret_environment_lookup"] = "passed"

    elif vuln_type == "SQL Injection":
        query_execute_calls = [
            call for call in _calls_in_tree(tree, "execute")
            if call.args and isinstance(call.args[0], ast.Name) and call.args[0].id == "query"
        ]
        # A parameterized query must pass the parameter tuple/list to execute.
        if any(len(call.args) < 2 for call in query_execute_calls):
            checks["parameterized_query"] = "failed"
            return False, {
                "status": "rejected_security_regression",
                "checks": checks,
                "reason": "SQL patch executes a query without bound parameters.",
            }
        checks["parameterized_query"] = "passed"

    elif vuln_type == "Weak JWT Implementation":
        if re.search(r"verify_signature\s*[\"']?\s*:\s*false|verify\s*=\s*false", source_lower):
            checks["jwt_signature_verification"] = "failed"
            return False, {
                "status": "rejected_security_regression",
                "checks": checks,
                "reason": "JWT patch still disables signature verification.",
            }
        decode_calls = _calls_in_tree(tree, "decode")
        jwt_decodes = [call for call in decode_calls if isinstance(call.func, ast.Attribute) and call.func.attr == "decode"]
        if jwt_decodes and not any(any(keyword.arg == "algorithms" for keyword in call.keywords) for call in jwt_decodes):
            checks["jwt_allowed_algorithms"] = "failed"
            return False, {
                "status": "rejected_security_regression",
                "checks": checks,
                "reason": "JWT patch does not explicitly restrict allowed algorithms.",
            }
        checks["jwt_signature_verification"] = "passed"
        checks["jwt_allowed_algorithms"] = "passed"

    elif vuln_type == "Unvalidated Redirects":
        unsafe_redirect = re.search(r"redirect\(\s*request\.(args|form|values)\.get\(", scope)
        if unsafe_redirect:
            checks["redirect_validation"] = "failed"
            return False, {
                "status": "rejected_security_regression",
                "checks": checks,
                "reason": "Redirect patch still passes request input directly to redirect().",
            }
        checks["redirect_validation"] = "passed"

    elif vuln_type == "Command Injection":
        run_calls = _calls_in_tree(tree, "run")
        for call in run_calls:
            if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in call.keywords):
                checks["shell_disabled"] = "failed"
                return False, {
                    "status": "rejected_security_regression",
                    "checks": checks,
                    "reason": "Command patch still enables shell=True.",
                }
        if ".stdout" in scope and run_calls and not any(
            any(keyword.arg in {"capture_output", "stdout"} for keyword in call.keywords)
            for call in run_calls
        ):
            checks["subprocess_output"] = "failed"
            return False, {
                "status": "rejected_runtime_risk",
                "checks": checks,
                "reason": "Command patch reads subprocess stdout without capturing it.",
            }
        checks["shell_disabled"] = "passed"
        checks["subprocess_output"] = "passed"

    elif vuln_type == "Insecure Deserialization":
        if re.search(r"\bpickle\.(loads|load)\s*\(", scope):
            checks["unsafe_deserialization"] = "failed"
            return False, {
                "status": "rejected_security_regression",
                "checks": checks,
                "reason": "Patch still deserializes untrusted input with pickle.",
            }
        checks["unsafe_deserialization"] = "passed"

    elif vuln_type == "Weak Cryptography":
        if re.search(r"hashlib\.(md5|sha1)\s*\(", source_lower):
            checks["weak_hash_removed"] = "failed"
            return False, {
                "status": "rejected_security_regression",
                "checks": checks,
                "reason": "Patch still uses MD5 or SHA-1.",
            }
        checks["weak_hash_removed"] = "passed"

    return True, {"status": "security_checks_passed", "checks": checks, "reason": "Category-specific security checks passed."}


def _validate_full_file_regression(finding: dict, candidate: str) -> tuple[bool, dict]:
    """Verify the entire patched module no longer reproduces the finding.

    This is deliberately separate from the local patch checks: a valid snippet
    is not sufficient when a duplicate secret or unsafe statement remains.
    """
    vuln_type = finding.get("vuln_type", "")
    original = (finding.get("vulnerable_code") or "").strip()
    checks = {"original_pattern_removed": "passed"}
    if original and original in candidate:
        checks["original_pattern_removed"] = "failed"
        return False, {"status": "rejected_security_regression", "checks": checks,
                       "reason": "The original vulnerable source remains in the patched file."}
    path = finding.get("repository_relative_path") or finding.get("file_path") or "candidate.py"
    if vuln_type == "Hardcoded Secrets":
        findings = detect_hardcoded_secrets(path, candidate)
        target = re.match(r"\s*([A-Z][A-Z0-9_]*)\s*=", original)
        name = target.group(1) if target else None
        assignments = re.findall(r"(?m)^\s*" + re.escape(name or "") + r"\s*=", candidate) if name else []
        if name and len(assignments) != 1:
            checks["single_secret_assignment"] = "failed"
            return False, {"status": "rejected_security_regression", "checks": checks,
                           "reason": f"Expected exactly one assignment for {name}; found {len(assignments)}."}
        if findings:
            checks["detector_rescan"] = "failed"
            return False, {"status": "rejected_security_regression", "checks": checks,
                           "reason": "Hardcoded-secret detector still reports a secret in the patched file."}
        checks.update({"single_secret_assignment": "passed", "detector_rescan": "passed"})
    elif vuln_type == "Unvalidated Redirects":
        if detect_unvalidated_redirects(path, candidate):
            checks["detector_rescan"] = "failed"
            return False, {"status": "rejected_security_regression", "checks": checks,
                           "reason": "Redirect detector still reports an unsafe direct redirect."}
        checks["detector_rescan"] = "passed"
    return True, {"status": "security_regression_tested", "checks": checks,
                  "reason": "Full-file regression checks passed."}


def _security_scope(candidate: str, fixed_code: str) -> str:
    """Return the enclosing function for a uniquely inserted replacement.

    SQL validation needs to inspect both query construction and its nearby
    execution call. Restricting that inspection to the enclosing function
    avoids treating independent findings in other functions as regressions.
    """
    try:
        tree = ast.parse(candidate)
    except SyntaxError:
        return fixed_code
    start = candidate.find(fixed_code)
    if start < 0:
        # Replacements are re-indented to their containing block. Locate the
        # first non-empty generated line when the stored LLM output had no
        # indentation of its own.
        first_line = next((line.strip() for line in fixed_code.splitlines() if line.strip()), "")
        if first_line:
            matches = [match.start() for match in re.finditer(re.escape(first_line), candidate)]
            start = matches[0] if len(matches) == 1 else -1
    if start < 0 or candidate.find(fixed_code, start + len(fixed_code)) >= 0:
        return fixed_code
    line = candidate[:start].count("\n") + 1
    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    containing = [node for node in functions if node.lineno <= line <= node.end_lineno]
    if not containing:
        return fixed_code
    return ast.get_source_segment(candidate, min(containing, key=lambda node: node.end_lineno - node.lineno)) or fixed_code


# ────────────────────────────────────────────────
# ELIGIBILITY FILTER
# ────────────────────────────────────────────────
def _get_base_indent(code: str) -> str:
    """
    Detect the base indentation of the first non-empty line of a code snippet.
    Returns the whitespace string (e.g. '    ' for 4 spaces).
    """
    for line in code.split("\n"):
        if line.strip():
            return line[: len(line) - len(line.lstrip())]
    return ""


def _apply_indent(fixed_code: str, base_indent: str) -> str:
    """
    Apply base_indent to every non-empty line of fixed_code.
    Strips existing leading whitespace first, then re-indents.
    This fixes Problem 2: LLM-generated fixes often have wrong or missing indent.
    """
    lines = fixed_code.split("\n")
    result = []
    for line in lines:
        if line.strip():
            result.append(base_indent + line.lstrip())
        else:
            result.append("")
    return "\n".join(result)


def _is_structural_rewrite(vulnerable_code: str, fixed_code: str) -> bool:
    """
    Detect if the LLM generated a structural rewrite instead of a drop-in fix.
    A drop-in fix should have roughly the same number of lines (±2 lines max).
    A structural rewrite (adding a whole new function def) is NOT safe to apply.

    This fixes Problem 3: LLM replacing one line with a whole function definition.
    """
    vuln_lines = [l for l in vulnerable_code.split("\n") if l.strip()]
    fix_lines = [l for l in fixed_code.split("\n") if l.strip()]

    # If fix is WAY longer than the original, it's probably a structural rewrite
    if len(fix_lines) > len(vuln_lines) + 5:
        return True

    # If fix contains a function definition and original doesn't, it's a rewrite
    fix_has_def = any(l.strip().startswith("def ") for l in fix_lines)
    vuln_has_def = any(l.strip().startswith("def ") for l in vuln_lines)
    if fix_has_def and not vuln_has_def:
        return True

    return False


def _import_roots(source: str) -> set[str]:
    """Return the top-level modules imported by valid Python source."""
    roots = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def _validate_python_patch(file_path: str, original: str, candidate: str) -> tuple[bool, dict]:
    """
    Validate a candidate Python file before it is pushed.

    New third-party imports are deliberately rejected. They need a dependency
    manifest update and project-specific validation, which is not safe for a
    one-click patch.
    """
    checks = {}
    try:
        ast.parse(candidate, filename=file_path)
        checks["ast_parse"] = "passed"
    except SyntaxError as exc:
        checks["ast_parse"] = "failed"
        return False, {
            "status": "rejected_syntax_error",
            "checks": checks,
            "reason": f"Syntax validation failed: {exc.msg} (line {exc.lineno}).",
        }

    original_imports = _import_roots(original)
    candidate_imports = _import_roots(candidate)
    new_imports = candidate_imports - original_imports
    stdlib_modules = getattr(sys, "stdlib_module_names", set())
    third_party_imports = sorted(
        module for module in new_imports
        if module not in stdlib_modules and module != "__future__"
    )
    if third_party_imports:
        checks["dependency_policy"] = "failed"
        return False, {
            "status": "rejected_dependency",
            "checks": checks,
            "reason": (
                "Generated fix introduces unapproved third-party import(s): "
                f"{', '.join(third_party_imports)}. Manual review required."
            ),
        }
    checks["dependency_policy"] = "passed"

    try:
        with open(file_path, "w", encoding="utf-8") as handle:
            handle.write(candidate)
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", file_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        checks["py_compile"] = "failed"
        return False, {
            "status": "rejected_validation_error",
            "checks": checks,
            "reason": f"Could not compile generated patch: {exc}",
        }

    if result.returncode != 0:
        checks["py_compile"] = "failed"
        output = (result.stderr or result.stdout).strip().replace("\n", " ")
        return False, {
            "status": "rejected_syntax_error",
            "checks": checks,
            "reason": f"Python compilation failed: {output[:500]}",
        }

    checks["py_compile"] = "passed"
    return True, {
        "status": "validated",
        "checks": checks,
        "reason": "AST parsing and Python compilation passed.",
    }


def _run_project_tests(
    repo_dir: str, allow_untested: bool = False
) -> tuple[bool, dict]:
    """Run an existing Python test suite in the fresh checkout when present.

    We never invent or install dependencies in a customer's repository. A
    patch that cannot be tested is not safe for one-click application, and an
    existing suite that fails likewise blocks the candidate from being pushed.
    """
    has_tests = any(
        name.startswith("test_") and name.endswith(".py")
        for _, _, files in os.walk(repo_dir)
        for name in files
    )
    if not has_tests:
        if allow_untested:
            return True, {
                "status": "tests_not_available",
                "checks": {"project_tests": "not_available"},
                "reason": (
                    "No Python test suite found. User explicitly requested a "
                    "manual-review PR after syntax and security validation."
                ),
            }
        return False, {
            "status": "rejected_test_validation_unavailable",
            "checks": {"project_tests": "not_available"},
            "reason": "No Python test suite found; Auto PR will not push an untested security patch.",
        }

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, {
            "status": "rejected_test_validation_error",
            "checks": {"project_tests": "failed"},
            "reason": f"Could not run repository tests: {exc}",
        }

    if result.returncode != 0:
        output = (result.stdout + "\n" + result.stderr).strip().replace("\n", " ")
        return False, {
            "status": "rejected_test_failure",
            "checks": {"project_tests": "failed"},
            "reason": f"Repository tests failed: {output[:500]}",
        }
    return True, {
        "status": "tests_passed",
        "checks": {"project_tests": "passed"},
        "reason": "Repository test suite passed.",
    }


def _replace_with_context(
    content: str, vulnerable_code: str, fixed_code: str
) -> tuple[str | None, str | None]:
    """Build an indentation-preserving, exact-match replacement candidate.

    Auto-PR must never guess at a source location.  The vulnerable snippet must
    occur exactly once, and a multi-line replacement must replace a complete
    source statement (rather than, for example, just ``redirect(...)`` after a
    ``return`` keyword).  The replacement is re-indented to match its source
    line so multi-line LLM responses remain valid inside functions and blocks.
    """
    if not vulnerable_code.strip():
        return None, "Vulnerable code snippet is empty."

    occurrences = content.count(vulnerable_code)
    if occurrences == 0:
        return None, "Vulnerable code pattern not found in current file. File may have changed since scan."
    if occurrences > 1:
        return None, "Vulnerable code pattern appears multiple times; refusing ambiguous replacement."

    match_start = content.index(vulnerable_code)
    match_end = match_start + len(vulnerable_code)
    line_start = content.rfind("\n", 0, match_start) + 1
    line_end = content.find("\n", match_end)
    if line_end == -1:
        line_end = len(content)

    prefix = content[line_start:match_start]
    suffix = content[match_end:line_end]
    replacement_lines = [line for line in fixed_code.splitlines() if line.strip()]

    # A multi-line replacement can safely replace only an entire statement.
    # Whitespace before a snippet is simply its block indentation; any other
    # prefix/suffix means the scanner captured a partial expression.
    if len(replacement_lines) > 1 and (prefix.strip() or suffix.strip()):
        return None, (
            "Generated multi-line fix targets only part of a source statement. "
            "Manual review required."
        )

    indentation = re.match(r"[ \t]*", content[line_start:]).group(0)
    replacement = _apply_indent(fixed_code.strip(), indentation)

    # When the stored snippet omits indentation, replace from the physical line
    # start to avoid retaining the original indentation *and* adding it again.
    replace_start = line_start if not prefix.strip() else match_start
    return content[:replace_start] + replacement + content[match_end:], None


def get_eligible_findings(findings: list[dict]) -> list[dict]:
    """
    Filter findings that qualify for auto-fix.

    A finding qualifies only if it has ALL of:
    - file_path (we know which file to edit)
    - line_number (we know roughly where)
    - vulnerable_code (exact text to find and replace)
    - fixed_code (what to replace it with)
    - NOT a web-sourced finding (nmap, nuclei, etc.)

    Returns the filtered list with a reason for each exclusion logged.
    """
    WEB_SOURCES = {
        "nmap", "ssl_analyzer", "headers_checker",
        "nuclei", "exposed_files_checker", "sqlmap_active"
    }

    eligible = []
    skipped = []

    for f in findings:
        reason = None

        if f.get("source") in WEB_SOURCES:
            reason = "web finding — no code to patch"
        elif not (f.get("repository_relative_path") or f.get("file_path")):
            reason = "no file_path"
        elif not f.get("vulnerable_code"):
            reason = "no vulnerable_code snippet stored"
        elif not f.get("fixed_code"):
            reason = "no fixed_code generated (architectural finding)"
        elif f.get("is_false_positive"):
            reason = "marked as false positive"
        elif f.get("remediation_status") not in {None, "suggested", "validated_locally"}:
            reason = f"remediation status is {f.get('remediation_status')}"

        if reason:
            skipped.append({
                "vuln_type": f.get("vuln_type"),
                "reason": reason
            })
        else:
            eligible.append(f)

    logger.info(
        f"Auto-PR eligibility: {len(eligible)} eligible, "
        f"{len(skipped)} skipped"
    )
    for s in skipped:
        logger.debug(f"  Skipped [{s['vuln_type']}]: {s['reason']}")

    return eligible


# ────────────────────────────────────────────────
# CORE ENGINE
# ────────────────────────────────────────────────

def create_fix_pr(
    github_token: str,
    repo_url: str,
    scan_id: str,
    findings: list[dict],
    allow_untested: bool = False,
) -> dict:
    """Validate every candidate locally, then create one branch and PR.

    A remote branch is never created until at least one candidate has passed
    patch-level checks, final file compilation, and the selected test policy.
    ``allow_untested`` is an explicit manual-review escape hatch: it permits a
    PR only after syntax and security checks pass, and reports that native tests
    were unavailable.
    """
    if not github_token or not github_token.strip():
        return _error_result("GitHub token is required")
    if not repo_url:
        return _error_result("Repository URL is required")

    owner, repo_name = _parse_repo_url(repo_url)
    if not owner or not repo_name:
        return _error_result(
            f"Could not parse owner/repo from URL: {repo_url}. "
            "Expected format: https://github.com/owner/repo"
        )

    eligible = get_eligible_findings(findings)
    if not eligible:
        return _error_result(
            "No findings are eligible for auto-fix. Findings need: file_path, "
            "vulnerable_code, and fixed_code. Web findings cannot be auto-fixed."
        )

    try:
        repo = Github(github_token).get_repo(f"{owner}/{repo_name}")
        default_branch = repo.default_branch
        source_sha = repo.get_branch(default_branch).commit.sha
    except GithubException as e:
        return _error_result(f"GitHub connection failed: {str(e)}")

    temp_dir = tempfile.mkdtemp(prefix="shieldlabs_pr_")
    skipped_fixes, validation_details, staged_files = [], [], {}
    staged_fixes = []
    try:
        auth_url = repo.clone_url.replace("https://", f"https://{github_token}@")
        subprocess.run(
            ["git", "clone", "--depth", "1", auth_url, temp_dir],
            check=True, capture_output=True, timeout=60,
        )

        fixes_by_file = {}
        for finding in eligible:
            relative_path = finding.get("repository_relative_path") or _normalize_path(finding["file_path"], temp_dir)
            if relative_path:
                fixes_by_file.setdefault(relative_path, []).append(finding)

        for relative_path, file_findings in fixes_by_file.items():
            local_path = os.path.join(temp_dir, relative_path)
            if not os.path.isfile(local_path):
                for finding in file_findings:
                    skipped_fixes.append(_skip(finding, relative_path, "skipped_file_not_found", "File not found in repository."))
                continue
            if not relative_path.endswith(".py"):
                for finding in file_findings:
                    skipped_fixes.append(_skip(finding, relative_path, "rejected_unsupported_file_type", "Only Python files can be automatically validated."))
                continue

            original = Path(local_path).read_text(encoding="utf-8", errors="ignore")
            expected_hashes = {f.get("source_file_hash") for f in file_findings if f.get("source_file_hash")}
            if expected_hashes and source_sha256(original) not in expected_hashes:
                for finding in file_findings:
                    skipped_fixes.append(_skip(finding, relative_path, "rejected_stale_source", "Source file hash differs from the scanned file; rerun the scan."))
                continue
            content = original
            file_fixes = []
            for finding in file_findings:
                vulnerable_code = finding.get("vulnerable_code", "")
                fixed_code = finding.get("fixed_code", "").strip()
                if not vulnerable_code.strip() or not fixed_code:
                    skipped_fixes.append(_skip(finding, relative_path, "skipped_missing_patch", "Empty vulnerable_code or fixed_code."))
                    continue
                if _is_structural_rewrite(vulnerable_code, fixed_code):
                    skipped_fixes.append(_skip(finding, relative_path, "rejected_unsafe_patch_boundary", "Generated fix is a structural rewrite; manual review required."))
                    continue
                candidate, replacement_error = _replace_with_context(content, vulnerable_code, fixed_code)
                if candidate is None:
                    skipped_fixes.append(_skip(finding, relative_path, "rejected_unsafe_patch_boundary", replacement_error))
                    continue

                valid, validation = _validate_python_patch(local_path, content, candidate)
                if valid:
                    # Check the enclosing function, not the entire file. This
                    # retains SQL query/execution context while isolating an
                    # independent finding in another function.
                    valid, security = _validate_vulnerability_fix(
                        finding.get("vuln_type", ""), candidate,
                        target_code=_security_scope(candidate, fixed_code),
                    )
                    validation["checks"].update(security["checks"])
                    if not valid:
                        validation = security
                if valid:
                    valid, regression = _validate_full_file_regression(finding, candidate)
                    validation["checks"].update(regression["checks"])
                    if not valid:
                        validation = regression
                validation_details.append({"file": relative_path, **validation})
                if not valid:
                    Path(local_path).write_text(content, encoding="utf-8")
                    skipped_fixes.append(_skip(finding, relative_path, validation["status"], validation["reason"], validation["checks"]))
                    continue

                content = candidate
                finding["remediation_status"] = "security_regression_tested"
                file_fixes.append({
                    "vuln_type": finding.get("vuln_type"), "severity": finding.get("severity"),
                    "cvss_score": finding.get("cvss_score"), "file": relative_path,
                    "line": finding.get("line_number"), "status": "staged",
                })

            if content == original:
                continue
            valid, validation = _validate_python_patch(local_path, original, content)
            validation_details.append({"file": relative_path, **validation})
            if not valid:
                Path(local_path).write_text(original, encoding="utf-8")
                for fix in file_fixes:
                    skipped_fixes.append({**fix, "status": validation["status"], "reason": validation["reason"], "checks": validation["checks"]})
                continue
            staged_files[relative_path] = content
            staged_fixes.extend(file_fixes)

        if not staged_files:
            return _no_fixes_result("No fixes were staged because generated changes failed validation.", skipped_fixes, validation_details)

        tests_valid, test_validation = _run_project_tests(temp_dir, allow_untested=allow_untested)
        validation_details.append({"file": "repository", **test_validation})
        if not tests_valid:
            return _no_fixes_result("No fixes were pushed because repository test validation failed.", skipped_fixes + [
                {**fix, "status": test_validation["status"], "reason": test_validation["reason"], "checks": test_validation["checks"]}
                for fix in staged_fixes
            ], validation_details)

        branch_name = f"shieldlabs-fixes-{scan_id.replace('scan_', '')[:8]}"
        try:
            # Ensure validation was performed against the current base.
            if repo.get_branch(default_branch).commit.sha != source_sha:
                return _no_fixes_result("Repository changed during validation; rerun the scan before creating a PR.", skipped_fixes, validation_details)
            repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=source_sha)
        except GithubException as e:
            if e.status != 422:
                return _error_result(f"Failed to create branch: {str(e)}")

        applied_fixes = []
        for relative_path, content in staged_files.items():
            try:
                gh_file = repo.get_contents(relative_path, ref=branch_name)
                repo.update_file(relative_path, f"fix: Apply ShieldLabs security fixes in {relative_path}", content, gh_file.sha, branch=branch_name)
                for fix in staged_fixes:
                    if fix["file"] == relative_path:
                        fix["status"] = "validated_and_applied"
                        fix["remediation_status"] = "applied_in_pr"
                        applied_fixes.append(fix)
            except GithubException as e:
                for fix in staged_fixes:
                    if fix["file"] == relative_path:
                        skipped_fixes.append({**fix, "status": "rejected_push_error", "reason": f"GitHub push failed: {e}"})

        if not applied_fixes:
            _delete_branch(repo, branch_name)
            return _no_fixes_result("No fixes were pushed because GitHub rejected the updates.", skipped_fixes, validation_details)

        pr = repo.create_pull(
            title=f"🛡️ ShieldLabs: {len(applied_fixes)} Security Fix{'es' if len(applied_fixes) != 1 else ''} Applied",
            body=_build_pr_description(scan_id, applied_fixes, skipped_fixes, validation_details),
            head=branch_name, base=default_branch,
        )
        return {
            "success": True, "pr_url": pr.html_url, "pr_number": pr.number,
            "branch_name": branch_name, "fixes_applied": len(applied_fixes),
            "fixes_skipped": len(skipped_fixes),
            "remediation_status": _remediation_status(len(applied_fixes), len(skipped_fixes)),
            "applied_details": applied_fixes, "skipped_details": skipped_fixes,
            "validation_details": validation_details, "error": None,
        }
    except GithubException as e:
        return _error_result(f"GitHub PR operation failed: {str(e)}")
    except (subprocess.CalledProcessError, OSError) as e:
        return _error_result(f"Failed to clone or validate repository: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _skip(finding: dict, file_path: str, status: str, reason: str, checks: dict | None = None) -> dict:
    """Build a consistent skipped-finding record."""
    return {"vuln_type": finding.get("vuln_type"), "file": file_path,
            "line": finding.get("line_number"), "status": status,
            "reason": reason, "checks": checks or {}}


def _no_fixes_result(message: str, skipped: list[dict], validations: list[dict]) -> dict:
    return _error_result(message, extra={"fixes_skipped": len(skipped),
        "skipped_details": skipped, "validation_details": validations})


def _delete_branch(repo, branch_name: str) -> None:
    """Best-effort cleanup for a branch with no successfully pushed changes."""
    try:
        repo.get_git_ref(f"heads/{branch_name}").delete()
    except Exception as exc:
        logger.warning("Could not delete empty branch %s: %s", branch_name, exc)


# ────────────────────────────────────────────────
# HELPERS
# ────────────────────────────────────────────────

def _parse_repo_url(url: str) -> tuple[str, str]:
    """Extract owner and repo name from GitHub URL."""
    try:
        cleaned = url.rstrip("/")
        if cleaned.endswith(".git"):
            cleaned = cleaned[:-4]
        parts = cleaned.replace("https://github.com/", "").split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
    except Exception:
        pass
    return "", ""


def _normalize_path(file_path: str, temp_dir: str) -> str | None:
    """
    Convert an absolute or mixed path to a repo-relative path.
    e.g. /tmp/shieldlabs_abc/app/main.py → app/main.py
    """
    if not file_path:
        return None

    # If it's absolute and starts with the temp dir, make it relative
    if os.path.isabs(file_path) and temp_dir in file_path:
        return os.path.relpath(file_path, temp_dir)

    # If it already looks relative, return as-is
    if not os.path.isabs(file_path):
        return file_path

    # Last resort — just take the filename
    return os.path.basename(file_path)


def _build_pr_description(
    scan_id: str,
    applied: list[dict],
    skipped: list[dict],
    validations: list[dict] | None = None,
) -> str:
    """Build a human-readable PR description."""

    lines = [
        "## 🛡️ ShieldLabs Automated Security Fix",
        "",
        f"**Scan ID:** `{scan_id}`",
        f"**Fixes Applied:** {len(applied)}",
        f"**Fixes Skipped:** {len(skipped)}",
        "",
        "> ⚠️ **Review each change before merging.** "
        "AI-generated fixes are correct for the detected pattern but "
        "may need adjustment for your specific business logic.",
        "",
    ]

    if applied:
        lines += [
            "### ✅ Applied Fixes",
            "",
            "| Vulnerability | File | Line | Severity | CVSS | Validation |",
            "|---|---|---|---|---|---|",
        ]
        for fix in applied:
            lines.append(
                f"| {fix['vuln_type']} "
                f"| `{fix['file']}` "
                f"| {fix.get('line', 'N/A')} "
                f"| {fix.get('severity', 'N/A')} "
                f"| {fix.get('cvss_score', 'N/A')} "
                f"| AST + py_compile passed |"
            )
        lines.append("")

    if skipped:
        lines += [
            "### ⚠️ Skipped (Manual Review Required)",
            "",
        ]
        for skip in skipped:
            lines.append(
                f"- **{skip['vuln_type']}** in `{skip['file']}` "
                f"({skip.get('status', 'manual_review')}): "
                f"{skip['reason']}"
            )
        lines.append("")

    if validations:
        lines += [
            "### Validation Summary",
            "",
        ]
        for validation in validations:
            checks = ", ".join(
                f"{name}={status}"
                for name, status in validation.get("checks", {}).items()
            ) or "no checks run"
            lines.append(
                f"- `{validation['file']}` — **{validation['status']}**: "
                f"{validation['reason']} ({checks})"
            )
        lines.append("")

    lines += [
        "---",
        "_Generated by [ShieldLabs](https://github.com/himachal12/ShieldLabs) "
        "— AI-powered security scanning for Nepal startups_ 🇳🇵",
    ]

    return "\n".join(lines)


def _error_result(message: str, extra: dict = None) -> dict:
    """Standardized error response."""
    result = {
        "success": False,
        "pr_url": None,
        "pr_number": None,
        "branch_name": "",
        "fixes_applied": 0,
        "fixes_skipped": 0,
        "applied_details": [],
        "skipped_details": [],
        "validation_details": [],
        "error": message
    }
    if extra:
        result.update(extra)
    return result
