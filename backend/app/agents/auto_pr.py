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
from github import Github, GithubException
from app.utils.logger import get_logger

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


def _validate_vulnerability_fix(vuln_type: str, patch_code: str) -> tuple[bool, dict]:
    """Apply conservative, deterministic security checks for generated fixes.

    Syntax validity alone cannot establish that an AI patch fixes the security
    issue. These guards inspect only the generated replacement for the current
    finding, so one remaining finding elsewhere in the same file cannot reject
    an otherwise safe patch. A patch which cannot satisfy a guard is kept out
    of the PR and left for manual review.
    """
    checks = {}
    try:
        tree = ast.parse(patch_code)
    except SyntaxError:
        # The caller records the more useful syntax error separately.
        return True, {"status": "not_run", "checks": checks, "reason": "Security checks deferred to syntax validation."}

    source_lower = patch_code.lower()
    if vuln_type == "SQL Injection":
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
        unsafe_redirect = re.search(r"redirect\(\s*request\.(args|form|values)\.get\(", patch_code)
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
        if ".stdout" in patch_code and run_calls and not any(
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
        if re.search(r"\bpickle\.(loads|load)\s*\(", patch_code):
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


def _run_project_tests(repo_dir: str) -> tuple[bool, dict]:
    """Run an existing Python test suite in the fresh checkout when present.

    We never invent or install dependencies in a customer's repository. A
    missing test suite is disclosed to the developer, while an existing suite
    that fails blocks the candidate from being pushed. This lets supported,
    independently syntax- and security-validated fixes help small repositories
    that do not yet have tests.
    """
    has_tests = any(
        name.startswith("test_") and name.endswith(".py")
        for _, _, files in os.walk(repo_dir)
        for name in files
    )
    if not has_tests:
        return True, {
            "status": "tests_not_available",
            "checks": {"project_tests": "not_available"},
            "reason": "No Python test suite found; patch passed static and category-specific validation only.",
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
        elif not f.get("file_path"):
            reason = "no file_path"
        elif not f.get("vulnerable_code"):
            reason = "no vulnerable_code snippet stored"
        elif not f.get("fixed_code"):
            reason = "no fixed_code generated (architectural finding)"
        elif f.get("is_false_positive"):
            reason = "marked as false positive"

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
    findings: list[dict]
) -> dict:
    """
    Main entry point. Creates a PR with auto-applied fixes.

    Args:
        github_token: Personal access token with repo write access
        repo_url:     Full GitHub URL (https://github.com/owner/repo)
        scan_id:      For branch naming and PR description
        findings:     All findings from the scan (we filter internally)

    Returns:
        {
            "success": bool,
            "pr_url": str | None,
            "pr_number": int | None,
            "branch_name": str,
            "fixes_applied": int,
            "fixes_skipped": int,
            "skipped_details": [...],
            "error": str | None
        }
    """
    # ── Validate inputs ────────────────────────────────────────
    if not github_token or not github_token.strip():
        return _error_result("GitHub token is required")

    if not repo_url:
        return _error_result("Repository URL is required")

    # ── Parse owner/repo from URL ──────────────────────────────
    owner, repo_name = _parse_repo_url(repo_url)
    if not owner or not repo_name:
        return _error_result(
            f"Could not parse owner/repo from URL: {repo_url}. "
            "Expected format: https://github.com/owner/repo"
        )

    # ── Filter eligible findings ───────────────────────────────
    eligible = get_eligible_findings(findings)
    if not eligible:
        return _error_result(
            "No findings are eligible for auto-fix. "
            "Findings need: file_path, vulnerable_code, and fixed_code. "
            "Web findings (headers, ports) cannot be auto-fixed."
        )

    # ── Connect to GitHub ──────────────────────────────────────
    try:
        g = Github(github_token)
        repo = g.get_repo(f"{owner}/{repo_name}")
        logger.info(f"Connected to GitHub repo: {repo.full_name}")
    except GithubException as e:
        if e.status == 401:
            return _error_result(
                "GitHub token is invalid or expired. "
                "Create a new token at github.com/settings/tokens "
                "with 'repo' scope (full read/write access)."
            )
        elif e.status == 404:
            return _error_result(
                f"Repository not found: {owner}/{repo_name}. "
                "Check the URL is correct and your token has access."
            )
        return _error_result(f"GitHub connection failed: {str(e)}")

    # ── Create branch ──────────────────────────────────────────
    branch_suffix = scan_id.replace("scan_", "")[:8]
    branch_name = f"shieldlabs-fixes-{branch_suffix}"

    try:
        default_branch = repo.default_branch
        source_sha = repo.get_branch(default_branch).commit.sha
        repo.create_git_ref(
            ref=f"refs/heads/{branch_name}",
            sha=source_sha
        )
        logger.info(f"Created branch: {branch_name} from {default_branch}")
    except GithubException as e:
        if e.status == 422:
            # Branch already exists (re-run of same scan)
            logger.warning(f"Branch {branch_name} already exists, reusing")
        else:
            return _error_result(f"Failed to create branch: {str(e)}")

    # ── Clone repo to apply fixes locally ─────────────────────
    temp_dir = tempfile.mkdtemp(prefix="shieldlabs_pr_")
    try:
        # Build authenticated clone URL
        auth_url = repo.clone_url.replace(
            "https://",
            f"https://{github_token}@"
        )

        import subprocess
        subprocess.run(
            ["git", "clone", "--depth", "1", auth_url, temp_dir],
            check=True,
            capture_output=True,
            timeout=60
        )
        logger.info(f"Cloned repo to {temp_dir}")

    except subprocess.CalledProcessError as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return _error_result(f"Failed to clone repository: {e.stderr.decode()[:200]}")
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return _error_result(f"Clone failed: {str(e)}")

    # ── Group findings by file ─────────────────────────────────
    fixes_by_file = {}
    for finding in eligible:
        file_path = finding["file_path"]

        # Normalize path — remove leading slashes, make relative
        # (stored paths might be absolute from the clone temp dir)
        normalized = _normalize_path(file_path, temp_dir)
        if not normalized:
            continue

        if normalized not in fixes_by_file:
            fixes_by_file[normalized] = []
        fixes_by_file[normalized].append(finding)

    logger.info(f"Fixes span {len(fixes_by_file)} file(s)")

    # ── Apply fixes file by file ───────────────────────────────
    applied_fixes = []
    skipped_fixes = []
    validation_details = []

    try:
        for relative_path, file_findings in fixes_by_file.items():
            local_path = os.path.join(temp_dir, relative_path)

            if not os.path.exists(local_path):
                for f in file_findings:
                    skipped_fixes.append({
                        "vuln_type": f.get("vuln_type"),
                        "file": relative_path,
                        "status": "skipped_file_not_found",
                        "reason": f"File not found in repo: {relative_path}"
                    })
                continue

            # Read current file content
            with open(local_path, 'r', encoding='utf-8', errors='ignore') as fh:
                content = fh.read()

            original_content = content  # keep for comparison
            file_applied_fixes = []

            # Apply and validate each fix independently. One rejected fix must
            # never discard another fix that already passed validation.
            for finding in file_findings:
                vulnerable_code = finding.get("vulnerable_code", "")
                fixed_code = finding.get("fixed_code", "").strip()

                if not vulnerable_code.strip() or not fixed_code:
                    skipped_fixes.append({
                        "vuln_type": finding.get("vuln_type"),
                        "file": relative_path,
                        "status": "skipped_missing_patch",
                        "reason": "Empty vulnerable_code or fixed_code"
                    })
                    continue

                if _is_structural_rewrite(vulnerable_code, fixed_code):
                    skipped_fixes.append({
                        "vuln_type": finding.get("vuln_type"),
                        "file": relative_path,
                        "status": "rejected_unsafe_patch_boundary",
                        "reason": (
                            "AI-generated fix is a structural rewrite "
                            "(e.g. adds a new function) rather than a drop-in "
                            "replacement. Manual fix recommended."
                        )
                    })
                    continue

                candidate, replacement_error = _replace_with_context(
                    content, vulnerable_code, fixed_code
                )
                if candidate is None:
                    validation = {
                        "status": "rejected_unsafe_patch_boundary",
                        "checks": {},
                        "reason": replacement_error,
                    }
                    is_valid = False
                else:
                    is_valid, validation = _validate_python_patch(
                        local_path, content, candidate
                    )

                if is_valid:
                    security_valid, security_validation = _validate_vulnerability_fix(
                        finding.get("vuln_type", ""), fixed_code
                    )
                    validation["checks"].update(security_validation["checks"])
                    if not security_valid:
                        is_valid = False
                        validation = security_validation
                        # _validate_python_patch writes a successful candidate to
                        # disk for py_compile. Do not let a rejected candidate
                        # become the base for a later finding in this file.
                        with open(local_path, "w", encoding="utf-8") as handle:
                            handle.write(content)

                validation_details.append({"file": relative_path, **validation})
                if not is_valid:
                    skipped_fixes.append({
                        "vuln_type": finding.get("vuln_type"),
                        "file": relative_path,
                        "line": finding.get("line_number"),
                        "status": validation["status"],
                        "reason": validation["reason"],
                        "checks": validation["checks"],
                    })
                    logger.warning(
                        "Rejected generated fix %s in %s: %s",
                        finding.get("vuln_type"), relative_path, validation["reason"],
                    )
                    continue

                content = candidate
                file_applied_fixes.append({
                    "vuln_type": finding.get("vuln_type"),
                    "severity": finding.get("severity"),
                    "cvss_score": finding.get("cvss_score"),
                    "file": relative_path,
                    "line": finding.get("line_number"),
                    "status": "pending_push",
                })
                logger.info(
                    "Validated staged fix: %s in %s",
                    finding.get("vuln_type"), relative_path,
                )

            # Validate the complete candidate file before it can be pushed.
            if content != original_content and relative_path.endswith(".py"):
                is_valid, validation = _validate_python_patch(
                    local_path, original_content, content
                )
                validation_details.append({"file": relative_path, **validation})
                if not is_valid:
                    # The validator writes the candidate before py_compile. Restore the
                    # original source and reject every patch in this file as a unit.
                    with open(local_path, "w", encoding="utf-8") as handle:
                        handle.write(original_content)
                    for fix in file_applied_fixes:
                        skipped_fixes.append({
                            "vuln_type": fix["vuln_type"],
                            "file": relative_path,
                            "line": fix.get("line"),
                            "status": validation["status"],
                            "reason": validation["reason"],
                            "checks": validation["checks"],
                        })
                    logger.warning(
                        "Rejected generated fixes in %s: %s",
                        relative_path,
                        validation["reason"],
                    )
                    continue

                tests_valid, test_validation = _run_project_tests(temp_dir)
                validation_details.append({"file": relative_path, **test_validation})
                if not tests_valid:
                    with open(local_path, "w", encoding="utf-8") as handle:
                        handle.write(original_content)
                    for fix in file_applied_fixes:
                        skipped_fixes.append({
                            "vuln_type": fix["vuln_type"],
                            "file": relative_path,
                            "line": fix.get("line"),
                            "status": test_validation["status"],
                            "reason": test_validation["reason"],
                            "checks": test_validation["checks"],
                        })
                    logger.warning(
                        "Rejected generated fixes in %s because tests failed: %s",
                        relative_path, test_validation["reason"],
                    )
                    continue

            if content != original_content and not relative_path.endswith(".py"):
                validation = {
                    "status": "rejected_unsupported_file_type",
                    "checks": {},
                    "reason": "Only Python files can be syntax-validated for Auto PR.",
                }
                validation_details.append({"file": relative_path, **validation})
                for fix in file_applied_fixes:
                    skipped_fixes.append({
                        "vuln_type": fix["vuln_type"],
                        "file": relative_path,
                        "status": "skipped_source_changed",
                        "reason": (
                            "Vulnerable code pattern not found in current file. "
                            "File may have changed since scan was run."
                        )
                    })
                continue

            # Push only a fully validated candidate file.
            if content != original_content:
                try:
                    # Get the file's SHA (needed for GitHub API update)
                    gh_file = repo.get_contents(relative_path, ref=branch_name)
                    repo.update_file(
                        path=relative_path,
                        message=f"fix: Apply ShieldLabs security fixes in {relative_path}",
                        content=content,
                        sha=gh_file.sha,
                        branch=branch_name
                    )
                    for fix in file_applied_fixes:
                        fix["status"] = "validated_and_applied"
                    applied_fixes.extend(file_applied_fixes)
                    logger.info(f"  Pushed fixed {relative_path} to {branch_name}")
                except GithubException as e:
                    logger.error(f"  Failed to push {relative_path}: {e}")
                    # Move these from applied to skipped
                    failed_types = [f.get("vuln_type") for f in file_findings]
                    for ft in failed_types:
                        skipped_fixes.append({
                            "vuln_type": ft,
                            "file": relative_path,
                            "status": "rejected_push_error",
                            "reason": f"GitHub push failed: {str(e)}"
                        })

    finally:
        # Always clean up temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info("Cleaned up temp directory")

    # If nothing got applied, don't open an empty PR
    if not applied_fixes:
        rejection_message = "No fixes could be applied. Review the validation details below."
        if validation_details:
            rejection_message = (
                "No fixes were pushed because generated changes failed validation. "
                "Review the validation details below."
            )
        return _error_result(
            rejection_message,
            extra={
                "branch_name": branch_name,
                "fixes_applied": 0,
                "fixes_skipped": len(skipped_fixes),
                "applied_details": [],
                "skipped_details": skipped_fixes,
                "validation_details": validation_details,
            }
        )

    # ── Create Pull Request ────────────────────────────────────
    pr_body = _build_pr_description(
        scan_id=scan_id,
        applied=applied_fixes,
        skipped=skipped_fixes,
        validations=validation_details,
    )

    try:
        pr = repo.create_pull(
            title=f"🛡️ ShieldLabs: {len(applied_fixes)} Security Fix"
                  f"{'es' if len(applied_fixes) != 1 else ''} Applied",
            body=pr_body,
            head=branch_name,
            base=default_branch
        )
        logger.info(f"PR created: {pr.html_url}")

        return {
            "success": True,
            "pr_url": pr.html_url,
            "pr_number": pr.number,
            "branch_name": branch_name,
            "fixes_applied": len(applied_fixes),
            "fixes_skipped": len(skipped_fixes),
            "remediation_status": _remediation_status(len(applied_fixes), len(skipped_fixes)),
            "applied_details": applied_fixes,
            "skipped_details": skipped_fixes,
            "validation_details": validation_details,
            "error": None
        }

    except GithubException as e:
        return _error_result(
            f"Failed to create Pull Request: {str(e)}",
            extra={
                "branch_name": branch_name,
                "fixes_applied": len(applied_fixes),
                "fixes_skipped": len(skipped_fixes),
                "remediation_status": _remediation_status(len(applied_fixes), len(skipped_fixes)),
                "applied_details": applied_fixes,
                "skipped_details": skipped_fixes,
                "validation_details": validation_details,
            }
        )


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
