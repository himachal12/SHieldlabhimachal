"""Focused safety tests for Auto-PR patch validation."""

import sys
from types import ModuleType
from types import SimpleNamespace


if "github" not in sys.modules:
    github_stub = ModuleType("github")

    class Github:  # pragma: no cover - import stub only
        pass

    class GithubException(Exception):  # pragma: no cover - import stub only
        pass

    github_stub.Github = Github
    github_stub.GithubException = GithubException
    sys.modules["github"] = github_stub

from app.agents import auto_pr
from app.agents.auto_pr import (
    _build_pr_description,
    _ensure_stdlib_imports,
    _replace_with_context,
    _run_project_tests,
    _validate_full_file_regression,
    _validate_vulnerability_fix,
    _validate_python_patch,
)


def test_full_file_secret_regression_rejects_duplicate_assignment():
    valid, detail = _validate_full_file_regression({
        "vuln_type": "Hardcoded Secrets",
        "repository_relative_path": "settings.py",
        "vulnerable_code": 'SECRET_KEY = "exposed"',
    }, 'SECRET_KEY = os.environ["SECRET_KEY"]\nSECRET_KEY = os.environ["SECRET_KEY"]\n')

    assert valid is False
    assert detail["checks"]["single_secret_assignment"] == "failed"


def test_full_file_secret_regression_allows_other_pending_secrets():
    valid, detail = _validate_full_file_regression({
        "vuln_type": "Hardcoded Secrets",
        "repository_relative_path": "settings.py",
        "vulnerable_code": 'SECRET_KEY = "exposed"',
    }, 'SECRET_KEY = os.environ["SECRET_KEY"]\nAPI_TOKEN = "still-exposed"\n')

    assert valid is True
    assert detail["checks"]["detector_rescan"] == "passed"


def test_valid_python_patch_is_compiled(tmp_path):
    source_file = tmp_path / "service.py"
    original = "value = 1\n"
    candidate = "value = 2\n"
    source_file.write_text(original, encoding="utf-8")

    is_valid, detail = _validate_python_patch(str(source_file), original, candidate)

    assert is_valid is True
    assert detail["status"] == "validated"
    assert detail["checks"] == {
        "ast_parse": "passed",
        "dependency_policy": "passed",
        "py_compile": "passed",
    }
    assert source_file.read_text(encoding="utf-8") == candidate


def test_secret_replacement_removes_literal_without_creating_duplicate_assignment(tmp_path):
    source_file = tmp_path / "settings.py"
    original = 'SECRET_KEY = "exposed"\n'
    source_file.write_text(original, encoding="utf-8")

    candidate, error = _replace_with_context(
        original,
        'SECRET_KEY = "exposed"',
        'import os\nSECRET_KEY = os.environ["SECRET_KEY"]',
    )
    assert error is None
    assert candidate == 'import os\nSECRET_KEY = os.environ["SECRET_KEY"]\n'
    assert candidate.count("SECRET_KEY =") == 1

    is_valid, detail = _validate_python_patch(str(source_file), original, candidate)
    assert is_valid is True
    assert detail["status"] == "validated"


def test_invalid_python_patch_is_rejected_before_push(tmp_path):
    source_file = tmp_path / "service.py"
    original = "value = 1\n"
    source_file.write_text(original, encoding="utf-8")

    is_valid, detail = _validate_python_patch(
        str(source_file), original, "return value = 2\n"
    )

    assert is_valid is False
    assert detail["status"] == "rejected_syntax_error"
    assert detail["checks"]["ast_parse"] == "failed"
    assert source_file.read_text(encoding="utf-8") == original


def test_new_third_party_import_requires_manual_review(tmp_path):
    source_file = tmp_path / "service.py"
    original = "value = 1\n"
    candidate = "import bcrypt\nvalue = 2\n"
    source_file.write_text(original, encoding="utf-8")

    is_valid, detail = _validate_python_patch(str(source_file), original, candidate)

    assert is_valid is False
    assert detail["status"] == "rejected_dependency"
    assert "bcrypt" in detail["reason"]
    assert source_file.read_text(encoding="utf-8") == original


def test_multiline_replacement_preserves_source_indentation():
    content = (
        "def get_user(name):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{name}'\"\n"
    )

    candidate, error = _replace_with_context(
        content,
        'query = f"SELECT * FROM users WHERE username = \'{name}\'"',
        'query = "SELECT * FROM users WHERE username = ?"\n'
        "cursor.execute(query, (name,))",
    )

    assert error is None
    assert candidate == (
        "def get_user(name):\n"
        "    query = \"SELECT * FROM users WHERE username = ?\"\n"
        "    cursor.execute(query, (name,))\n"
    )


def test_nested_multiline_replacement_preserves_relative_indentation():
    content = "def endpoint():\n    return redirect(request.args.get('url'))\n"

    candidate, error = _replace_with_context(
        content,
        "return redirect(request.args.get('url'))",
        "target = request.args.get('url', '/')\n"
        "if not target.startswith('/') or target.startswith('//'):\n"
        "    target = '/'\n"
        "return redirect(target)",
    )

    assert error is None
    assert candidate == (
        "def endpoint():\n"
        "    target = request.args.get('url', '/')\n"
        "    if not target.startswith('/') or target.startswith('//'):\n"
        "        target = '/'\n"
        "    return redirect(target)\n"
    )


def test_ensure_stdlib_imports_adds_os_once_after_docstring():
    source = '"""settings"""\n\nSECRET_KEY = os.environ["SECRET_KEY"]\nAPI_TOKEN = os.environ["API_TOKEN"]\n'

    candidate = _ensure_stdlib_imports(source)

    assert candidate.count("import os") == 1
    assert candidate == '"""settings"""\n\nimport os\n\nSECRET_KEY = os.environ["SECRET_KEY"]\nAPI_TOKEN = os.environ["API_TOKEN"]\n'


def test_ensure_stdlib_imports_does_not_duplicate_existing_os_import():
    source = 'import os\nSECRET_KEY = os.environ["SECRET_KEY"]\n'

    assert _ensure_stdlib_imports(source) == source


def test_line_number_fallback_replaces_spaced_secret_line_without_duplication():
    content = (
        '# VULN 1: Hardcoded secrets\n'
        'JWT_SECRET      = "jwt_secret_do_not_share"\n'
        'AWS_ACCESS_KEY  = "AKIAIOSFODNN7HARDCODED"\n'
    )

    candidate, error = _replace_with_context(
        content,
        'JWT_SECRET = "jwt_secret_do_not_share"',
        'JWT_SECRET = os.environ["JWT_SECRET"]',
        line_number=2,
    )

    assert error is None
    assert 'JWT_SECRET      = "jwt_secret_do_not_share"' not in candidate
    assert candidate.count('JWT_SECRET =') == 1
    assert 'JWT_SECRET = os.environ["JWT_SECRET"]' in candidate
    assert 'AWS_ACCESS_KEY  = "AKIAIOSFODNN7HARDCODED"' in candidate


def test_line_number_fallback_replaces_partial_redirect_statement():
    content = "@app.route('/redirect')\ndef redirect_user():\n    return redirect(request.args.get('url'))\n"

    candidate, error = _replace_with_context(
        content,
        "redirect(request.args.get('url'))",
        "target = request.args.get('url', '/')\n"
        "if not target.startswith('/') or target.startswith('//'):\n"
        "    target = '/'\n"
        "return redirect(target)",
        line_number=3,
    )

    assert error is None
    assert "return redirect(request.args.get('url'))" not in candidate
    assert candidate == (
        "@app.route('/redirect')\n"
        "def redirect_user():\n"
        "    target = request.args.get('url', '/')\n"
        "    if not target.startswith('/') or target.startswith('//'):\n"
        "        target = '/'\n"
        "    return redirect(target)\n"
    )


def test_multiline_replacement_rejects_partial_statement():
    content = "def endpoint():\n    return redirect(request.args.get('url'))\n"

    candidate, error = _replace_with_context(
        content,
        "redirect(request.args.get('url'))",
        "url = request.args.get('url', '/')\nreturn redirect(url)",
    )

    assert candidate is None
    assert error == (
        "Generated multi-line fix targets only part of a source statement. "
        "Manual review required."
    )


def test_sql_patch_without_bound_parameters_is_rejected():
    valid, detail = _validate_vulnerability_fix(
        "SQL Injection",
        'query = "SELECT * FROM users WHERE id = ?"\nconn.execute(query)\n',
    )

    assert valid is False
    assert detail["status"] == "rejected_security_regression"
    assert detail["checks"]["parameterized_query"] == "failed"


def test_jwt_patch_that_still_disables_verification_is_rejected():
    valid, detail = _validate_vulnerability_fix(
        "Weak JWT Implementation",
        'payload = jwt.decode(token, options={"verify_signature": False})\n',
    )

    assert valid is False
    assert detail["status"] == "rejected_security_regression"


def test_command_patch_reading_uncaptured_stdout_is_rejected():
    valid, detail = _validate_vulnerability_fix(
        "Command Injection",
        'result = subprocess.run(["ping", host], shell=False).stdout.decode()\n',
    )

    assert valid is False
    assert detail["status"] == "rejected_runtime_risk"


def test_safe_parameterized_sql_patch_passes_category_check():
    valid, detail = _validate_vulnerability_fix(
        "SQL Injection",
        'query = "SELECT * FROM users WHERE id = ?"\ncursor = conn.execute(query, (user_id,))\n',
    )

    assert valid is True
    assert detail["checks"]["parameterized_query"] == "passed"


def test_sql_check_uses_the_changed_fix_not_other_file_findings():
    candidate = (
        'query = "SELECT * FROM users WHERE id = ?"\n'
        'conn.execute(query, (user_id,))\n\n'
        'query = f"SELECT * FROM users WHERE name = \'{name}\'"\n'
        'conn.execute(query)\n'
    )
    fixed_region = (
        'query = "SELECT * FROM users WHERE id = ?"\n'
        'conn.execute(query, (user_id,))\n'
    )

    valid, detail = _validate_vulnerability_fix(
        "SQL Injection", candidate, target_code=fixed_region
    )

    assert valid is True
    assert detail["checks"]["parameterized_query"] == "passed"


def test_explicit_manual_review_allows_no_test_suite(tmp_path):
    valid, detail = _run_project_tests(str(tmp_path), allow_untested=True)

    assert valid is True
    assert detail["status"] == "tests_not_available"

def test_pr_description_reports_validation_and_skips():
    description = _build_pr_description(
        scan_id="scan_123",
        applied=[{
            "vuln_type": "SQL Injection",
            "file": "app.py",
            "line": 10,
            "severity": "HIGH",
            "cvss_score": 8.0,
        }],
        skipped=[{
            "vuln_type": "Weak JWT Implementation",
            "file": "app.py",
            "status": "rejected_syntax_error",
            "reason": "Syntax validation failed: invalid syntax.",
        }],
        validations=[{
            "file": "app.py",
            "status": "rejected_syntax_error",
            "reason": "Syntax validation failed: invalid syntax.",
            "checks": {"ast_parse": "failed"},
        }],
    )

    assert "AST + py_compile passed" in description
    assert "rejected_syntax_error" in description
    assert "Validation Summary" in description


def test_create_pr_does_not_push_a_syntax_invalid_patch(monkeypatch):
    class FakeRepo:
        full_name = "owner/repo"
        default_branch = "main"
        clone_url = "https://github.com/owner/repo.git"
        updated = False
        branch_created = False

        def get_branch(self, name):
            return SimpleNamespace(commit=SimpleNamespace(sha="abc123"))

        def create_git_ref(self, **kwargs):
            self.branch_created = True
            return None

        def get_contents(self, *args, **kwargs):
            raise AssertionError("Invalid code must never be pushed")

        def update_file(self, *args, **kwargs):
            self.updated = True
            raise AssertionError("Invalid code must never be pushed")

    repo = FakeRepo()
    monkeypatch.setattr(auto_pr, "Github", lambda token: SimpleNamespace(
        get_repo=lambda name: repo
    ))

    real_run = auto_pr.subprocess.run

    def fake_run(command, **kwargs):
        if command[:2] == ["git", "clone"]:
            destination = command[-1]
            import os
            os.makedirs(destination, exist_ok=True)
            with open(os.path.join(destination, "app.py"), "w", encoding="utf-8") as handle:
                handle.write('def target():\n    value = "bad"\n')
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return real_run(command, **kwargs)

    monkeypatch.setattr(auto_pr.subprocess, "run", fake_run)

    result = auto_pr.create_fix_pr(
        github_token="test-token",
        repo_url="https://github.com/owner/repo",
        scan_id="scan_validation",
        findings=[{
            "vuln_type": "SQL Injection",
            "severity": "HIGH",
            "cvss_score": 8.0,
            "file_path": "app.py",
            "line_number": 2,
            "vulnerable_code": 'value = "bad"',
            "fixed_code": 'return value = "good"',
            "source": "bandit",
        }],
    )

    assert result["success"] is False
    assert result["fixes_applied"] == 0
    assert result["skipped_details"][0]["status"] == "rejected_syntax_error"
    assert result["validation_details"][0]["status"] == "rejected_syntax_error"
    assert repo.updated is False
    assert repo.branch_created is False


def test_manual_review_pushes_a_valid_fix_only_after_local_validation(monkeypatch):
    class FakeRepo:
        full_name = "owner/repo"
        default_branch = "main"
        clone_url = "https://github.com/owner/repo.git"
        branch_created = False
        updated_content = None

        def get_branch(self, name):
            return SimpleNamespace(commit=SimpleNamespace(sha="abc123"))

        def create_git_ref(self, **kwargs):
            self.branch_created = True

        def get_contents(self, *args, **kwargs):
            return SimpleNamespace(sha="file-sha")

        def update_file(self, *args, **kwargs):
            self.updated_content = kwargs["content"] if "content" in kwargs else args[2]

        def create_pull(self, **kwargs):
            return SimpleNamespace(html_url="https://github.com/owner/repo/pull/1", number=1)

    repo = FakeRepo()
    monkeypatch.setattr(auto_pr, "Github", lambda token: SimpleNamespace(get_repo=lambda name: repo))
    real_run = auto_pr.subprocess.run

    def fake_run(command, **kwargs):
        if command[:2] == ["git", "clone"]:
            destination = command[-1]
            import os
            os.makedirs(destination, exist_ok=True)
            with open(os.path.join(destination, "app.py"), "w", encoding="utf-8") as handle:
                handle.write('SECRET = "bad"\n')
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return real_run(command, **kwargs)

    monkeypatch.setattr(auto_pr.subprocess, "run", fake_run)
    result = auto_pr.create_fix_pr(
        github_token="test-token",
        repo_url="https://github.com/owner/repo",
        scan_id="scan_valid",
        allow_untested=True,
        findings=[{
            "vuln_type": "Hardcoded Secrets", "severity": "HIGH", "cvss_score": 7.5,
            "file_path": "app.py", "line_number": 1,
            "vulnerable_code": 'SECRET = "bad"',
            "fixed_code": 'SECRET = os.environ.get("SECRET")', "source": "bandit",
        }],
    )

    assert result["success"] is True
    assert repo.branch_created is True
    assert repo.updated_content == 'import os\n\nSECRET = os.environ.get("SECRET")\n'
    assert result["validation_details"][-1]["status"] == "tests_not_available"
