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
from app.agents.auto_pr import _build_pr_description, _validate_python_patch


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

        def get_branch(self, name):
            return SimpleNamespace(commit=SimpleNamespace(sha="abc123"))

        def create_git_ref(self, **kwargs):
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
