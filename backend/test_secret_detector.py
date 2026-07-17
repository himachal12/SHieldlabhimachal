"""Regression tests for deterministic secret detection and remediation."""

import sys
from types import ModuleType


if "requests" not in sys.modules:
    requests_stub = ModuleType("requests")
    requests_stub.exceptions = type("Exceptions", (), {"Timeout": Exception, "ConnectionError": Exception})
    sys.modules["requests"] = requests_stub

if "groq" not in sys.modules:
    groq_stub = ModuleType("groq")
    groq_stub.Groq = lambda **kwargs: None
    sys.modules["groq"] = groq_stub

if "github" not in sys.modules:
    github_stub = ModuleType("github")
    github_stub.Github = object
    github_stub.GithubException = Exception
    sys.modules["github"] = github_stub

from app.agents.auto_pr import _validate_vulnerability_fix
from app.scanners.pattern_detector import detect_hardcoded_secrets


def test_secret_detector_covers_access_and_payment_key_assignments(tmp_path):
    source = (
        'AWS_ACCESS_KEY = "AKIAIOSFODNN7HARDCODED"\n'
        'STRIPE_KEY = "hardcoded-secret-for-testing"\n'
        'DATABASE_URL = "sqlite:///users.db"\n'
    )

    findings = detect_hardcoded_secrets(str(tmp_path / "settings.py"), source)

    assert [finding["vulnerable_code"] for finding in findings] == [
        'AWS_ACCESS_KEY = "AKIAIOSFODNN7HARDCODED"',
        'STRIPE_KEY = "hardcoded-secret-for-testing"',
    ]


def test_secret_validation_rejects_literal_and_accepts_environment_lookup():
    invalid, invalid_detail = _validate_vulnerability_fix(
        "Hardcoded Secrets", 'API_KEY = "still-exposed"\n'
    )
    valid, valid_detail = _validate_vulnerability_fix(
        "Hardcoded Secrets", 'API_KEY = os.environ["API_KEY"]\n'
    )

    assert invalid is False
    assert invalid_detail["checks"]["secret_literal_removed"] == "failed"
    assert valid is True
    assert valid_detail["checks"] == {
        "secret_literal_removed": "passed",
        "secret_environment_lookup": "passed",
    }
