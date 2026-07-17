"""Tests for source-aware, conservative LLM fix generation."""

import sys
from types import ModuleType


if "requests" not in sys.modules:
    requests_stub = ModuleType("requests")
    requests_stub.exceptions = type("Exceptions", (), {
        "Timeout": Exception,
        "ConnectionError": Exception,
    })
    sys.modules["requests"] = requests_stub

if "groq" not in sys.modules:
    groq_stub = ModuleType("groq")
    groq_stub.Groq = lambda **kwargs: None
    sys.modules["groq"] = groq_stub

from app.agents.fix_generation import PATCH_SYSTEM_PROMPT, generate_fix


def test_llm_fix_receives_source_context_and_patch_system_prompt(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "import os\n\n"
        "def lookup(user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )
    captured = {}

    def fake_ollama(prompt, **kwargs):
        captured["prompt"] = prompt
        captured["system_prompt"] = kwargs["system_prompt"]
        return (
            '{"fixed_code": "query = \\"SELECT * FROM users WHERE id = ?\\"", '
            '"why_vulnerable": "Untrusted input reaches SQL.", '
            '"why_fix_works": "A bound parameter prevents injection.", '
            '"remediation_time": "15 minutes"}'
        )

    monkeypatch.setattr("app.agents.fix_generation.ollama_call", fake_ollama)

    result = generate_fix({
        "vuln_type": "SQL Injection",
        "vulnerable_code": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        "file_path": str(source),
        "line_number": 4,
    })

    assert result["fix_source"] == "llm_generated"
    assert captured["system_prompt"] == PATCH_SYSTEM_PROMPT
    assert "FILE IMPORTS:\nimport os" in captured["prompt"]
    assert "def lookup(user_id):" in captured["prompt"]


def test_empty_llm_patch_is_marked_for_manual_review(monkeypatch):
    monkeypatch.setattr(
        "app.agents.fix_generation.ollama_call",
        lambda prompt, **kwargs: (
            '{"fixed_code": "", "why_vulnerable": "Risk.", '
            '"why_fix_works": "Broader context is required.", '
            '"remediation_time": "1 hour"}'
        ),
    )

    result = generate_fix({
        "vuln_type": "SQL Injection",
        "vulnerable_code": "query = build_query(user_input)",
    })

    assert result["fixed_code"] is None
    assert result["fix_source"] == "manual_review_required"
    assert result["remediation_time"] == "Manual review required"
