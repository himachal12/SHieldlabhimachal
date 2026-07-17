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

from app.agents.deterministic_fixes import deterministic_fix
from app.agents.fix_generation import _build_fix_prompt, generate_fix


def test_hardcoded_secret_uses_deterministic_environment_lookup(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("import os\nAPI_KEY = \"secret-value\"\n", encoding="utf-8")
    finding = {
        "vuln_type": "Hardcoded Secrets",
        "vulnerable_code": 'API_KEY = "secret-value"',
        "file_path": str(source),
    }
    monkeypatch.setattr("app.agents.fix_generation.ollama_call", lambda prompt: (_ for _ in ()).throw(AssertionError("LLM should not be called")))

    result = generate_fix(finding)

    assert result["fixed_code"] == 'API_KEY = os.environ.get("API_KEY")'
    assert result["fix_source"] == "deterministic"


def test_redirect_replaces_complete_statement(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "def redirect_user():\n"
        "    return redirect(request.args.get('url'))\n",
        encoding="utf-8",
    )
    finding = {
        "vuln_type": "Unvalidated Redirects",
        "file_path": str(source),
        "line_number": 2,
        "vulnerable_code": "redirect(request.args.get('url'))",
    }

    result = deterministic_fix(finding)

    assert result["vulnerable_code"] == "return redirect(request.args.get('url'))"
    assert "target.startswith('//')" in result["fixed_code"]
    assert result["fix_source"] == "deterministic"


def test_unknown_secret_shape_remains_for_manual_or_llm_handling():
    assert deterministic_fix({
        "vuln_type": "Hardcoded Secrets",
        "vulnerable_code": "config['api_key'] = 'secret'",
    }) is None


def test_secret_without_an_existing_os_import_is_not_auto_rewritten(tmp_path):
    source = tmp_path / "app.py"
    source.write_text('API_KEY = "secret-value"\n', encoding="utf-8")

    assert deterministic_fix({
        "vuln_type": "Hardcoded Secrets",
        "vulnerable_code": 'API_KEY = "secret-value"',
        "file_path": str(source),
    }) is None


def test_llm_prompt_includes_imports_and_enclosing_function(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "import sqlite3\n\n"
        "def lookup(user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    return query\n",
        encoding="utf-8",
    )

    prompt = _build_fix_prompt(
        {
            "file_path": str(source),
            "line_number": 4,
            "vulnerable_code": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        },
        "VULNERABLE CODE:\n{code}",
    )

    assert "FILE IMPORTS:\nimport sqlite3" in prompt
    assert "ENCLOSING FUNCTION:\ndef lookup(user_id):" in prompt
