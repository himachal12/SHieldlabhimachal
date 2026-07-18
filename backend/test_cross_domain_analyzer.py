import sys
from types import ModuleType

if "requests" not in sys.modules:
    requests_stub = ModuleType("requests")
    requests_stub.post = lambda *args, **kwargs: None
    requests_stub.exceptions = type("exceptions", (), {"Timeout": TimeoutError, "ConnectionError": ConnectionError})
    sys.modules["requests"] = requests_stub

if "groq" not in sys.modules:
    groq_stub = ModuleType("groq")

    class Groq:  # pragma: no cover - import stub only
        def __init__(self, *args, **kwargs):
            pass

    groq_stub.Groq = Groq
    sys.modules["groq"] = groq_stub

import json

from app.agents import cross_domain_analyzer as analyzer


def test_finding_evidence_for_code_finding_includes_location_and_code():
    evidence = analyzer._finding_evidence({
        "finding_id": "find_1",
        "vuln_type": "Hardcoded Secrets",
        "source": "code_scanner",
        "file_path": "app.py",
        "line_number": 15,
        "vulnerable_code": 'SECRET_KEY = "supersecretkey123"',
        "confidence": 0.95,
    })

    assert evidence["scanner_family"] == "code"
    assert evidence["location"] == "app.py:15"
    assert evidence["scan_mode"] == "code"
    assert evidence["vulnerable_code"] == 'SECRET_KEY = "supersecretkey123"'
    assert evidence["fix_available"] is False


def test_finding_evidence_for_web_finding_includes_url_and_scan_mode():
    evidence = analyzer._finding_evidence({
        "finding_id": "find_2",
        "vuln_type": "Exposed Sensitive Files",
        "source": "exposed_files_checker",
        "url": "http://localhost:5000/.env",
        "scan_mode": "passive",
    })

    assert evidence["scanner_family"] == "web"
    assert evidence["location"] == "http://localhost:5000/.env"
    assert evidence["scan_mode"] == "passive"
    assert evidence["source"] == "exposed_files_checker"


def test_analyze_pair_returns_rich_chain(monkeypatch):
    payload = {
        "compounds": True,
        "attack_chain": ["Step 1: Read exposed .env"],
        "attack_steps": [{
            "step": 1,
            "title": "Read exposed environment file",
            "description": "Attacker accesses the exposed .env file.",
            "uses_finding_ids": ["find_web"],
            "source": "exposed_files_checker",
            "location": "http://localhost:5000/.env",
            "scanner_family": "web",
        }],
        "compounded_severity": "CRITICAL",
        "time_to_exploit": "less than 30 minutes",
        "impact": "Secrets can be reused to access protected data.",
        "reasoning": "Both findings expose credential material.",
        "confidence": "high",
        "priority_rationale": "Credential exposure should be fixed first.",
        "recommended_fix_order": ["Block /.env", "Rotate secrets"],
    }
    monkeypatch.setattr(analyzer, "groq_call", lambda prompt: json.dumps(payload))

    chain = analyzer._analyze_pair(
        {
            "finding_id": "find_code",
            "vuln_type": "Hardcoded Secrets",
            "source": "code_scanner",
            "file_path": "app.py",
            "line_number": 15,
            "vulnerable_code": 'SECRET_KEY = "supersecretkey123"',
        },
        {
            "finding_id": "find_web",
            "vuln_type": "Exposed Sensitive Files",
            "source": "exposed_files_checker",
            "url": "http://localhost:5000/.env",
            "scan_mode": "passive",
        },
    )

    assert chain["finding_ids"] == ["find_code", "find_web"]
    assert chain["evidence"][0]["location"] == "app.py:15"
    assert chain["attack_steps"][0]["uses_finding_ids"] == ["find_web"]
    assert chain["source_summary"]["evidence_type"] == "mixed"
    assert chain["recommended_fix_order"] == ["Block /.env", "Rotate secrets"]


def test_ensure_finding_ids_assigns_unique_ids():
    findings = [{"vuln_type": "Hardcoded Secrets"}, {"vuln_type": "Exposed Sensitive Files"}]

    analyzer.ensure_finding_ids(findings)

    assert all(finding.get("finding_id") for finding in findings)
    assert findings[0]["finding_id"] != findings[1]["finding_id"]


def test_dedupe_for_chain_analysis_keeps_highest_confidence_duplicate():
    low_confidence_duplicate = {
        "finding_id": "finding_low11111",
        "vuln_type": "Hardcoded Secrets",
        "source": "bandit",
        "file_path": "app.py",
        "line_number": 10,
        "vulnerable_code": 'API_KEY = "secret"',
        "description": "Possible hardcoded secret",
        "confidence": 0.4,
    }
    high_confidence_duplicate = {
        "finding_id": "finding_high2222",
        "vuln_type": "Hardcoded Secrets",
        "source": "custom",
        "file_path": "app.py",
        "line_number": 9,
        "vulnerable_code": 'API_KEY = "secret"',
        "description": "Custom detector reports the same secret on an adjacent line",
        "confidence": 0.95,
    }
    web_finding = {
        "finding_id": "finding_web33333",
        "vuln_type": "Exposed Sensitive Files",
        "source": "exposed_files_checker",
        "url": "https://example.test/.env",
    }
    original_findings = [low_confidence_duplicate, high_confidence_duplicate, web_finding]

    deduped = analyzer._dedupe_for_chain_analysis(original_findings)

    assert len(original_findings) == 3
    assert len(deduped) == 2
    assert deduped[0] is high_confidence_duplicate
    assert deduped[1] is web_finding


def test_analyze_attack_chains_dedupes_before_pair_analysis(monkeypatch):
    pairs = []

    def fake_analyze_pair(code_finding, web_finding):
        pairs.append((code_finding["finding_id"], web_finding["finding_id"]))
        return {
            "chain_id": "chain_test",
            "finding_ids": [code_finding["finding_id"], web_finding["finding_id"]],
            "finding_types": [code_finding["vuln_type"], web_finding["vuln_type"]],
            "severity": "CRITICAL",
            "attack_chain": [],
            "attack_steps": [],
            "evidence": [],
            "source_summary": {},
            "time_to_exploit": "unknown",
            "impact": "",
            "reasoning": "",
            "confidence": "high",
            "priority_rationale": "",
            "recommended_fix_order": [],
        }

    monkeypatch.setattr(analyzer, "_analyze_pair", fake_analyze_pair)

    findings = [
        {
            "finding_id": "finding_low11111",
            "vuln_type": "Hardcoded Secrets",
            "source": "bandit",
            "file_path": "app.py",
            "line_number": 10,
            "vulnerable_code": 'API_KEY = "secret"',
            "description": "Possible hardcoded secret",
            "confidence": 0.4,
        },
        {
            "finding_id": "finding_high2222",
            "vuln_type": "Hardcoded Secrets",
            "source": "custom",
            "file_path": "app.py",
            "line_number": 9,
            "vulnerable_code": 'API_KEY = "secret"',
            "description": "Custom detector reports the same secret on an adjacent line",
            "confidence": 0.95,
        },
        {
            "finding_id": "finding_web33333",
            "vuln_type": "Exposed Sensitive Files",
            "source": "exposed_files_checker",
            "url": "https://example.test/.env",
        },
    ]

    chains = analyzer.analyze_attack_chains(findings)

    assert len(chains) == 1
    assert pairs == [("finding_high2222", "finding_web33333")]
    assert len(findings) == 3


def test_humanize_fix_order_strips_raw_finding_ids_from_chain_output(monkeypatch):
    payload = {
        "compounds": True,
        "attack_chain": ["Step 1: Read exposed .env"],
        "attack_steps": [],
        "compounded_severity": "CRITICAL",
        "recommended_fix_order": [
            "Fix finding_1234abcd first by blocking /.env",
            "Then rotate secrets for finding_deadbeef.",
            "finding_cafebabe - Remove hardcoded credentials",
        ],
    }
    monkeypatch.setattr(analyzer, "groq_call", lambda prompt: json.dumps(payload))

    chain = analyzer._analyze_pair(
        {
            "finding_id": "finding_1234abcd",
            "vuln_type": "Hardcoded Secrets",
            "source": "code_scanner",
            "file_path": "app.py",
            "line_number": 15,
        },
        {
            "finding_id": "finding_deadbeef",
            "vuln_type": "Exposed Sensitive Files",
            "source": "exposed_files_checker",
            "url": "http://localhost:5000/.env",
        },
    )

    assert chain["recommended_fix_order"] == [
        "Fix first by blocking /.env",
        "Then rotate secrets.",
        "Remove hardcoded credentials",
    ]
    assert all("finding_" not in item for item in chain["recommended_fix_order"])
