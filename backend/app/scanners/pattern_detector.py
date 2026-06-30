"""
Custom Pattern Detector
Covers the vulnerability categories that generic SAST tools (like Bandit)
don't check, because they require understanding app-level architecture
(routing, auth, headers) rather than generic AST antipatterns.

These are regex-based and intentionally scoped for Flask apps -- good
enough for the hackathon demo, not a production-grade ruleset. Each
detector notes its known limitations.
"""

import re
from app.utils.logger import get_logger

logger = get_logger("pattern_detector")


def _line_number(source: str, match_start: int) -> int:
    """Convert a regex match position into a 1-indexed line number."""
    return source[:match_start].count("\n") + 1


def detect_missing_csrf(file_path: str, source: str) -> list[dict]:
    """
    Flag state-changing routes (POST/PUT/DELETE) when no CSRF protection
    library (Flask-WTF's CSRFProtect) is present anywhere in the file.

    LIMITATION: file-level check, not route-level. A route-level check would
    need to trace whether THIS SPECIFIC route is exempted or protected,
    which requires more context than regex gives us cleanly.
    """
    findings = []
    has_csrf_lib = "csrf" in source.lower() or "CSRFProtect" in source

    route_pattern = re.compile(
        r"@app\.route\([^)]*methods\s*=\s*\[([^\]]*)\][^)]*\)\s*\ndef\s+(\w+)"
    )

    for match in route_pattern.finditer(source):
        methods = match.group(1)
        func_name = match.group(2)
        is_state_changing = any(
            m.strip().strip("'\"") in ("POST", "PUT", "DELETE")
            for m in methods.split(",")
        )
        if is_state_changing and not has_csrf_lib:
            findings.append({
                "vuln_type": "Missing CSRF Protection",
                "severity": "MEDIUM",
                "file_path": file_path,
                "line_number": _line_number(source, match.start()),
                "description": f"Route '{func_name}' handles {methods.strip()} requests "
                                f"but no CSRF protection (e.g. Flask-WTF CSRFProtect) "
                                f"was found anywhere in this file.",
                "vulnerable_code": match.group(0).split("\n")[0],
                "confidence": 0.6,
                "source": "custom"
            })

    return findings


def detect_weak_jwt(file_path: str, source: str) -> list[dict]:
    """Catch explicit JWT signature-verification bypasses."""
    findings = []
    patterns = [
        (r"jwt\.decode\([^)]*verify\s*=\s*False",
         "JWT signature verification explicitly disabled (verify=False)"),
        (r"options\s*=\s*\{[^}]*['\"]verify_signature['\"]\s*:\s*False",
         "JWT signature verification disabled via options dict"),
        (r"algorithms\s*=\s*\[\s*['\"]none['\"]",
         "JWT 'none' algorithm explicitly allowed -- complete signature bypass"),
    ]
    for pattern, desc in patterns:
        for m in re.finditer(pattern, source, re.IGNORECASE):
            findings.append({
                "vuln_type": "Weak JWT Implementation",
                "severity": "CRITICAL",
                "file_path": file_path,
                "line_number": _line_number(source, m.start()),
                "description": desc,
                "vulnerable_code": m.group(0),
                "confidence": 0.85,
                "source": "custom"
            })
    return findings


def detect_xss_risk(file_path: str, source: str) -> list[dict]:
    """
    Catch template-rendering patterns that bypass Jinja2's default
    autoescaping. Flask autoescapes by default, so plain render_template()
    calls are usually safe -- the risk is when devs explicitly disable that.
    """
    findings = []
    patterns = [
        (r"render_template_string\(\s*f['\"]",
         "User-controllable f-string passed to render_template_string "
         "(potential template injection / XSS)"),
        (r"\|\s*safe\b",
         "Jinja2 '|safe' filter disables autoescaping for this value -- "
         "XSS risk if it ever contains user input"),
        (r"Markup\(\s*f['\"]",
         "Markup() wrapping an f-string bypasses autoescaping and can "
         "enable XSS if user input is included"),
    ]
    for pattern, desc in patterns:
        for m in re.finditer(pattern, source):
            findings.append({
                "vuln_type": "XSS Vulnerabilities",
                "severity": "HIGH",
                "file_path": file_path,
                "line_number": _line_number(source, m.start()),
                "description": desc,
                "vulnerable_code": m.group(0),
                "confidence": 0.55,
                "source": "custom"
            })
    return findings


def detect_missing_security_headers(file_path: str, source: str) -> list[dict]:
    """File-level check: does this Flask app configure security headers anywhere?"""
    is_flask_app = "Flask(__name__)" in source or "from flask import" in source
    if not is_flask_app:
        return []

    has_talisman = "flask_talisman" in source or "Talisman(" in source
    has_manual_headers = (
        "@app.after_request" in source and "X-Frame-Options" in source
    )

    if has_talisman or has_manual_headers:
        return []

    return [{
        "vuln_type": "Missing Security Headers",
        "severity": "MEDIUM",
        "file_path": file_path,
        "line_number": 1,
        "description": "No security headers (Content-Security-Policy, "
                        "X-Frame-Options, HSTS) configured. Consider "
                        "flask-talisman or an @app.after_request handler.",
        "vulnerable_code": None,
        "confidence": 0.5,
        "source": "custom"
    }]


def detect_missing_rate_limiting(file_path: str, source: str) -> list[dict]:
    """File-level check: any rate-limiting library present?"""
    is_flask_app = "Flask(__name__)" in source
    if not is_flask_app:
        return []

    has_limiter = (
        "flask_limiter" in source or "Limiter(" in source or "@limiter.limit" in source
    )
    if has_limiter:
        return []

    return [{
        "vuln_type": "Missing Rate Limiting",
        "severity": "LOW",
        "file_path": file_path,
        "line_number": 1,
        "description": "No rate-limiting library (e.g. flask-limiter) detected. "
                        "Auth/login-style endpoints are vulnerable to brute force.",
        "vulnerable_code": None,
        "confidence": 0.4,
        "source": "custom"
    }]


def detect_unvalidated_redirects(file_path: str, source: str) -> list[dict]:
    """Catch redirect() targets taken directly from request params with no allowlist check."""
    findings = []
    pattern = re.compile(r"redirect\(\s*request\.(args|form|values)\.get\(['\"](\w+)['\"]\)")

    for m in pattern.finditer(source):
        findings.append({
            "vuln_type": "Unvalidated Redirects",
            "severity": "MEDIUM",
            "file_path": file_path,
            "line_number": _line_number(source, m.start()),
            "description": f"redirect() target comes directly from user-controlled "
                            f"input ('{m.group(2)}') with no allowlist/domain validation.",
            "vulnerable_code": m.group(0),
            "confidence": 0.8,
            "source": "custom"
        })
    return findings


# All custom detectors, run in sequence by the orchestrator
ALL_DETECTORS = [
    detect_missing_csrf,
    detect_weak_jwt,
    detect_xss_risk,
    detect_missing_security_headers,
    detect_missing_rate_limiting,
    detect_unvalidated_redirects,
]