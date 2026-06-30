"""
Static Remediation Guides
For architectural findings where there's no single code snippet to "fix" --
the remediation is "add this piece of infrastructure to your app."
These are pre-written, not LLM-generated, because they're standard advice
that doesn't vary per-finding the way a code fix does.
"""

REMEDIATION_GUIDES = {
    "Missing CSRF Protection": {
        "fix_explanation": (
            "Install Flask-WTF and enable CSRFProtect globally: "
            "`from flask_wtf import CSRFProtect; CSRFProtect(app)`. "
            "Then ensure all POST/PUT/DELETE forms include the CSRF token "
            "(`{{ csrf_token() }}` in templates, or the X-CSRFToken header for AJAX/JSON requests)."
        ),
        "remediation_time": "30 minutes",
    },
    "Missing Security Headers": {
        "fix_explanation": (
            "Install flask-talisman and apply it globally: "
            "`from flask_talisman import Talisman; Talisman(app)`. "
            "This adds Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, "
            "and Strict-Transport-Security headers automatically to every response. "
            "For finer control, configure each header manually via an @app.after_request handler."
        ),
        "remediation_time": "20 minutes",
    },
    "Missing Rate Limiting": {
        "fix_explanation": (
            "Install flask-limiter and apply limits to sensitive endpoints "
            "(especially login/register/password-reset): "
            "`from flask_limiter import Limiter; limiter = Limiter(app, key_func=get_remote_address)` "
            "then decorate routes with `@limiter.limit(\"5 per minute\")`."
        ),
        "remediation_time": "30 minutes",
    },
    "Insecure Configuration": {
        "fix_explanation": (
            "Set `debug=False` in production, and load the debug flag from an "
            "environment variable instead of hardcoding it: "
            "`app.run(debug=os.environ.get('FLASK_DEBUG', 'False') == 'True')`. "
            "Debug mode exposes a Python console via the Werkzeug debugger that allows "
            "remote code execution if reachable by an attacker."
        ),
        "remediation_time": "5 minutes",
    },
}


def get_remediation_guide(vuln_type: str) -> dict | None:
    """Return the static guide dict for an architectural finding."""
    return REMEDIATION_GUIDES.get(vuln_type)