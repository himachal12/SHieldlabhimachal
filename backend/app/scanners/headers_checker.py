"""
Security Headers Checker
Makes an HTTP(S) request to a target and checks for the presence of
standard security headers.
"""

import requests
from app.utils.logger import get_logger

logger = get_logger("headers_checker")

# header_name -> (severity if missing, recommendation)
REQUIRED_HEADERS = {
    "Content-Security-Policy": ("MEDIUM", "Add a CSP header to mitigate XSS by restricting script sources."),
    "X-Frame-Options": ("MEDIUM", "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking."),
    "X-Content-Type-Options": ("LOW", "Add X-Content-Type-Options: nosniff to prevent MIME-sniffing attacks."),
    "Strict-Transport-Security": ("HIGH", "Add HSTS header to force HTTPS and prevent downgrade attacks."),
    "Referrer-Policy": ("LOW", "Add a Referrer-Policy header to control referrer information leakage."),
}


def check_headers(target: str, timeout: int = 10) -> dict:
    """
    Request the target over HTTPS (falling back to HTTP if HTTPS fails)
    and check for standard security headers.

    Returns:
        {
            "target": str,
            "reachable": bool,
            "scheme_used": str | None,
            "findings": [{"issue": str, "severity": str, "recommendation": str}],
            "error": str | None
        }
    """
    url_https = f"https://{target}"
    url_http = f"http://{target}"

    response = None
    scheme_used = None

    for url, scheme in [(url_https, "https"), (url_http, "http")]:
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True,
                                     headers={"User-Agent": "ShieldLabs-Scanner/1.0"})
            scheme_used = scheme
            break
        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not reach {url}: {e}")
            continue

    if response is None:
        return {
            "target": target, "reachable": False, "scheme_used": None,
            "findings": [], "error": "Could not reach target over HTTPS or HTTP"
        }

    findings = []
    headers_present = {h.lower() for h in response.headers.keys()}

    for header_name, (severity, recommendation) in REQUIRED_HEADERS.items():
        if header_name.lower() not in headers_present:
            findings.append({
                "issue": f"Missing {header_name} header",
                "severity": severity,
                "recommendation": recommendation
            })

    if scheme_used == "http":
        findings.append({
            "issue": "Site is served over plain HTTP, not HTTPS",
            "severity": "HIGH",
            "recommendation": "Migrate to HTTPS and redirect all HTTP traffic to HTTPS."
        })

    logger.info(f"Headers check of {target}: {len(findings)} missing/issues found (scheme={scheme_used})")

    return {
        "target": target,
        "reachable": True,
        "scheme_used": scheme_used,
        "findings": findings,
        "error": None
    }