"""
Exposed Files Detector
Checks for common paths that should NEVER be publicly accessible
but frequently are on misconfigured deployments.
No rate-limiting here since we're just checking specific paths
in sequence, not fuzzing.
"""

import requests
from app.utils.rate_limiter import web_scan_limiter
from app.utils.logger import get_logger

logger = get_logger("exposed_files")

# path -> (vuln_type, severity, description)
SENSITIVE_PATHS = {
    "/.git/config": (
        "Exposed Sensitive Files", "CRITICAL",
        "Git repository configuration file is publicly accessible. "
        "Attackers can reconstruct source code history, exposing all code, "
        "secrets, and commit history."
    ),
    "/.git/HEAD": (
        "Exposed Sensitive Files", "CRITICAL",
        "Git repository HEAD reference exposed, confirming .git directory is accessible."
    ),
    "/.env": (
        "Exposed Sensitive Files", "CRITICAL",
        ".env file is publicly accessible, likely containing database credentials, "
        "API keys, and other secrets."
    ),
    "/.env.local": (
        "Exposed Sensitive Files", "CRITICAL",
        ".env.local file exposed -- likely contains local development secrets."
    ),
    "/.env.production": (
        "Exposed Sensitive Files", "CRITICAL",
        ".env.production file exposed -- likely contains production database credentials and API keys."
    ),
    "/config.php": (
        "Exposed Sensitive Files", "CRITICAL",
        "config.php exposed -- PHP configuration files often contain database credentials."
    ),
    "/wp-config.php.bak": (
        "Exposed Sensitive Files", "CRITICAL",
        "WordPress config backup file exposed -- contains database credentials."
    ),
    "/backup.sql": (
        "Exposed Sensitive Files", "CRITICAL",
        "Database backup file is publicly downloadable."
    ),
    "/db.sqlite": (
        "Exposed Sensitive Files", "CRITICAL",
        "SQLite database file is publicly downloadable."
    ),
    "/docker-compose.yml": (
        "Exposed Sensitive Files", "HIGH",
        "docker-compose.yml exposed -- reveals service architecture, port mapping, "
        "and possibly credentials."
    ),
    "/requirements.txt": (
        "Technology Detection", "LOW",
        "requirements.txt accessible -- reveals Python dependencies and versions "
        "(useful for targeted CVE attacks)."
    ),
    "/package.json": (
        "Technology Detection", "LOW",
        "package.json accessible -- reveals Node.js dependencies and versions."
    ),
    "/.htaccess": (
        "Exposed Sensitive Files", "MEDIUM",
        ".htaccess file exposed -- may reveal URL rewriting rules or access control config."
    ),
    "/server-status": (
        "Insecure Configuration", "MEDIUM",
        "Apache server-status page is accessible -- reveals active connections, "
        "request details, and server load."
    ),
    "/phpinfo.php": (
        "Insecure Configuration", "HIGH",
        "phpinfo() page exposed -- reveals PHP version, loaded extensions, "
        "server environment, and configuration."
    ),
}


def check_exposed_files(target: str, timeout: int = 8) -> list[dict]:
    """
    Check a list of sensitive paths against the target.

    Args:
        target: domain (e.g. "example.com"), no scheme

    Returns:
        List of finding dicts for any accessible sensitive paths
    """
    base_urls = [f"https://{target}", f"http://{target}"]
    findings = []

    # Determine which scheme is live (try HTTPS first)
    base_url = None
    for url in base_urls:
        try:
            web_scan_limiter.wait()
            r = requests.head(url, timeout=timeout, allow_redirects=True,
                              headers={"User-Agent": "ShieldLabs-Scanner/1.0"})
            if r.status_code < 500:
                base_url = url
                break
        except requests.exceptions.RequestException:
            continue

    if not base_url:
        logger.warning(f"Target {target} is not reachable for exposed file check")
        return []

    for path, (vuln_type, severity, description) in SENSITIVE_PATHS.items():
        web_scan_limiter.wait()
        url = f"{base_url}{path}"
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=False,
                             headers={"User-Agent": "ShieldLabs-Scanner/1.0"})

            # 200 = definitely exposed
            # 403 = exists but access denied (still interesting, shows path exists)
            # anything else = probably not there
            if r.status_code == 200:
                findings.append({
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "description": f"[HTTP 200 - CONFIRMED ACCESSIBLE] {description}",
                    "url": url,
                    "confidence": 0.95,
                    "source": "exposed_files_checker"
                })
                logger.warning(f"EXPOSED: {url} (HTTP 200)")

            elif r.status_code == 403:
                # Don't add to findings -- 403 means the path exists but is protected.
                # That's the CORRECT behavior -- not a vulnerability
                logger.debug(f"Path exists but protected: {url} (HTTP 403)")

        except requests.exceptions.RequestException as e:
            logger.debug(f"Request to {url} failed: {e}")
            continue

    logger.info(f"Exposed files check of {target}: {len(findings)} exposed paths found")
    return findings