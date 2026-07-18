"""
Web Scanner Orchestrator
Two scan modes:
  passive (default) — safe recon, headers, SSL, Nuclei templates
  active (opt-in)   — adds sqlmap SQLi confirmation testing

ACTIVE MODE REQUIRES EXPLICIT USER CONSENT RECORDED BEFORE CALLING.
The consent_confirmed parameter enforces this at the code level.
"""

from app.scanners.port_scanner import scan_ports
from app.scanners.ssl_analyzer import analyze_ssl
from app.scanners.headers_checker import check_headers
from app.scanners.nuclei_runner import run_nuclei, is_nuclei_available
from app.scanners.exposed_files import check_exposed_files
from app.config import settings, ScanMode
from app.utils.logger import get_logger

logger = get_logger("web_scanner")

SENSITIVE_PORTS = {
    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
    5984: "CouchDB", 9200: "Elasticsearch", 1433: "MSSQL", 3389: "RDP"
}


def scan_web_target(
    target: str,
    scan_mode: ScanMode = ScanMode.PASSIVE,
    consent_confirmed: bool = False,
    active_urls: list[str] = None
) -> list[dict]:
    """
    Run web scanning pipeline against a target.

    Args:
        target:            Domain or IP to scan
        scan_mode:         PASSIVE (default) or ACTIVE (opt-in)
        consent_confirmed: MUST be True to run active mode.
                           Prevents accidental active scanning.
        active_urls:       Specific URLs with params to test with sqlmap
                           e.g. ["http://target.com/search?q=test"]
                           Required for active mode to know WHAT to test.

    Returns:
        List of findings in standard format
    """
    findings = []
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]

    # =========================================================
    # ACTIVE MODE SAFETY GATE
    # =========================================================
    if scan_mode == ScanMode.ACTIVE:
        if not consent_confirmed:
            logger.error(
                "Active scan requested but consent_confirmed=False. "
                "Refusing to run active scan without explicit consent. "
                "Falling back to passive mode."
            )
            scan_mode = ScanMode.PASSIVE  # Hard fallback -- never exploit without consent
        else:
            logger.warning(
                f"[ACTIVE SCAN MODE] User consent confirmed. "
                f"Running active testing on {clean_target}. "
                f"This sends real attack payloads to the target."
            )

    # =========================================================
    # PASSIVE SCANNING (always runs, regardless of mode)
    # =========================================================

    logger.info(f"[PASSIVE] Port scanning {clean_target}...")
    port_result = scan_ports(clean_target)
    for p in port_result.get("ports", []):
        port_num = p["port"]
        if port_num in SENSITIVE_PORTS:
            findings.append({
                "vuln_type": "Exposed Database/Service",
                "severity": "CRITICAL",
                "description": (
                    f"{SENSITIVE_PORTS[port_num]} is exposed on port {port_num} "
                    f"({p['service']}, {p['version']}). Databases should never be "
                    "directly accessible from the public internet."
                ),
                "url": clean_target,
                "port": port_num,
                "confidence": 0.9,
                "source": "nmap",
                "scan_mode": "passive"
            })
        else:
            findings.append({
                "vuln_type": "Open Port",
                "severity": "LOW",
                "description": f"Port {port_num} open: {p['service']} ({p['version']})",
                "url": clean_target,
                "port": port_num,
                "confidence": 0.95,
                "source": "nmap",
                "scan_mode": "passive"
            })

    logger.info(f"[PASSIVE] Checking exposed files...")
    for f in check_exposed_files(clean_target):
        f["scan_mode"] = "passive"
        findings.append(f)

    logger.info(f"[PASSIVE] Analyzing SSL/TLS...")
    ssl_result = analyze_ssl(clean_target)
    for f in ssl_result.get("findings", []):
        findings.append({
            "vuln_type": "SSL/TLS Misconfiguration",
            "severity": f["severity"],
            "description": f["issue"],
            "url": clean_target,
            "confidence": 0.85,
            "source": "ssl_analyzer",
            "scan_mode": "passive",
            "remediation_hint": f["recommendation"]
        })

    logger.info(f"[PASSIVE] Checking security headers...")
    headers_result = check_headers(clean_target)
    for f in headers_result.get("findings", []):
        findings.append({
            "vuln_type": "Missing Security Headers",
            "severity": f["severity"],
            "description": f["issue"],
            "url": clean_target,
            "confidence": 0.95,
            "source": "headers_checker",
            "scan_mode": "passive",
            "remediation_hint": f.get("recommendation")
        })

    if is_nuclei_available():
        logger.info(f"[PASSIVE] Running Nuclei templates...")
        for f in run_nuclei(clean_target):
            f["scan_mode"] = "passive"
            findings.append(f)
    else:
        logger.warning("Nuclei not available -- skipping template scan")

    # =========================================================
    # ACTIVE SCANNING (ONLY if consent confirmed)
    # =========================================================
    if scan_mode == ScanMode.ACTIVE and consent_confirmed:
        from app.scanners.sqlmap_runner import extract_query_params, get_sqlmap_unavailable_reason, run_sqlmap_active

        if not active_urls:
            logger.warning(
                "[ACTIVE] SQLMap skipped: no active URLs were provided. "
                "Provide active_urls with URLs that include query parameters."
            )
        else:
            unavailable_reason = get_sqlmap_unavailable_reason()
            if unavailable_reason:
                logger.warning(f"[ACTIVE] SQLMap skipped: {unavailable_reason}")
            else:
                logger.info(f"[ACTIVE] Running SQLMap on {len(active_urls)} URL(s)...")
                for url in active_urls:
                    sqlmap_findings = run_sqlmap_active(
                        target_url=url,
                        params=extract_query_params(url),
                        max_requests=settings.SQLMAP_MAX_REQUESTS
                    )
                    for f in sqlmap_findings:
                        f["scan_mode"] = "active"
                        findings.append(f)

        # Summary of active scan
        active_count = sum(1 for f in findings if f.get("scan_mode") == "active")
        logger.info(f"[ACTIVE] Active scan complete: {active_count} additional findings")

    passive_count = sum(1 for f in findings if f.get("scan_mode") == "passive")
    active_count = sum(1 for f in findings if f.get("scan_mode") == "active")
    logger.info(
        f"Web scan complete: {len(findings)} total findings "
        f"({passive_count} passive, {active_count} active)"
    )
    return findings