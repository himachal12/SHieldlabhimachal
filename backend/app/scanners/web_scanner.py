"""
Web Scanner Orchestrator
Runs port scanning + SSL analysis + header checks against a target,
and converts results into our standard finding format (matching the
shape used by code_scanner.py) so downstream code -- severity reasoning,
report generation -- doesn't need to know "web" vs "code" findings apart.
"""

from app.scanners.port_scanner import scan_ports
from app.scanners.ssl_analyzer import analyze_ssl
from app.scanners.headers_checker import check_headers
from app.utils.logger import get_logger

logger = get_logger("web_scanner")

# Ports that are dangerous to have exposed to the public internet at all
SENSITIVE_PORTS = {
    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
    5984: "CouchDB", 9200: "Elasticsearch", 1433: "MSSQL", 3389: "RDP"
}


def scan_web_target(target: str) -> list[dict]:
    """
    Run the full web scanning pipeline against a domain/IP.

    Returns a list of finding dicts in the SAME shape as code_scanner's
    output (vuln_type, severity, description, confidence, source) so
    they can be merged with code findings downstream.
    """
    findings = []

    # --- Port scan ---
    port_result = scan_ports(target)
    if port_result["error"]:
        logger.warning(f"Port scan issue for {target}: {port_result['error']}")
    else:
        for p in port_result["ports"]:
            port_num = p["port"]
            if port_num in SENSITIVE_PORTS:
                findings.append({
                    "vuln_type": "Exposed Database/Service",
                    "severity": "CRITICAL",
                    "description": f"{SENSITIVE_PORTS[port_num]} ({p['service']}, {p['version']}) "
                                    f"is exposed on port {port_num} and reachable from the network.",
                    "url": target,
                    "port": port_num,
                    "confidence": 0.9,
                    "source": "nmap"
                })
            else:
                findings.append({
                    "vuln_type": "Open Port",
                    "severity": "LOW",
                    "description": f"Port {port_num} is open running {p['service']} ({p['version']}).",
                    "url": target,
                    "port": port_num,
                    "confidence": 0.95,
                    "source": "nmap"
                })

    # --- SSL/TLS analysis (only meaningful if port 443 is open, but we try regardless) ---
    ssl_result = analyze_ssl(target)
    if ssl_result["ssl_available"]:
        for f in ssl_result["findings"]:
            findings.append({
                "vuln_type": "SSL/TLS Misconfiguration",
                "severity": f["severity"],
                "description": f["issue"],
                "url": target,
                "confidence": 0.85,
                "source": "ssl_analyzer",
                "remediation_hint": f["recommendation"]
            })

    # --- Security headers ---
    headers_result = check_headers(target)
    if headers_result["reachable"]:
        for f in headers_result["findings"]:
            findings.append({
                "vuln_type": "Missing Security Headers",
                "severity": f["severity"],
                "description": f["issue"],
                "url": target,
                "confidence": 0.95,
                "source": "headers_checker",
                "remediation_hint": f["recommendation"]
            })
    else:
        logger.warning(f"Could not reach {target} over HTTP/HTTPS for header check")

    logger.info(f"Web scan of {target} complete: {len(findings)} total findings")
    return findings