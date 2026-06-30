"""
Port Scanner
Wraps Nmap CLI, runs version detection against a target, returns structured JSON.

Uses python-nmap-style raw XML parsing via Nmap's own -oX (XML output) rather
than -f json, because Nmap's JSON support is inconsistent across versions --
XML output has been stable for 20+ years and is what every serious wrapper uses.
"""

import subprocess
import shutil
import xml.etree.ElementTree as ET
from app.utils.logger import get_logger

logger = get_logger("port_scanner")

# Resolve nmap path once at import time -- prefer PATH, fall back to common
# Windows install location if PATH lookup fails (Application Control workaround)
_NMAP_PATH = shutil.which("nmap") or r"C:\Program Files (x86)\Nmap\nmap.exe"

# Ports we care about for a web-app security context -- not scanning all 65535,
# that's slow and mostly irrelevant for "is this startup's web app exposed"
COMMON_WEB_PORTS = "21,22,23,25,53,80,110,143,443,445,1433,3000,3306,3389,5000,5432,5984,6379,8000,8080,8443,9200,27017"


def is_nmap_available() -> bool:
    """Check whether nmap is reachable before attempting a scan."""
    try:
        result = subprocess.run([_NMAP_PATH, "--version"], capture_output=True, timeout=10)
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def scan_ports(target: str, ports: str = COMMON_WEB_PORTS, timeout: int = 60) -> dict:
    """
    Run an Nmap service-detection scan against a target.

    Args:
        target: domain or IP to scan
        ports: comma-separated port list (default: common web/db/app ports)
        timeout: max seconds before giving up

    Returns:
        {
            "target": str,
            "host_up": bool,
            "ports": [{"port": int, "state": str, "service": str, "version": str}],
            "error": str | None
        }
    """
    if not is_nmap_available():
        logger.error("nmap is not available -- check install path / Windows Application Control settings")
        return {"target": target, "host_up": False, "ports": [], "error": "nmap not available"}

    try:
        # -sV = version detection, -p = port list, -oX - = XML output to stdout,
        # -T4 = faster timing template (safe for testing, not stealthy -- fine for our use case),
        # --open = only report open ports, reduces noise
        result = subprocess.run(
            [_NMAP_PATH, "-sV", "-p", ports, "-T4", "--open", "-oX", "-", target],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if not result.stdout:
            logger.warning(f"Nmap produced no output. stderr: {result.stderr[:300]}")
            return {"target": target, "host_up": False, "ports": [], "error": "no output from nmap"}

        return _parse_nmap_xml(result.stdout, target)

    except subprocess.TimeoutExpired:
        logger.error(f"Nmap scan timed out after {timeout}s on {target}")
        return {"target": target, "host_up": False, "ports": [], "error": f"scan timed out after {timeout}s"}
    except Exception as e:
        logger.error(f"Nmap scan failed on {target}: {e}")
        return {"target": target, "host_up": False, "ports": [], "error": str(e)}


def _parse_nmap_xml(xml_output: str, target: str) -> dict:
    """Parse Nmap's XML output into our structured format."""
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        logger.error(f"Could not parse nmap XML output: {e}")
        return {"target": target, "host_up": False, "ports": [], "error": "XML parse error"}

    host = root.find("host")
    if host is None:
        # Host didn't respond / is down / blocked all probes
        return {"target": target, "host_up": False, "ports": [], "error": None}

    ports_found = []
    ports_elem = host.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue  # we already filter with --open, but double-check

            service_elem = port_elem.find("service")
            service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "") if service_elem is not None else ""
            version = service_elem.get("version", "") if service_elem is not None else ""
            version_str = f"{product} {version}".strip() or "unknown version"

            ports_found.append({
                "port": int(port_elem.get("portid")),
                "protocol": port_elem.get("protocol"),
                "state": "open",
                "service": service_name,
                "version": version_str
            })

    logger.info(f"Nmap scan of {target}: {len(ports_found)} open ports found")
    return {"target": target, "host_up": True, "ports": ports_found, "error": None}