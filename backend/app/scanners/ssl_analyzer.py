"""
SSL/TLS Analyzer
Checks certificate validity and negotiated TLS version using Python's
built-in ssl module -- no external tool dependency (testssl.sh would
require WSL/bash on Windows, which is unnecessary complexity for what
we actually need to check).
"""

import ssl
import socket
import datetime
from app.utils.logger import get_logger

logger = get_logger("ssl_analyzer")

# TLS versions considered insecure/deprecated
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def analyze_ssl(target: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Connect to target:port and inspect the SSL/TLS certificate + protocol version.

    Returns:
        {
            "target": str,
            "ssl_available": bool,
            "tls_version": str | None,
            "cert_expired": bool | None,
            "cert_expires": str | None,
            "cert_self_signed": bool | None,
            "findings": [{"issue": str, "severity": str, "recommendation": str}],
            "error": str | None
        }
    """
    findings = []

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # we want to inspect even invalid certs, not reject the connection

    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                tls_version = ssock.version()
                cert = ssock.getpeercert()

    except (socket.timeout, ConnectionRefusedError, socket.gaierror) as e:
        logger.warning(f"Could not establish SSL connection to {target}:{port} -- {e}")
        return {
            "target": target, "ssl_available": False, "tls_version": None,
            "cert_expired": None, "cert_expires": None, "cert_self_signed": None,
            "findings": [], "error": f"Connection failed: {e}"
        }
    except ssl.SSLError as e:
        logger.warning(f"SSL handshake failed for {target}:{port} -- {e}")
        return {
            "target": target, "ssl_available": False, "tls_version": None,
            "cert_expired": None, "cert_expires": None, "cert_self_signed": None,
            "findings": [], "error": f"SSL handshake failed: {e}"
        }

    # Check TLS version
    if tls_version in WEAK_TLS_VERSIONS:
        findings.append({
            "issue": f"Weak TLS version in use: {tls_version}",
            "severity": "HIGH",
            "recommendation": "Disable protocols below TLS 1.2 on the server."
        })

    # Check certificate expiration
    cert_expired = None
    cert_expires_str = None
    if cert and "notAfter" in cert:
        expire_date = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        cert_expires_str = expire_date.isoformat()
        cert_expired = expire_date < datetime.datetime.utcnow()
        if cert_expired:
            findings.append({
                "issue": f"SSL certificate expired on {cert_expires_str}",
                "severity": "CRITICAL",
                "recommendation": "Renew the SSL certificate immediately."
            })
        else:
            days_remaining = (expire_date - datetime.datetime.utcnow()).days
            if days_remaining < 30:
                findings.append({
                    "issue": f"SSL certificate expires soon ({days_remaining} days remaining)",
                    "severity": "MEDIUM",
                    "recommendation": "Renew the SSL certificate before it expires."
                })

    # Rough self-signed check: issuer == subject means it signed itself
    cert_self_signed = None
    if cert and "issuer" in cert and "subject" in cert:
        cert_self_signed = cert["issuer"] == cert["subject"]
        if cert_self_signed:
            findings.append({
                "issue": "Certificate appears to be self-signed",
                "severity": "MEDIUM",
                "recommendation": "Use a certificate from a trusted CA (e.g. Let's Encrypt) for production."
            })

    logger.info(f"SSL analysis of {target}:{port} complete -- {len(findings)} findings")

    return {
        "target": target,
        "ssl_available": True,
        "tls_version": tls_version,
        "cert_expired": cert_expired,
        "cert_expires": cert_expires_str,
        "cert_self_signed": cert_self_signed,
        "findings": findings,
        "error": None
    }