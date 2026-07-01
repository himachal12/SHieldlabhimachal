"""
Cross-Domain Analysis Agent
Looks at code findings + web findings together and identifies
attack chains where multiple findings compound into greater risk.

Example:
  Code finding: SQL Injection in /api/search (CVSS 7.5)
  Web finding:  MySQL exposed on port 3306 (CVSS 9.0)

  ATTACK CHAIN:
  Step 1: Attacker finds SQL injection via /api/search
  Step 2: Extracts credentials from database via SQLi
  Step 3: Database also directly accessible on port 3306
  Step 4: Attacker bypasses app entirely, queries DB directly
  COMPOUNDED SEVERITY: CRITICAL (worse than either finding alone)
  TIME TO COMPROMISE: 10 minutes

This is what separates ShieldLabs from "we ran Bandit and Nmap."
"""

import json
import uuid
from app.utils.llm import groq_call
from app.utils.logger import get_logger

logger = get_logger("cross_domain_analyzer")

# Pairs of vuln types that are known to compound risk when found together.
# We use this to PRE-FILTER before sending to Groq -- no point asking
# "do these compound?" for unrelated findings like Missing Rate Limiting + Open Port 80
COMPOUND_PAIRS = [
    # Database exposure compounds with injection vulns
    ({"SQL Injection", "SQL Injection (Confirmed Active)"}, {"Exposed Database/Service"}),
    # Hardcoded secrets compound with exposed config files
    ({"Hardcoded Secrets"}, {"Exposed Sensitive Files"}),
    # Command injection compounds with open ports to internal services
    ({"Command Injection"}, {"Open Port", "Exposed Database/Service"}),
    # Weak auth compounds with anything network-facing
    ({"Weak JWT Implementation", "Missing CSRF Protection"}, {"Open Port", "Exposed Database/Service"}),
    # Insecure deserialization compounds with exposed endpoints
    ({"Insecure Deserialization"}, {"Open Port"}),
    # Missing headers compounds with XSS (makes XSS easier to exploit)
    ({"XSS Vulnerabilities"}, {"Missing Security Headers"}),
    # Default creds compounds with exposed services
    ({"Default Credentials"}, {"Exposed Database/Service", "Open Port"}),
]

CHAIN_ANALYSIS_PROMPT = """You are a penetration tester analyzing how multiple vulnerabilities combine into attack chains.

FINDING 1 (Code):
Type: {type1}
Description: {desc1}
CVSS: {cvss1}

FINDING 2 (Infrastructure/Web):
Type: {type2}
Description: {desc2}
CVSS: {cvss2}

Analyze if these two findings compound into a more severe attack chain.

Respond ONLY with valid JSON, no markdown:
{{
  "compounds": true/false,
  "attack_chain": [
    "Step 1: ...",
    "Step 2: ...",
    "Step 3: ..."
  ],
  "compounded_severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "time_to_exploit": "e.g. 10 minutes",
  "impact": "one sentence describing the worst-case outcome",
  "reasoning": "one sentence explaining why these findings compound"
}}"""


def _findings_could_compound(f1: dict, f2: dict) -> bool:
    """
    Check if two findings match any known compound pair pattern.
    Pre-filters before expensive Groq calls.
    """
    t1 = f1.get("vuln_type", "")
    t2 = f2.get("vuln_type", "")

    for set1, set2 in COMPOUND_PAIRS:
        if (t1 in set1 and t2 in set2) or (t2 in set1 and t1 in set2):
            return True
    return False


def _analyze_pair(f1: dict, f2: dict) -> dict | None:
    """
    Ask Groq whether two findings compound into an attack chain.
    Returns a chain dict if they compound, None if they don't.
    """
    prompt = CHAIN_ANALYSIS_PROMPT.format(
        type1=f1.get("vuln_type", ""),
        desc1=f1.get("description", "")[:200],
        cvss1=f1.get("cvss_score", "unknown"),
        type2=f2.get("vuln_type", ""),
        desc2=f2.get("description", "")[:200],
        cvss2=f2.get("cvss_score", "unknown"),
    )

    response = groq_call(prompt)

    try:
        cleaned = response.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(cleaned)
    except (json.JSONDecodeError, AttributeError):
        logger.warning(f"Could not parse chain analysis response: {response[:150]!r}")
        return None

    if not parsed.get("compounds", False):
        return None

    chain_id = f"chain_{uuid.uuid4().hex[:8]}"
    finding_ids = [
        f1.get("finding_id", f1.get("vuln_type")),
        f2.get("finding_id", f2.get("vuln_type"))
    ]

    return {
        "chain_id": chain_id,
        "finding_ids": finding_ids,
        "finding_types": [f1.get("vuln_type"), f2.get("vuln_type")],
        "severity": parsed.get("compounded_severity", "HIGH"),
        "attack_chain": parsed.get("attack_chain", []),
        "time_to_exploit": parsed.get("time_to_exploit", "unknown"),
        "impact": parsed.get("impact", ""),
        "reasoning": parsed.get("reasoning", ""),
    }


def analyze_attack_chains(findings: list[dict]) -> list[dict]:
    """
    Find all attack chains across a findings list.

    Strategy:
    1. Split findings into code-sourced vs web-sourced
    2. Check all cross-source pairs against COMPOUND_PAIRS filter
    3. Only call Groq for pairs that COULD compound (saves quota)
    4. Return list of confirmed attack chains

    Args:
        findings: Combined list of code + web findings

    Returns:
        List of attack chain dicts
    """
    # Split by source
    code_findings = [
        f for f in findings
        if f.get("source") in {"bandit", "custom", "code_scanner"}
    ]
    web_findings = [
        f for f in findings
        if f.get("source") in {
            "nmap", "ssl_analyzer", "headers_checker",
            "nuclei", "exposed_files_checker", "sqlmap_active"
        }
    ]

    if not code_findings or not web_findings:
        logger.info("No cross-domain pairs to analyze (need both code + web findings)")
        return []

    chains = []
    pairs_checked = 0
    groq_calls_made = 0

    for cf in code_findings:
        for wf in web_findings:
            if not _findings_could_compound(cf, wf):
                continue  # Pre-filter passed -- skip Groq call

            pairs_checked += 1
            logger.info(
                f"Analyzing potential chain: "
                f"{cf.get('vuln_type')} + {wf.get('vuln_type')}"
            )

            chain = _analyze_pair(cf, wf)
            groq_calls_made += 1

            if chain:
                chains.append(chain)
                logger.warning(
                    f"ATTACK CHAIN FOUND: {chain['finding_types']} → "
                    f"{chain['severity']} | {chain['time_to_exploit']}"
                )

    logger.info(
        f"Chain analysis complete: {pairs_checked} pairs checked, "
        f"{groq_calls_made} Groq calls, {len(chains)} chains found"
    )
    return chains