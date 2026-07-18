"""
Cross-Domain Analysis Agent
Looks at code findings + web findings together and identifies
attack chains where multiple findings compound into greater risk.
"""

import json
import re
import uuid
from app.utils.llm import groq_call
from app.utils.logger import get_logger

logger = get_logger("cross_domain_analyzer")

CODE_SOURCES = {"bandit", "custom", "code_scanner", "pattern_detector"}
WEB_SOURCES = {
    "nmap", "ssl_analyzer", "headers_checker",
    "nuclei", "exposed_files_checker", "sqlmap_active",
}

# Pairs of vuln types that are known to compound risk when found together.
COMPOUND_PAIRS = [
    ({"SQL Injection", "SQL Injection (Confirmed Active)"}, {"Exposed Database/Service"}),
    ({"Hardcoded Secrets"}, {"Exposed Sensitive Files"}),
    ({"Command Injection"}, {"Open Port", "Exposed Database/Service"}),
    ({"Weak JWT Implementation", "Missing CSRF Protection"}, {"Open Port", "Exposed Database/Service"}),
    ({"Insecure Deserialization"}, {"Open Port"}),
    ({"XSS Vulnerabilities"}, {"Missing Security Headers"}),
    ({"Default Credentials"}, {"Exposed Database/Service", "Open Port"}),
]

CHAIN_ANALYSIS_PROMPT = """You are a penetration tester analyzing how multiple vulnerabilities combine into attack chains.

Use ONLY the evidence below. Do not invent locations, secrets, URLs, ports, files, scanners, or source code.
Every structured attack step must reference the provided source/location and include uses_finding_ids with at least one listed finding_id.
Recommended fix order items must be human-readable remediation steps and must not include raw internal finding IDs such as finding_1234abcd.
If the evidence is not enough to explain a real chain, return compounds=false.

FINDING 1 EVIDENCE:
- Finding ID: {id1}
- Type: {type1}
- Source scanner: {source1}
- Scanner family: {family1}
- File: {file1}
- Line: {line1}
- URL: {url1}
- Port: {port1}
- Location: {location1}
- Scan mode: {mode1}
- Vulnerable code: {code1}
- Description: {desc1}
- CVSS: {cvss1}
- Confidence: {confidence1}
- Fix available: {fix1}

FINDING 2 EVIDENCE:
- Finding ID: {id2}
- Type: {type2}
- Source scanner: {source2}
- Scanner family: {family2}
- File: {file2}
- Line: {line2}
- URL: {url2}
- Port: {port2}
- Location: {location2}
- Scan mode: {mode2}
- Vulnerable code: {code2}
- Description: {desc2}
- CVSS: {cvss2}
- Confidence: {confidence2}
- Fix available: {fix2}

Analyze if these two findings compound into a more severe attack chain.

Respond ONLY with valid JSON, no markdown:
{{
  "compounds": true/false,
  "attack_chain": [
    "Step 1: ...",
    "Step 2: ...",
    "Step 3: ..."
  ],
  "attack_steps": [
    {{
      "step": 1,
      "title": "short title",
      "description": "what the attacker does using only the evidence above",
      "uses_finding_ids": ["{id1}"],
      "source": "source scanner from evidence",
      "location": "location from evidence",
      "scanner_family": "code|web"
    }}
  ],
  "compounded_severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "time_to_exploit": "e.g. less than 30 minutes",
  "impact": "one sentence describing the worst-case outcome",
  "reasoning": "why these findings compound using the evidence",
  "confidence": "high|medium|low",
  "priority_rationale": "why this chain should be prioritized",
  "recommended_fix_order": ["human-readable first fix with no raw finding IDs", "human-readable second fix with no raw finding IDs"]
}}"""


FINDING_ID_PATTERN = re.compile(r"\bfinding_[0-9a-fA-F]{8,}\b")


def ensure_finding_ids(findings: list[dict]) -> None:
    """Assign stable in-memory finding IDs before chain analysis/persistence."""
    for finding in findings:
        if not finding.get("finding_id"):
            finding["finding_id"] = f"finding_{uuid.uuid4().hex[:8]}"


def _trim(value, limit: int = 500):
    """Return a safe, bounded value for evidence snapshots and prompts."""
    if value is None:
        return None
    text = str(value).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _scanner_family(finding: dict) -> str:
    """Classify a finding as code, web, or unknown evidence."""
    source = finding.get("source")
    if source in CODE_SOURCES or finding.get("file_path") or finding.get("repository_relative_path"):
        return "code"
    if source in WEB_SOURCES or finding.get("url") or finding.get("port") is not None:
        return "web"
    return "unknown"


def _finding_location(finding: dict) -> str:
    """Build a display-ready location from file/line, URL, or port evidence."""
    file_path = finding.get("repository_relative_path") or finding.get("file_path")
    line_number = finding.get("line_number")
    if file_path:
        return f"{file_path}:{line_number}" if line_number else str(file_path)
    if finding.get("url"):
        return str(finding["url"])
    if finding.get("port") is not None:
        return f"Port {finding['port']}"
    return "Location unavailable"


def _finding_evidence(finding: dict) -> dict:
    """Return a bounded, structured snapshot of the finding used by a chain."""
    family = _scanner_family(finding)
    scan_mode = finding.get("scan_mode") or ("code" if family == "code" else "unknown")
    return {
        "finding_id": finding.get("finding_id") or finding.get("vuln_type") or "unknown_finding",
        "vuln_type": finding.get("vuln_type", "Unknown"),
        "source": finding.get("source") or ("code_scanner" if family == "code" else "unknown"),
        "scanner_family": family,
        "severity": finding.get("severity", "MEDIUM"),
        "cvss_score": finding.get("cvss_score"),
        "description": _trim(finding.get("description"), 700) or "",
        "file_path": finding.get("file_path"),
        "repository_relative_path": finding.get("repository_relative_path") or finding.get("file_path"),
        "line_number": finding.get("line_number"),
        "url": finding.get("url"),
        "port": finding.get("port"),
        "location": _finding_location(finding),
        "scan_mode": scan_mode,
        "confidence": finding.get("confidence", 1.0),
        "vulnerable_code": _trim(finding.get("vulnerable_code"), 500),
        "remediation_status": finding.get("remediation_status", "detected"),
        "fix_available": bool(finding.get("fixed_code")),
    }


def _source_summary(evidence: list[dict]) -> dict:
    """Summarize scanner families, sources, scan modes, and locations in a chain."""
    code_sources = sorted({e["source"] for e in evidence if e.get("scanner_family") == "code" and e.get("source")})
    web_sources = sorted({e["source"] for e in evidence if e.get("scanner_family") == "web" and e.get("source")})
    scan_modes = sorted({e["scan_mode"] for e in evidence if e.get("scan_mode")})
    locations = [e["location"] for e in evidence if e.get("location") and e["location"] != "Location unavailable"]
    families = sorted({e.get("scanner_family", "unknown") for e in evidence})
    return {
        "code_sources": code_sources,
        "web_sources": web_sources,
        "scan_modes": scan_modes,
        "locations": locations,
        "evidence_type": "mixed" if len(set(families) - {"unknown"}) > 1 else (families[0] if families else "unknown"),
    }


def _findings_could_compound(f1: dict, f2: dict) -> bool:
    """Check if two findings match any known compound pair pattern."""
    t1 = f1.get("vuln_type", "")
    t2 = f2.get("vuln_type", "")

    for set1, set2 in COMPOUND_PAIRS:
        if (t1 in set1 and t2 in set2) or (t2 in set1 and t1 in set2):
            return True
    return False


def _format_prompt_value(value) -> str:
    if value is None or value == "":
        return "not provided"
    return str(value)


def _confidence_score(finding: dict) -> float:
    """Return a comparable numeric confidence for dedupe preference."""
    confidence = finding.get("confidence", 0)
    if isinstance(confidence, (int, float)):
        return float(confidence)
    if isinstance(confidence, str):
        normalized = confidence.strip().lower()
        labels = {"high": 1.0, "medium": 0.6, "low": 0.3}
        if normalized in labels:
            return labels[normalized]
        try:
            return float(normalized)
        except ValueError:
            return 0.0
    return 0.0


def _chain_dedupe_key(finding: dict) -> tuple:
    """Key findings by vulnerability evidence, ignoring scanner-specific IDs.

    Scanner-overlap reports can point to adjacent lines or use different
    descriptions for the same vulnerable statement. When vulnerable code is
    available, treat file + vulnerability type + normalized code as the source
    of truth so Bandit/custom duplicates collapse for chain generation.
    """
    evidence = _finding_evidence(finding)
    path = evidence.get("repository_relative_path") or evidence.get("file_path") or ""
    code = (evidence.get("vulnerable_code") or "").strip()

    if evidence["scanner_family"] == "code" and code:
        return (
            evidence["scanner_family"],
            evidence["vuln_type"],
            path,
            code,
        )

    return (
        evidence["scanner_family"],
        evidence["vuln_type"],
        path,
        evidence.get("line_number"),
        evidence.get("url") or "",
        evidence.get("port"),
        code,
        (evidence.get("description") or "").strip(),
    )


def _dedupe_for_chain_analysis(findings: list[dict]) -> list[dict]:
    """Collapse duplicate scanner-overlap findings only for chain generation.

    The original findings list is left untouched so every scanner finding can
    still be persisted and displayed in the finding explorer. When two findings
    share the same vulnerability evidence, prefer the highest-confidence one.
    """
    deduped_by_key: dict[tuple, dict] = {}
    order: list[tuple] = []

    for finding in findings:
        key = _chain_dedupe_key(finding)
        existing = deduped_by_key.get(key)
        if existing is None:
            deduped_by_key[key] = finding
            order.append(key)
            continue
        if _confidence_score(finding) > _confidence_score(existing):
            deduped_by_key[key] = finding

    return [deduped_by_key[key] for key in order]


def _humanize_fix_order(fix_order) -> list[str]:
    """Remove internal finding IDs from LLM-produced fix-order text."""
    if isinstance(fix_order, str):
        items = [fix_order]
    elif isinstance(fix_order, list):
        items = fix_order
    else:
        return []

    cleaned_items = []
    for item in items:
        text = str(item).strip()
        if not text:
            continue
        text = FINDING_ID_PATTERN.sub("", text)
        text = re.sub(r"\s+([,.;:])", r"\1", text)
        text = re.sub(r"\(\s*\)", "", text)
        text = re.sub(r"\[\s*\]", "", text)
        text = re.sub(r"\s{2,}", " ", text)
        text = re.sub(r"\b(for|from|in|on|with|of|to)\s*([.;:,]|$)", r"\2", text, flags=re.IGNORECASE)
        text = re.sub(r"\s+([,.;:])", r"\1", text)
        text = re.sub(r"\s+-\s*$", "", text).strip(" -")
        if text:
            cleaned_items.append(text)
    return cleaned_items


def _analyze_pair(f1: dict, f2: dict) -> dict | None:
    """Ask Groq whether two findings compound into an attack chain."""
    evidence = [_finding_evidence(f1), _finding_evidence(f2)]
    e1, e2 = evidence
    prompt = CHAIN_ANALYSIS_PROMPT.format(
        id1=e1["finding_id"], type1=e1["vuln_type"], source1=e1["source"], family1=e1["scanner_family"],
        file1=_format_prompt_value(e1.get("file_path")), line1=_format_prompt_value(e1.get("line_number")),
        url1=_format_prompt_value(e1.get("url")), port1=_format_prompt_value(e1.get("port")),
        location1=e1["location"], mode1=e1["scan_mode"], code1=_format_prompt_value(e1.get("vulnerable_code")),
        desc1=_format_prompt_value(e1.get("description")), cvss1=_format_prompt_value(e1.get("cvss_score")),
        confidence1=_format_prompt_value(e1.get("confidence")), fix1=str(e1.get("fix_available", False)).lower(),
        id2=e2["finding_id"], type2=e2["vuln_type"], source2=e2["source"], family2=e2["scanner_family"],
        file2=_format_prompt_value(e2.get("file_path")), line2=_format_prompt_value(e2.get("line_number")),
        url2=_format_prompt_value(e2.get("url")), port2=_format_prompt_value(e2.get("port")),
        location2=e2["location"], mode2=e2["scan_mode"], code2=_format_prompt_value(e2.get("vulnerable_code")),
        desc2=_format_prompt_value(e2.get("description")), cvss2=_format_prompt_value(e2.get("cvss_score")),
        confidence2=_format_prompt_value(e2.get("confidence")), fix2=str(e2.get("fix_available", False)).lower(),
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

    finding_ids = [e1["finding_id"], e2["finding_id"]]
    return {
        "chain_id": f"chain_{uuid.uuid4().hex[:8]}",
        "finding_ids": finding_ids,
        "finding_types": [e1["vuln_type"], e2["vuln_type"]],
        "severity": parsed.get("compounded_severity", "HIGH"),
        "attack_chain": parsed.get("attack_chain", []),
        "attack_steps": parsed.get("attack_steps", []),
        "evidence": evidence,
        "source_summary": _source_summary(evidence),
        "time_to_exploit": parsed.get("time_to_exploit", "unknown"),
        "impact": parsed.get("impact", ""),
        "reasoning": parsed.get("reasoning", ""),
        "confidence": parsed.get("confidence", "medium"),
        "priority_rationale": parsed.get("priority_rationale", ""),
        "recommended_fix_order": _humanize_fix_order(parsed.get("recommended_fix_order", [])),
    }


def analyze_attack_chains(findings: list[dict]) -> list[dict]:
    """Find all attack chains across a findings list."""
    chain_findings = _dedupe_for_chain_analysis(findings)
    code_findings = [f for f in chain_findings if _scanner_family(f) == "code"]
    web_findings = [f for f in chain_findings if _scanner_family(f) == "web"]

    if not code_findings or not web_findings:
        logger.info("No cross-domain pairs to analyze (need both code + web findings)")
        return []

    chains = []
    pairs_checked = 0
    groq_calls_made = 0

    for cf in code_findings:
        for wf in web_findings:
            if not _findings_could_compound(cf, wf):
                continue

            pairs_checked += 1
            logger.info(f"Analyzing potential chain: {cf.get('vuln_type')} + {wf.get('vuln_type')}")

            chain = _analyze_pair(cf, wf)
            groq_calls_made += 1

            if chain:
                chains.append(chain)
                logger.warning(
                    f"ATTACK CHAIN FOUND: {chain['finding_types']} -> "
                    f"{chain['severity']} | {chain['time_to_exploit']}"
                )

    logger.info(
        f"Chain analysis complete: {pairs_checked} pairs checked, "
        f"{groq_calls_made} Groq calls, {len(chains)} chains found"
    )
    return chains
