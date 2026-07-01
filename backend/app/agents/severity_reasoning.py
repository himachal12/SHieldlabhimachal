"""
Severity Reasoning Agent
Takes raw findings (with rough severity labels from scanners) and
produces proper CVSS 3.1 scores + real-world exploitability assessments.

Uses Groq (cloud, strong reasoning) for the exploitability judgment call,
since this is a high-value reasoning task worth the API quota spend.
"""

import json
from app.utils.llm import groq_call
from app.utils.logger import get_logger

logger = get_logger("severity_reasoning")

# CVSS 3.1 base metric weights
# Reference: https://www.first.org/cvss/calculator/3.1
CVSS_AV = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2}
CVSS_AC = {"LOW": 0.77, "HIGH": 0.44}
CVSS_PR = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
CVSS_UI = {"NONE": 0.85, "REQUIRED": 0.62}
CVSS_IMPACT = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}

EXPLOITABILITY_PROMPT = """You are a penetration tester assessing real-world exploitability.

VULNERABILITY: {vuln_type}
DESCRIPTION: {description}
LOCATION: {location}
SEVERITY (scanner's estimate): {severity}

Answer ONLY with valid JSON, no markdown:
{{
  "attack_vector": "NETWORK|ADJACENT|LOCAL|PHYSICAL",
  "attack_complexity": "LOW|HIGH",
  "privileges_required": "NONE|LOW|HIGH",
  "user_interaction": "NONE|REQUIRED",
  "confidentiality_impact": "NONE|LOW|HIGH",
  "integrity_impact": "NONE|LOW|HIGH",
  "availability_impact": "NONE|LOW|HIGH",
  "exploitability_score": <integer 1-10>,
  "time_to_exploit": "<e.g. '5 minutes' or '2 hours' or 'days'>",
  "reasoning": "<one sentence: why this is or isn't easily exploitable in practice>"
}}"""


def calculate_cvss(av: str, ac: str, pr: str, ui: str,
                   c_impact: str, i_impact: str, a_impact: str) -> float:
    """
    Calculate CVSS 3.1 Base Score from metric values.
    Returns score between 0.0 and 10.0.
    """
    exploitability = (8.22
                      * CVSS_AV.get(av, 0.85)
                      * CVSS_AC.get(ac, 0.77)
                      * CVSS_PR.get(pr, 0.85)
                      * CVSS_UI.get(ui, 0.85))

    c = CVSS_IMPACT.get(c_impact, 0.0)
    i = CVSS_IMPACT.get(i_impact, 0.0)
    a = CVSS_IMPACT.get(a_impact, 0.0)

    iss = 1 - (1 - c) * (1 - i) * (1 - a)  # Impact Sub-Score

    if iss == 0:
        impact = 0.0
    else:
        impact = 6.42 * iss  # Scope Unchanged formula

    if impact == 0:
        return 0.0

    base_score = min(10.0, (impact + exploitability))

    # Round to 1 decimal per CVSS spec
    return round(base_score, 1)


def _severity_from_cvss(score: float) -> str:
    """Convert a CVSS score to a severity label per CVSS 3.1 spec."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "INFO"


def reason_severity(finding: dict) -> dict:
    """
    Use Groq to assess real-world exploitability and calculate a CVSS score.
    Attaches cvss_score, severity (updated), exploitability_score,
    time_to_exploit, and reasoning to the finding.
    """
    location = (
        f"{finding.get('file_path', '')}:{finding.get('line_number', '')}"
        if finding.get("file_path")
        else finding.get("url", "unknown")
    )

    prompt = EXPLOITABILITY_PROMPT.format(
        vuln_type=finding.get("vuln_type", "Unknown"),
        description=finding.get("description", ""),
        location=location,
        severity=finding.get("severity", "MEDIUM")
    )

    response = groq_call(prompt)

    try:
        cleaned = response.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(cleaned)
    except (json.JSONDecodeError, AttributeError):
        logger.warning(f"Could not parse Groq severity response for {finding.get('vuln_type')}: {response[:150]!r}")
        # Fail safe: keep original severity, add a placeholder CVSS
        finding["cvss_score"] = _fallback_cvss(finding.get("severity", "MEDIUM"))
        finding["exploitability_score"] = 5
        finding["time_to_exploit"] = "unknown"
        finding["severity_reasoning"] = "Automated reasoning failed -- severity estimate from scanner label"
        return finding

    cvss = calculate_cvss(
        av=parsed.get("attack_vector", "NETWORK"),
        ac=parsed.get("attack_complexity", "LOW"),
        pr=parsed.get("privileges_required", "NONE"),
        ui=parsed.get("user_interaction", "NONE"),
        c_impact=parsed.get("confidentiality_impact", "LOW"),
        i_impact=parsed.get("integrity_impact", "LOW"),
        a_impact=parsed.get("availability_impact", "LOW")
    )

    finding["cvss_score"] = cvss
    finding["severity"] = _severity_from_cvss(cvss)  # override scanner's rough label
    finding["exploitability_score"] = parsed.get("exploitability_score", 5)
    finding["time_to_exploit"] = parsed.get("time_to_exploit", "unknown")
    finding["severity_reasoning"] = parsed.get("reasoning", "")
    finding["cvss_vector"] = (
        f"CVSS:3.1/AV:{parsed.get('attack_vector', 'N')[:1]}/"
        f"AC:{parsed.get('attack_complexity', 'L')[:1]}/"
        f"PR:{parsed.get('privileges_required', 'N')[:1]}/"
        f"UI:{parsed.get('user_interaction', 'N')[:1]}"
    )

    logger.info(f"Severity assessed: {finding['vuln_type']} -> CVSS {cvss} ({finding['severity']})")
    return finding


def _fallback_cvss(severity_label: str) -> float:
    """Last-resort CVSS estimate when Groq fails, based on scanner's severity label."""
    return {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(severity_label, 5.0)


def reason_all_severities(findings: list[dict]) -> list[dict]:
    """
    Run reason_severity() across all findings.

    Smart filtering: skip "Open Port" (LOW, informational) and
    "Technology Detection" findings -- they don't benefit from
    CVSS reasoning, and we don't want to burn Groq quota on them.
    """
    SKIP_TYPES = {"Open Port", "Technology Detection"}

    reasoned = []
    skipped = 0
    for f in findings:
        if f.get("vuln_type") in SKIP_TYPES:
            f["cvss_score"] = 2.0
            f["exploitability_score"] = 2
            reasoned.append(f)
            skipped += 1
        else:
            reasoned.append(reason_severity(f))

    logger.info(
        f"Severity reasoning complete: {len(findings) - skipped} Groq calls made, "
        f"{skipped} findings auto-scored (informational)"
    )
    return reasoned