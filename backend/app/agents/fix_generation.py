"""
Fix Generation
For each finding: either generate a real code fix via LLM (fixable categories)
or attach a pre-written remediation guide (architectural categories).
"""

import json
from app.utils.llm import ollama_call
from app.utils.logger import get_logger
from app.agents.fix_templates import get_template, is_fixable
from app.agents.remediation_guides import get_remediation_guide

logger = get_logger("fix_generation")


def _parse_llm_fix_response(response: str) -> dict | None:
    """
    Parse the LLM's JSON response. Returns None if it's malformed --
    caller decides what to do (we never want a malformed response to
    silently produce a broken/fake fix).
    """
    try:
        cleaned = response.strip()
        if cleaned.startswith("```"):
            # Strip markdown fences if the model added them despite instructions
            cleaned = cleaned.split("```")[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
        cleaned = cleaned.strip()
        parsed = json.loads(cleaned)

        # Validate required keys are present
        required = {"fixed_code", "why_vulnerable", "why_fix_works", "remediation_time"}
        if not required.issubset(parsed.keys()):
            logger.warning(f"LLM fix response missing required keys: {parsed.keys()}")
            return None

        return parsed

    except (json.JSONDecodeError, IndexError, TypeError) as e:
        logger.warning(f"Could not parse LLM fix response: {e} -- raw: {response[:150]!r}")
        return None


def generate_fix(finding: dict) -> dict:
    """
    Attach fix information to a single finding.
    Mutates and returns the finding dict with fixed_code/fix_explanation/
    remediation_time populated (or a note that fix generation isn't applicable).
    """
    vuln_type = finding["vuln_type"]

    # CASE 1: Architectural finding -- attach static guide, no LLM call needed
    guide = get_remediation_guide(vuln_type)
    if guide:
        finding["fixed_code"] = None
        finding["fix_explanation"] = guide["fix_explanation"]
        finding["remediation_time"] = guide["remediation_time"]
        finding["fix_source"] = "static_guide"
        return finding

    # CASE 2: Fixable category -- but only if we actually have a code snippet to work with
    if is_fixable(vuln_type):
        code = finding.get("vulnerable_code")
        if not code:
            finding["fixed_code"] = None
            finding["fix_explanation"] = "No code snippet available to generate a fix from."
            finding["remediation_time"] = "Manual review required"
            finding["fix_source"] = "skipped_no_code"
            return finding

        template = get_template(vuln_type)
        prompt = template.format(code=code)
        response = ollama_call(prompt)

        parsed = _parse_llm_fix_response(response)
        if parsed is None:
            # Fail safe: don't fabricate a fix, be honest that generation failed
            finding["fixed_code"] = None
            finding["fix_explanation"] = "Automated fix generation failed for this finding -- manual review recommended."
            finding["remediation_time"] = "Manual review required"
            finding["fix_source"] = "generation_failed"
            return finding

        finding["fixed_code"] = parsed["fixed_code"]
        finding["fix_explanation"] = f"{parsed['why_vulnerable']} {parsed['why_fix_works']}"
        finding["remediation_time"] = parsed["remediation_time"]
        finding["fix_source"] = "llm_generated"
        return finding

    # CASE 3: Category we don't have fix logic for at all (e.g. "Other (...)" from Bandit)
    finding["fixed_code"] = None
    finding["fix_explanation"] = "This finding type is outside current automated fix coverage -- manual review recommended."
    finding["remediation_time"] = "Manual review required"
    finding["fix_source"] = "out_of_scope"
    return finding


def generate_all_fixes(findings: list[dict]) -> list[dict]:
    """Run generate_fix() across a findings list."""
    fixable_count = sum(1 for f in findings if is_fixable(f["vuln_type"]) and f.get("vulnerable_code"))
    logger.info(f"Generating fixes: {fixable_count} via LLM, rest via static guides or marked manual")
    return [generate_fix(f) for f in findings]