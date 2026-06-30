"""
Semantic Analyzer
For low-confidence findings, asks the local LLM (Qwen2.5-Coder via Ollama)
to sanity-check whether it's a real issue or a false positive.

Deliberately only calls the LLM below a confidence threshold -- calling it
for EVERY finding would be slow and pointless for things we're already
90% confident about (e.g. Bandit HIGH-confidence findings).
"""

import json
from app.utils.llm import ollama_call
from app.utils.logger import get_logger

logger = get_logger("semantic_analyzer")

CONFIDENCE_THRESHOLD = 0.7

PROMPT_TEMPLATE = """You are a security code reviewer. Look at this flagged issue and decide if it's a REAL vulnerability or a FALSE POSITIVE.

FLAGGED ISSUE: {vuln_type}
DESCRIPTION: {description}
CODE:
{code}

Respond with ONLY valid JSON, nothing else, no markdown fences:
{{"is_real": true, "reasoning": "one sentence"}}"""


def review_finding(finding: dict) -> dict:
    """Review one low-confidence finding via LLM. Returns the finding, possibly updated."""
    if finding["confidence"] >= CONFIDENCE_THRESHOLD:
        return finding  # confident enough already -- skip the LLM call entirely

    prompt = PROMPT_TEMPLATE.format(
        vuln_type=finding["vuln_type"],
        description=finding["description"],
        code=finding.get("vulnerable_code") or "(file-level check, no specific code line)"
    )

    response = ollama_call(prompt)

    try:
        # Strip markdown fences if the model adds them despite instructions
        cleaned = response.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(cleaned)
        is_real = parsed.get("is_real", True)
        reasoning = parsed.get("reasoning", "")
    except (json.JSONDecodeError, TypeError):
        logger.warning(f"Could not parse LLM response as JSON: {response[:120]!r}")
        return finding  # fail safe: keep the original finding untouched, don't drop it

    finding["llm_reasoning"] = reasoning
    if not is_real:
        finding["confidence"] = max(0.05, finding["confidence"] - 0.3)
        finding["is_likely_false_positive"] = True
    else:
        finding["confidence"] = min(1.0, finding["confidence"] + 0.2)

    return finding


def review_all_low_confidence(findings: list[dict]) -> list[dict]:
    """Run review_finding() across a findings list. Mutates+returns the same list."""
    low_conf_count = sum(1 for f in findings if f["confidence"] < CONFIDENCE_THRESHOLD)
    logger.info(f"Reviewing {low_conf_count}/{len(findings)} low-confidence findings via LLM")
    return [review_finding(f) for f in findings]