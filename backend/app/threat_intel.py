"""
Threat intelligence feed helpers.

Fetches recent CVEs from the public NVD API, normalizes the response into a
small product-friendly payload, and optionally enriches the highest-priority
items with short AI explanations.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from app.utils.llm import llm_call
from app.utils.logger import get_logger

logger = get_logger("threat_intel")

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_SECONDS = int(os.getenv("THREAT_INTEL_CACHE_TTL_SECONDS", "1800"))
MAX_LIMIT = 50

_cache: dict[str, Any] = {"key": None, "expires_at": 0.0, "payload": None}


SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}


def get_threat_intel(
    severity: str = "CRITICAL",
    days: int = 7,
    limit: int = 10,
    ai: bool = True,
) -> dict[str, Any]:
    """Return a recent CVE feed normalized for the frontend Threat Radar."""
    normalized_severity = _normalize_severity(severity)
    safe_days = max(1, min(days, 30))
    safe_limit = max(1, min(limit, MAX_LIMIT))
    cache_key = f"{normalized_severity}:{safe_days}:{safe_limit}:{ai}"
    now = time.time()

    if _cache["key"] == cache_key and _cache["payload"] and _cache["expires_at"] > now:
        cached = dict(_cache["payload"])
        cached["cached"] = True
        return cached

    try:
        items = _fetch_recent_cves(days=safe_days)
        items = _filter_and_sort(items, severity=normalized_severity)[:safe_limit]
        if ai and items:
            items = _enrich_with_ai(items)

        payload = {
            "source": "NVD CVE API 2.0",
            "source_url": NVD_CVE_API_URL,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "severity": normalized_severity,
            "days": safe_days,
            "count": len(items),
            "cached": False,
            "items": items,
        }
        _cache.update({
            "key": cache_key,
            "expires_at": now + CACHE_TTL_SECONDS,
            "payload": payload,
        })
        return payload
    except Exception as exc:
        logger.error(f"Threat intel fetch failed: {exc}")
        if _cache["payload"]:
            fallback = dict(_cache["payload"])
            fallback["cached"] = True
            fallback["warning"] = "Live threat feed unavailable; showing cached data."
            return fallback
        return {
            "source": "NVD CVE API 2.0",
            "source_url": NVD_CVE_API_URL,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "severity": normalized_severity,
            "days": safe_days,
            "count": 0,
            "cached": False,
            "warning": "Live threat feed unavailable. Try again later.",
            "items": [],
        }


def _fetch_recent_cves(days: int) -> list[dict[str, Any]]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": _nvd_timestamp(start),
        "pubEndDate": _nvd_timestamp(end),
        "resultsPerPage": 200,
    }
    api_key = os.getenv("NVD_API_KEY")
    headers = {"User-Agent": "ShieldLabs-ThreatRadar/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    response = requests.get(NVD_CVE_API_URL, params=params, headers=headers, timeout=20)
    response.raise_for_status()
    data = response.json()
    return [_normalize_cve(entry.get("cve", {})) for entry in data.get("vulnerabilities", [])]


def _normalize_cve(cve: dict[str, Any]) -> dict[str, Any]:
    cve_id = cve.get("id", "Unknown CVE")
    description = _english_description(cve.get("descriptions", []))
    severity, cvss_score, vector = _cvss(cve.get("metrics", {}))
    published = cve.get("published")
    last_modified = cve.get("lastModified")
    keywords = _extract_keywords(cve, description)

    return {
        "cve_id": cve_id,
        "severity": severity,
        "cvss_score": cvss_score,
        "published": published,
        "last_modified": last_modified,
        "description": description,
        "affected_keywords": keywords,
        "cvss_vector": vector,
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != "Unknown CVE" else NVD_CVE_API_URL,
        "why_this_matters": _fallback_summary(severity, cvss_score, description),
        "recommended_action": "Check whether this product or dependency exists in your stack, then review vendor patches and mitigations.",
    }


def _english_description(descriptions: list[dict[str, Any]]) -> str:
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return item["value"]
    if descriptions:
        return descriptions[0].get("value", "No description provided by source.")
    return "No description provided by source."


def _cvss(metrics: dict[str, Any]) -> tuple[str, float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_items = metrics.get(key) or []
        if metric_items:
            metric = metric_items[0]
            cvss_data = metric.get("cvssData", {})
            severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity") or "UNKNOWN"
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            return str(severity).upper(), score, vector
    return "UNKNOWN", None, None


def _extract_keywords(cve: dict[str, Any], description: str) -> list[str]:
    keywords: list[str] = []
    configurations = cve.get("configurations", []) or []
    for config in configurations:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) > 5:
                    for value in (parts[3], parts[4]):
                        cleaned = value.replace("_", " ").strip()
                        if cleaned and cleaned != "*" and cleaned not in keywords:
                            keywords.append(cleaned)
                if len(keywords) >= 6:
                    return keywords

    # Conservative fallback: surface a few recognizable title-case tokens from
    # the official description without claiming they are confirmed products.
    for token in description.replace(",", " ").replace(".", " ").split():
        cleaned = token.strip("()[]{}:;'")
        if len(cleaned) > 3 and cleaned[0].isupper() and cleaned.lower() not in {"this", "that", "before", "after"}:
            if cleaned not in keywords:
                keywords.append(cleaned)
        if len(keywords) >= 4:
            break
    return keywords


def _filter_and_sort(items: list[dict[str, Any]], severity: str) -> list[dict[str, Any]]:
    if severity != "ALL":
        minimum = SEVERITY_RANK.get(severity, SEVERITY_RANK["CRITICAL"])
        items = [item for item in items if SEVERITY_RANK.get(item["severity"], 0) >= minimum]

    return sorted(
        items,
        key=lambda item: (
            SEVERITY_RANK.get(item["severity"], 0),
            item["cvss_score"] or 0,
            item["published"] or "",
        ),
        reverse=True,
    )


def _enrich_with_ai(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compact_items = [
        {
            "cve_id": item["cve_id"],
            "severity": item["severity"],
            "cvss_score": item["cvss_score"],
            "description": item["description"][:700],
            "affected_keywords": item["affected_keywords"],
        }
        for item in items[:10]
    ]
    prompt = (
        "You are ShieldLabs Threat Radar. Summarize public CVE data for developers. "
        "Return JSON only as an array of objects with cve_id, why_this_matters, "
        "recommended_action. Do not invent products or facts. If impact is unclear, say to verify exposure. "
        f"CVEs: {json.dumps(compact_items)}"
    )
    response = llm_call(prompt, prefer="groq")
    summaries = _parse_ai_summaries(response)
    if not summaries:
        return items

    enriched = []
    for item in items:
        merged = dict(item)
        summary = summaries.get(item["cve_id"])
        if summary:
            merged["why_this_matters"] = summary.get("why_this_matters") or merged["why_this_matters"]
            merged["recommended_action"] = summary.get("recommended_action") or merged["recommended_action"]
            merged["ai_enriched"] = True
        else:
            merged["ai_enriched"] = False
        enriched.append(merged)
    return enriched


def _parse_ai_summaries(response: str) -> dict[str, dict[str, str]]:
    if not response:
        return {}
    try:
        cleaned = response.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            cleaned = cleaned.removeprefix("json").strip()
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            parsed = parsed.get("items", [])
        return {
            item.get("cve_id"): item
            for item in parsed
            if isinstance(item, dict) and item.get("cve_id")
        }
    except Exception as exc:
        logger.warning(f"Could not parse AI threat summaries: {exc}")
        return {}


def _fallback_summary(severity: str, score: float | None, description: str) -> str:
    score_text = f" with CVSS {score}" if score is not None else ""
    return (
        f"This {severity.lower()} vulnerability{score_text} may require developer review because affected deployments could need urgent patching or mitigation."
    )


def _normalize_severity(severity: str) -> str:
    value = (severity or "CRITICAL").upper()
    return value if value in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"} else "CRITICAL"


def _nvd_timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")
