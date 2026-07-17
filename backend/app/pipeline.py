"""
Full Scan Pipeline Orchestrator
Chains every component built Days 3-7 into one end-to-end flow.
Called by background tasks -- never called synchronously in a route handler.

Flow:
  Input (GitHub URL / ZIP / Domain)
      ↓
  [Code Scanner] parse → detect → semantic filter → fix generation
      ↓
  [Web Scanner] port scan → exposed files → SSL → headers → Nuclei
      ↓
  [Severity Reasoning] CVSS 3.1 scoring per finding (Groq)
      ↓
  [Cross-Domain Analysis] attack chain detection (Groq)
      ↓
  [Database] persist all findings + chains
      ↓
  Scan marked "completed"
"""

import traceback
from datetime import datetime
from sqlalchemy.orm import Session

from app import crud
from app.config import ScanMode
from app.utils.logger import get_logger

logger = get_logger("pipeline")


def _update_progress(db: Session, scan_id: str, progress: int, stage: str):
    """Helper to update scan progress -- called between pipeline stages."""
    crud.update_scan_status(
        db, scan_id,
        status="scanning",
        current_stage=stage,
        progress=progress
    )
    logger.info(f"[{scan_id}] {progress}% — {stage}")


def run_code_scan_pipeline(
    db: Session,
    scan_id: str,
    repo_url: str = None,
    zip_path: str = None
):
    """
    Full pipeline for code scanning.
    Runs in a background task -- updates DB throughout.
    """
    temp_path = None
    try:
        # ── Stage 1: Parse codebase ─────────────────────────────
        _update_progress(db, scan_id, 5, "Cloning and parsing repository...")

        from app.agents.code_parser import CodeParser
        from app.utils.repo_handler import download_github_repo, extract_zip, cleanup_temp_repo

        # Keep this checkout alive until remediation generation is complete.
        # Deterministic fixes inspect the original source (for example, to
        # confirm ``import os`` before replacing a hardcoded secret), and LLM
        # prompts use the same source for context. Cleaning it up earlier
        # forces an unnecessary, less-safe LLM fallback.
        if repo_url:
            temp_path = download_github_repo(repo_url)
        elif zip_path:
            temp_path = extract_zip(zip_path)
        else:
            raise ValueError("No input provided: need repo_url or zip_path")

        parser = CodeParser()
        code_map = parser.parse_local_path(temp_path)

        logger.info(
            f"[{scan_id}] Parsed {code_map['total_files_parsed']} files, "
            f"{code_map['total_functions']} functions"
        )

        # ── Stage 2: Detect vulnerabilities ─────────────────────
        _update_progress(db, scan_id, 20, "Scanning for vulnerabilities...")

        from app.scanners.code_scanner import scan_codebase

        raw_findings = scan_codebase(temp_path)

        logger.info(f"[{scan_id}] Raw findings: {len(raw_findings)}")

        # ── Stage 3: Semantic false-positive filter ───────────────
        _update_progress(db, scan_id, 40, "Filtering false positives...")

        from app.scanners.semantic_analyzer import review_all_low_confidence
        findings = review_all_low_confidence(raw_findings)

        # ── Stage 4: Fix generation ───────────────────────────────
        _update_progress(db, scan_id, 55, "Generating fix suggestions...")

        from app.agents.fix_generation import generate_all_fixes
        findings = generate_all_fixes(findings)

        # ── Stage 5: Severity reasoning (CVSS) ───────────────────
        _update_progress(db, scan_id, 70, "Calculating CVSS scores...")

        from app.agents.severity_reasoning import reason_all_severities
        findings = reason_all_severities(findings)

        # ── Stage 6: Persist findings ────────────────────────────
        _update_progress(db, scan_id, 85, "Saving findings...")

        _persist_findings(db, scan_id, findings)

        # ── Stage 7: Complete ────────────────────────────────────
        crud.update_scan_status(
            db, scan_id, status="completed",
            current_stage="Scan complete", progress=100
        )
        crud.update_scan_counts(db, scan_id)

        scan = crud.get_scan(db, scan_id)
        logger.info(
            f"[{scan_id}] CODE SCAN COMPLETE — "
            f"{scan.total_findings} findings "
            f"({scan.critical_count} critical, {scan.high_count} high)"
        )

    except Exception as e:
        logger.error(f"[{scan_id}] Pipeline failed: {e}\n{traceback.format_exc()}")
        crud.update_scan_status(
            db, scan_id, status="failed",
            current_stage=f"Error: {str(e)[:200]}"
        )
    finally:
        if temp_path:
            cleanup_temp_repo(temp_path)


def run_web_scan_pipeline(
    db: Session,
    scan_id: str,
    domain: str,
    scan_mode: ScanMode = ScanMode.PASSIVE,
    consent_confirmed: bool = False,
    active_urls: list = None
):
    """Full pipeline for web scanning."""
    try:
        # ── Stage 1: Web scanning ─────────────────────────────────
        _update_progress(db, scan_id, 10, "Starting web reconnaissance...")

        from app.scanners.web_scanner import scan_web_target
        raw_findings = scan_web_target(
            target=domain,
            scan_mode=scan_mode,
            consent_confirmed=consent_confirmed,
            active_urls=active_urls or []
        )

        # ── Stage 2: Severity reasoning ───────────────────────────
        _update_progress(db, scan_id, 60, "Calculating CVSS scores...")

        from app.agents.severity_reasoning import reason_all_severities
        findings = reason_all_severities(raw_findings)

        # ── Stage 3: Persist ──────────────────────────────────────
        _update_progress(db, scan_id, 85, "Saving findings...")
        _persist_findings(db, scan_id, findings)

        # ── Stage 4: Complete ─────────────────────────────────────
        crud.update_scan_status(
            db, scan_id, status="completed",
            current_stage="Scan complete", progress=100
        )
        crud.update_scan_counts(db, scan_id)

        scan = crud.get_scan(db, scan_id)
        logger.info(
            f"[{scan_id}] WEB SCAN COMPLETE — "
            f"{scan.total_findings} findings"
        )

    except Exception as e:
        logger.error(f"[{scan_id}] Pipeline failed: {e}\n{traceback.format_exc()}")
        crud.update_scan_status(
            db, scan_id, status="failed",
            current_stage=f"Error: {str(e)[:200]}"
        )


def run_combined_pipeline(
    db: Session,
    scan_id: str,
    repo_url: str,
    domain: str,
    scan_mode: ScanMode = ScanMode.PASSIVE,
    consent_confirmed: bool = False,
    active_urls: list = None,
):
    """
    Combined code + web scan with cross-domain analysis.
    This is the FULL ShieldLabs experience -- both pillars + attack chains.
    """
    temp_path = None
    try:
        all_findings = []

        # ── Code scanning ─────────────────────────────────────────
        _update_progress(db, scan_id, 5, "Cloning and parsing repository...")

        from app.utils.repo_handler import download_github_repo, cleanup_temp_repo
        from app.scanners.code_scanner import scan_codebase
        from app.scanners.semantic_analyzer import review_all_low_confidence
        from app.agents.fix_generation import generate_all_fixes

        temp_path = download_github_repo(repo_url)
        _update_progress(db, scan_id, 15, "Detecting code vulnerabilities...")
        raw_code_findings = scan_codebase(temp_path)

        _update_progress(db, scan_id, 25, "Filtering false positives...")
        code_findings = review_all_low_confidence(raw_code_findings)

        _update_progress(db, scan_id, 35, "Generating fix suggestions...")
        code_findings = generate_all_fixes(code_findings)

        all_findings.extend(code_findings)

        # ── Web scanning ──────────────────────────────────────────
        _update_progress(db, scan_id, 45, "Starting web reconnaissance...")

        from app.scanners.web_scanner import scan_web_target
        web_findings = scan_web_target(
            target=domain,
            scan_mode=scan_mode,
            consent_confirmed=consent_confirmed,
            active_urls=active_urls or []
        )
        all_findings.extend(web_findings)

        # ── Severity reasoning for ALL findings ───────────────────
        _update_progress(db, scan_id, 60, "Calculating CVSS scores...")

        from app.agents.severity_reasoning import reason_all_severities
        all_findings = reason_all_severities(all_findings)

        # ── Cross-domain analysis ─────────────────────────────────
        _update_progress(db, scan_id, 75, "Running cross-domain attack chain analysis...")

        from app.agents.cross_domain_analyzer import analyze_attack_chains
        chains = analyze_attack_chains(all_findings)

        # Tag findings that are part of a chain
        chain_finding_ids = set()
        for chain in chains:
            for fid in chain.get("finding_ids", []):
                chain_finding_ids.add(fid)

        for f in all_findings:
            fid = f.get("finding_id") or f.get("vuln_type")
            if fid in chain_finding_ids:
                f["is_cross_domain"] = True

        # ── Persist everything ────────────────────────────────────
        _update_progress(db, scan_id, 88, "Saving findings and attack chains...")
        _persist_findings(db, scan_id, all_findings)
        _persist_chains(db, scan_id, chains)

        # ── Complete ──────────────────────────────────────────────
        crud.update_scan_status(
            db, scan_id, status="completed",
            current_stage="Scan complete", progress=100
        )
        crud.update_scan_counts(db, scan_id)

        scan = crud.get_scan(db, scan_id)
        logger.info(
            f"[{scan_id}] COMBINED SCAN COMPLETE — "
            f"{scan.total_findings} findings, {len(chains)} attack chains"
        )

    except Exception as e:
        logger.error(f"[{scan_id}] Pipeline failed: {e}\n{traceback.format_exc()}")
        crud.update_scan_status(
            db, scan_id, status="failed",
            current_stage=f"Error: {str(e)[:200]}"
        )
    finally:
        if temp_path:
            cleanup_temp_repo(temp_path)


def _persist_findings(db: Session, scan_id: str, findings: list[dict]):
    """Save all findings to database."""
    for f in findings:
        try:
            crud.add_finding(
                db=db,
                scan_id=scan_id,
                vuln_type=f.get("vuln_type", "Unknown"),
                severity=f.get("severity", "MEDIUM"),
                description=f.get("description", ""),
                file_path=f.get("file_path"),
                line_number=f.get("line_number"),
                url=f.get("url"),
                port=f.get("port"),
                cvss_score=f.get("cvss_score"),
                vulnerable_code=f.get("vulnerable_code"),
                fixed_code=f.get("fixed_code"),
                fix_source=f.get("fix_source"),
                remediation_status=f.get("remediation_status", "detected"),
                patch_validation_details=f.get("patch_validation_details"),
                source_file_hash=f.get("source_file_hash"),
                repository_relative_path=f.get("repository_relative_path"),
                repository_commit=f.get("repository_commit"),
                finding_rule_id=f.get("finding_rule_id"),
                patch_kind=f.get("patch_kind"),
                fix_explanation=f.get("fix_explanation"),
                remediation_time=f.get("remediation_time"),
                confidence=f.get("confidence", 1.0),
                is_false_positive=f.get("is_likely_false_positive", False),
                is_cross_domain=f.get("is_cross_domain", False),
            )
        except Exception as e:
            logger.warning(f"Failed to persist finding {f.get('vuln_type')}: {e}")


def _persist_chains(db: Session, scan_id: str, chains: list[dict]):
    """Save attack chains to database."""
    from app.database import AttackChain, SessionLocal
    import json

    db_session = db
    for chain in chains:
        try:
            chain_record = AttackChain(
                scan_id=scan_id,
                chain_id=chain["chain_id"],
                finding_ids=json.dumps(chain.get("finding_ids", [])),
                severity=chain.get("severity", "HIGH"),
                description=json.dumps(chain.get("attack_chain", [])),
                time_to_exploit=chain.get("time_to_exploit", "unknown"),
                impact=chain.get("impact", ""),
            )
            db_session.add(chain_record)
            db_session.commit()
        except Exception as e:
            logger.warning(f"Failed to persist chain {chain.get('chain_id')}: {e}")
