"""
API Routes — now actually triggers real pipeline execution
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from app.database import get_db
from app import schemas, crud
from app.config import ScanMode
from app.utils.logger import get_logger

logger = get_logger("routes")
router = APIRouter(prefix="/api", tags=["api"])


# ──────────────────────────────────────────────
# CODE SCAN
# ──────────────────────────────────────────────

@router.post("/scan/code", response_model=schemas.ScanResponse)
async def scan_code(
    request: schemas.CodeScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Initiate code repository scan.
    Returns scan_id immediately, scan runs in background.
    Poll /api/status/{scan_id} for progress.
    """
    try:
        scan = crud.create_scan(
            db,
            scan_type="code",
            repo_url=str(request.repo_url) if request.repo_url else None
        )

        # Import here to avoid circular imports
        from app.pipeline import run_code_scan_pipeline
        from app.database import SessionLocal

        def run_with_own_db():
            """Background tasks need their own DB session."""
            task_db = SessionLocal()
            try:
                run_code_scan_pipeline(
                    db=task_db,
                    scan_id=scan.scan_id,
                    repo_url=str(request.repo_url) if request.repo_url else None
                )
            finally:
                task_db.close()

        background_tasks.add_task(run_with_own_db)

        return schemas.ScanResponse(
            scan_id=scan.scan_id,
            status="queued",
            message=f"Code scan queued. Poll /api/status/{scan.scan_id} for progress."
        )

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────
# WEB SCAN
# ──────────────────────────────────────────────

@router.post("/scan/web", response_model=schemas.ScanResponse)
async def scan_web(
    request: schemas.WebScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Initiate web application scan.
    Returns scan_id immediately, scan runs in background.
    """
    try:
        scan = crud.create_scan(
            db, scan_type="web", domain=request.domain
        )

        from app.pipeline import run_web_scan_pipeline
        from app.database import SessionLocal

        def run_with_own_db():
            task_db = SessionLocal()
            try:
                run_web_scan_pipeline(
                    db=task_db,
                    scan_id=scan.scan_id,
                    domain=request.domain,
                    scan_mode=ScanMode(request.scan_mode),
                    consent_confirmed=request.consent_confirmed,
                    active_urls=request.active_urls
                )
            finally:
                task_db.close()

        background_tasks.add_task(run_with_own_db)

        return schemas.ScanResponse(
            scan_id=scan.scan_id,
            status="queued",
            message=f"Web scan queued. Poll /api/status/{scan.scan_id} for progress."
        )

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────
# COMBINED SCAN (CODE + WEB + ATTACK CHAINS)
# ──────────────────────────────────────────────

@router.post("/scan/combined", response_model=schemas.ScanResponse)
async def scan_combined(
    request: schemas.CombinedScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Full ShieldLabs scan: code + web + cross-domain attack chain analysis.
    This is the flagship endpoint.
    """
    try:
        scan = crud.create_scan(
            db,
            scan_type="combined",
            repo_url=str(request.repo_url),
            domain=request.domain
        )

        from app.pipeline import run_combined_pipeline
        from app.database import SessionLocal

        def run_with_own_db():
            task_db = SessionLocal()
            try:
                run_combined_pipeline(
                    db=task_db,
                    scan_id=scan.scan_id,
                    repo_url=str(request.repo_url),
                    domain=request.domain,
                    scan_mode=ScanMode(request.scan_mode),
                    consent_confirmed=request.consent_confirmed,
                    active_urls=request.active_urls,
                )
            finally:
                task_db.close()

        background_tasks.add_task(run_with_own_db)

        return schemas.ScanResponse(
            scan_id=scan.scan_id,
            status="queued",
            message=f"Combined scan queued. Poll /api/status/{scan.scan_id} for progress."
        )

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────
# STATUS + RESULTS
# ──────────────────────────────────────────────

@router.get("/status/{scan_id}")
async def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    """Real-time scan progress. Frontend polls this."""
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "progress": scan.progress,
        "current_stage": scan.current_stage,
        "total_findings": scan.total_findings,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error": scan.error_message
    }


@router.get("/results/{scan_id}", response_model=schemas.ResultsResponse)
async def get_results(scan_id: str, db: Session = Depends(get_db)):
    """Get complete scan results including findings and attack chains"""
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("completed", "failed"):
        raise HTTPException(
            status_code=202,
            detail=f"Scan still in progress ({scan.progress}%). "
                   f"Check /api/status/{scan_id}"
        )

    findings = crud.get_findings_by_scan(db, scan_id)

    # Get attack chains (only exist for combined scans)
    raw_chains = crud.get_chains_by_scan(db, scan_id)

    # Build AttackChainSchema objects
    chain_schemas = []
    for c in raw_chains:
        try:
            chain_schemas.append(schemas.AttackChainSchema(
                chain_id=c["chain_id"],
                finding_ids=c["finding_ids"],
                finding_types=c["finding_types"],
                severity=c["severity"],
                attack_chain=c["attack_chain"],
                time_to_exploit=c["time_to_exploit"],
                impact=c["impact"],
                reasoning=c["reasoning"]
            ))
        except Exception as e:
            logger.warning(f"Could not serialize chain {c.get('chain_id')}: {e}")

    return schemas.ResultsResponse(
        scan_id=scan.scan_id,
        status=scan.status,
        scan_type=scan.scan_type,
        repo_url=scan.repo_url, 
        total_findings=scan.total_findings,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        findings=[schemas.FindingSchema.from_orm(f) for f in findings],
        attack_chains=chain_schemas,
        report_path=scan.report_path,
        created_at=scan.created_at,
        completed_at=scan.completed_at
    )


@router.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


# ──────────────────────────────────────────────
# AUTO-PR ENDPOINT
# ──────────────────────────────────────────────

@router.post("/pr/create", response_model=schemas.PRResult)
async def create_fix_pr(
    request: schemas.CreatePRRequest,
    db: Session = Depends(get_db)
):
    """
    Create a GitHub Pull Request with AI-generated fixes applied.

    Finds all eligible findings from the scan (code findings with
    file_path + vulnerable_code + fixed_code), applies them to the
    repository, and opens a PR for developer review.

    This runs synchronously (not background task) because it typically
    finishes in under 60 seconds — no polling needed.
    """
    # Verify scan exists and is completed
    scan = crud.get_scan(db, request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not completed yet (status: {scan.status}). "
                   "Wait for scan to complete before creating a PR."
        )

    # Get findings from database
    raw_findings = crud.get_findings_by_scan(db, request.scan_id)
    if request.finding_ids is not None:
        selected_ids = set(request.finding_ids)
        raw_findings = [f for f in raw_findings if f.finding_id in selected_ids]
        if not raw_findings:
            raise HTTPException(
                status_code=400,
                detail="None of the selected findings belong to this completed scan."
            )

    # Convert SQLAlchemy objects to dicts for the auto_pr module
    findings_dicts = []
    for f in raw_findings:
        findings_dicts.append({
            "finding_id": f.finding_id,
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "vulnerable_code": f.vulnerable_code,
            "fixed_code": f.fixed_code,
            "fix_explanation": f.fix_explanation,
            "fix_source": f.fix_source,
            "remediation_status": f.remediation_status,
            "source_file_hash": f.source_file_hash,
            "is_false_positive": f.is_false_positive,
            "source": "bandit"  # default for code findings
        })

    if not findings_dicts:
        raise HTTPException(
            status_code=400,
            detail="No findings found for this scan. "
                   "Make sure this was a code scan with results."
        )

    # Run the auto-PR engine
    from app.agents.auto_pr import create_fix_pr as _create_pr

    logger.info(
        f"Creating auto-PR for scan {request.scan_id} "
        f"on {request.repo_url}"
    )

    try:
        result = _create_pr(
            github_token=request.github_token,
            repo_url=str(request.repo_url),
            scan_id=request.scan_id,
            findings=findings_dicts,
            allow_untested=request.allow_untested,
        )
    except Exception as exc:
        logger.exception("Auto-PR engine failed before a PR could be created")
        result = {
            "success": False,
            "pr_url": None,
            "pr_number": None,
            "branch_name": "",
            "fixes_applied": 0,
            "fixes_skipped": 0,
            "applied_details": [],
            "skipped_details": [],
            "validation_details": [],
            "error": (
                "Auto-PR failed before any changes were pushed: "
                f"{type(exc).__name__}: {exc}"
            ),
        }

    return schemas.PRResult(**result)
