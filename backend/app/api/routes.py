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
    """Get complete scan results including all findings."""
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("completed", "failed"):
        raise HTTPException(
            status_code=202,
            detail=f"Scan still in progress ({scan.progress}%). Check /api/status/{scan_id}"
        )

    findings = crud.get_findings_by_scan(db, scan_id)

    return schemas.ResultsResponse(
        scan_id=scan.scan_id,
        status=scan.status,
        scan_type=scan.scan_type,
        total_findings=scan.total_findings,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        findings=[schemas.FindingSchema.from_orm(f) for f in findings],
        report_path=scan.report_path,
        created_at=scan.created_at,
        completed_at=scan.completed_at
    )


@router.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}