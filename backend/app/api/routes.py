"""
API routes for ShieldLabs
Main endpoints for scanning, analysis, results
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import schemas, crud

router = APIRouter(prefix="/api", tags=["api"])


# ==================
# CODE SCANNING
# ==================

@router.post("/scan/code", response_model=schemas.ScanResponse)
async def scan_code(request: schemas.CodeScanRequest, db: Session = Depends(get_db)):
    """Initiate a code repository scan"""
    try:
        scan = crud.create_scan(
            db,
            scan_type="code",
            repo_url=str(request.repo_url) if request.repo_url else None
        )
        return schemas.ScanResponse(
            scan_id=scan.scan_id,
            status=scan.status,
            message="Code scan queued successfully"
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/web", response_model=schemas.ScanResponse)
async def scan_web(request: schemas.WebScanRequest, db: Session = Depends(get_db)):
    """Initiate a web application scan"""
    try:
        scan = crud.create_scan(db, scan_type="web", domain=request.domain)
        return schemas.ScanResponse(
            scan_id=scan.scan_id,
            status=scan.status,
            message="Web scan queued successfully"
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# ==================
# ANALYSIS & RESULTS
# ==================

@router.post("/analyze", response_model=schemas.ScanResponse)
async def analyze_scan(request: schemas.AnalyzeRequest, db: Session = Depends(get_db)):
    """Start multi-agent analysis on a completed scan"""
    scan = crud.get_scan(db, request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = crud.update_scan_status(
        db, request.scan_id, status="scanning",
        current_stage="Running multi-agent analysis..."
    )

    return schemas.ScanResponse(
        scan_id=scan.scan_id,
        status=scan.status,
        message="Analysis started"
    )


@router.get("/results/{scan_id}", response_model=schemas.ResultsResponse)
async def get_results(scan_id: str, db: Session = Depends(get_db)):
    """Get scan results (findings, report)"""
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = crud.get_findings_by_scan(db, scan_id)
    findings_response = [schemas.FindingSchema.from_orm(f) for f in findings]

    return schemas.ResultsResponse(
        scan_id=scan.scan_id,
        status=scan.status,
        scan_type=scan.scan_type,
        total_findings=scan.total_findings,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        findings=findings_response,
        report_path=scan.report_path,
        created_at=scan.created_at,
        completed_at=scan.completed_at
    )


@router.get("/status/{scan_id}")
async def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    """Get current scan status (for real-time UI polling later)"""
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "progress": scan.progress,
        "current_stage": scan.current_stage,
        "total_findings": scan.total_findings
    }