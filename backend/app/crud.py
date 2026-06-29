"""
CRUD operations for ShieldLabs
Centralized database queries - routes.py calls these instead of querying directly
"""

import uuid
from datetime import datetime
from sqlalchemy.orm import Session
from app.database import Scan, Finding, Report, AttackChain
from app.utils.logger import get_logger

logger = get_logger("crud")


# ==================
# SCAN OPERATIONS
# ==================

def create_scan(db: Session, scan_type: str, repo_url: str = None,
                 domain: str = None, zip_path: str = None) -> Scan:
    """Create a new scan record"""
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"

    scan = Scan(
        scan_id=scan_id,
        scan_type=scan_type,
        status="queued",
        repo_url=repo_url,
        domain=domain,
        zip_path=zip_path,
        progress=0,
        current_stage="Initializing...",
        created_at=datetime.utcnow()
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)
    logger.info(f"Created scan {scan_id} (type={scan_type})")
    return scan


def get_scan(db: Session, scan_id: str) -> Scan | None:
    """Get a single scan by ID"""
    return db.query(Scan).filter(Scan.scan_id == scan_id).first()


def update_scan_status(db: Session, scan_id: str, status: str,
                        current_stage: str = None, progress: int = None) -> Scan | None:
    """Update scan status/progress"""
    scan = get_scan(db, scan_id)
    if not scan:
        return None

    scan.status = status
    if current_stage is not None:
        scan.current_stage = current_stage
    if progress is not None:
        scan.progress = progress

    if status == "scanning" and not scan.started_at:
        scan.started_at = datetime.utcnow()
    if status in ("completed", "failed"):
        scan.completed_at = datetime.utcnow()

    db.commit()
    db.refresh(scan)
    return scan


def update_scan_counts(db: Session, scan_id: str) -> Scan | None:
    """Recalculate finding counts for a scan based on actual findings in DB"""
    scan = get_scan(db, scan_id)
    if not scan:
        return None

    findings = get_findings_by_scan(db, scan_id)
    scan.total_findings = len(findings)
    scan.critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    scan.high_count = sum(1 for f in findings if f.severity == "HIGH")
    scan.medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
    scan.low_count = sum(1 for f in findings if f.severity == "LOW")

    db.commit()
    db.refresh(scan)
    return scan


# ==================
# FINDING OPERATIONS
# ==================

def add_finding(db: Session, scan_id: str, vuln_type: str, severity: str,
                 description: str, **kwargs) -> Finding:
    """
    Add a new finding to a scan.
    kwargs can include: file_path, line_number, url, port, cvss_score,
    vulnerable_code, fixed_code, fix_explanation, remediation_time, confidence
    """
    finding_id = f"find_{uuid.uuid4().hex[:8]}"

    finding = Finding(
        scan_id=scan_id,
        finding_id=finding_id,
        vuln_type=vuln_type,
        severity=severity,
        description=description,
        created_at=datetime.utcnow(),
        **kwargs
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)
    logger.info(f"Added finding {finding_id} ({vuln_type}, {severity}) to {scan_id}")
    return finding


def get_findings_by_scan(db: Session, scan_id: str) -> list[Finding]:
    """Get all findings for a scan, excluding false positives by default"""
    return db.query(Finding).filter(
        Finding.scan_id == scan_id,
        Finding.is_false_positive == False
    ).order_by(Finding.cvss_score.desc()).all()


def get_finding(db: Session, finding_id: str) -> Finding | None:
    """Get a single finding by ID"""
    return db.query(Finding).filter(Finding.finding_id == finding_id).first()


def mark_false_positive(db: Session, finding_id: str) -> Finding | None:
    """Mark a finding as a false positive (manual review override)"""
    finding = get_finding(db, finding_id)
    if not finding:
        return None
    finding.is_false_positive = True
    db.commit()
    db.refresh(finding)
    return finding


# ==================
# REPORT OPERATIONS
# ==================

def create_report(db: Session, scan_id: str, file_path: str,
                   risk_level: str, executive_summary: str = None) -> Report:
    """Create a report record after PDF generation"""
    report = Report(
        scan_id=scan_id,
        file_path=file_path,
        risk_level=risk_level,
        executive_summary=executive_summary,
        generated_at=datetime.utcnow()
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    # Link the report path back to the scan record too
    scan = get_scan(db, scan_id)
    if scan:
        scan.report_path = file_path
        db.commit()

    return report


def get_report(db: Session, scan_id: str) -> Report | None:
    """Get the report for a scan"""
    return db.query(Report).filter(Report.scan_id == scan_id).first()