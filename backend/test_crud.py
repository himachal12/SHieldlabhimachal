from dotenv import load_dotenv
load_dotenv()

from app.database import SessionLocal
from app import crud

db = SessionLocal()

# Your scan ID
scan_id = "scan_4371b059"

finding = crud.add_finding(
    db,
    scan_id,
    vuln_type="SQL Injection",
    severity="CRITICAL",
    description="String concatenation in SQL query allows injection",
    file_path="app.py",
    line_number=42,
    cvss_score=9.1,
    vulnerable_code='query = f"SELECT * FROM users WHERE id = {user_id}"',
    confidence=0.95,
)

print(f"Added: {finding.finding_id}")

crud.update_scan_counts(db, scan_id)

scan = crud.get_scan(db, scan_id)
print(f"Scan now has {scan.total_findings} findings, {scan.critical_count} critical")

db.close()