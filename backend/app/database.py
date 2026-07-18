"""
Database configuration and setup
SQLite database for ShieldLabs
"""

import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

# Get database URL from .env
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./shieldlabs.db")

# Create SQLite engine
# check_same_thread=False is needed for SQLite (allows multiple threads)
if "sqlite" in DATABASE_URL:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        echo=False  # Set to True to see SQL queries
    )
else:
    engine = create_engine(DATABASE_URL)

# Create session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class for models
Base = declarative_base()

# ==================
# DATABASE MODELS
# ==================

class Scan(Base):
    """
    Represents a security scan
    Stores metadata about each scan performed
    """
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True)  # Unique identifier (e.g., "scan_abc123")
    scan_type = Column(String)  # "code" or "web"
    status = Column(String, default="queued")  # queued, scanning, completed, failed
    
    # Input data
    repo_url = Column(String, nullable=True)  # GitHub URL
    zip_path = Column(String, nullable=True)  # Uploaded ZIP
    domain = Column(String, nullable=True)    # Web domain
    
    # Progress
    progress = Column(Integer, default=0)  # 0-100%
    current_stage = Column(String, default="")  # "Parsing code...", "Scanning for SQL injection...", etc.
    
    # Results
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    
    # Report
    report_path = Column(String, nullable=True)  # Path to generated PDF
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Error tracking
    error_message = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<Scan {self.scan_id} ({self.scan_type})>"


class Finding(Base):
    """
    Represents a security vulnerability finding
    Each scan can have multiple findings
    """
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, index=True)  # Foreign key to Scan.scan_id
    finding_id = Column(String, unique=True, index=True)  # e.g., "find_sql_001"
    
    # Finding details
    vuln_type = Column(String, index=True)  # "SQL Injection", "Hardcoded Secret", etc.
    severity = Column(String, index=True)  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    cvss_score = Column(Float, nullable=True)  # 0.0 - 10.0
    
    # Location
    file_path = Column(String, nullable=True)  # Which file (for code findings)
    line_number = Column(Integer, nullable=True)  # Line number
    url = Column(String, nullable=True)  # URL (for web findings)
    port = Column(Integer, nullable=True)  # Port (for web findings)
    
    # Vulnerability info
    description = Column(Text)  # What is the vulnerability
    vulnerable_code = Column(Text, nullable=True)  # Code snippet showing the issue
    fixed_code = Column(Text, nullable=True)  # AI-generated fix
    fix_explanation = Column(Text, nullable=True)  # Why the fix works
    remediation_time = Column(String, nullable=True)  # "30 minutes", "1 hour", etc.
    fix_source = Column(String, nullable=True)
    remediation_status = Column(String, default="detected", nullable=False)
    patch_validation_details = Column(Text, nullable=True)
    source_file_hash = Column(String, nullable=True)
    repository_relative_path = Column(String, nullable=True)
    repository_commit = Column(String, nullable=True)
    finding_rule_id = Column(String, nullable=True)
    patch_kind = Column(String, nullable=True)
    
    # Confidence & filtering
    confidence = Column(Float, default=1.0)  # 0.0 - 1.0 (how confident are we?)
    is_false_positive = Column(Boolean, default=False)  # Manually marked as false positive?
    
    # Classification
    is_cross_domain = Column(Boolean, default=False)  # Part of attack chain?
    attack_chain_id = Column(String, nullable=True)  # Which attack chain?
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f"<Finding {self.finding_id} ({self.vuln_type})>"


class Report(Base):
    """
    Represents a generated security report
    One report per scan
    """
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True)
    
    # Report file
    file_path = Column(String)  # Path to PDF file
    file_size = Column(Integer, nullable=True)  # Size in bytes
    
    # Report metadata
    executive_summary = Column(Text, nullable=True)
    risk_level = Column(String)  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    
    # Timestamps
    generated_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f"<Report {self.scan_id}>"


class AttackChain(Base):
    """
    Represents cross-domain attack chains
    Groups multiple findings that compound risk
    """
    __tablename__ = "attack_chains"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, index=True)
    chain_id = Column(String, unique=True, index=True)
    
    # Chain details
    finding_ids = Column(Text)  # Comma-separated list of finding IDs
    severity = Column(String)  # Overall severity after compounding
    description = Column(Text)  # How findings connect
    time_to_exploit = Column(String)  # "5 minutes", "2 hours", etc.
    impact = Column(Text)  # Business impact
    evidence = Column(Text, nullable=True)  # JSON finding evidence snapshots
    attack_steps = Column(Text, nullable=True)  # JSON structured attack steps
    source_summary = Column(Text, nullable=True)  # JSON source/mode/location summary
    confidence = Column(String, nullable=True)  # high, medium, low
    priority_rationale = Column(Text, nullable=True)
    recommended_fix_order = Column(Text, nullable=True)  # JSON ordered remediation actions
    reasoning = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f"<AttackChain {self.chain_id}>"


# Create all tables
def init_db():
    """
    Create all database tables
    Run this once at startup
    """
    Base.metadata.create_all(bind=engine)
    # SQLite's create_all does not add columns to an existing development DB.
    # Keep this small, idempotent migration so lifecycle/provenance fields are
    # available without silently losing them after an upgrade.
    if "sqlite" in DATABASE_URL:
        required_columns = {
            "fix_source": "VARCHAR", "remediation_status": "VARCHAR DEFAULT 'detected'",
            "patch_validation_details": "TEXT", "source_file_hash": "VARCHAR",
            "repository_relative_path": "VARCHAR", "repository_commit": "VARCHAR",
            "finding_rule_id": "VARCHAR", "patch_kind": "VARCHAR",
        }
        required_attack_chain_columns = {
            "evidence": "TEXT", "attack_steps": "TEXT", "source_summary": "TEXT",
            "confidence": "VARCHAR", "priority_rationale": "TEXT",
            "recommended_fix_order": "TEXT", "reasoning": "TEXT",
        }
        with engine.begin() as connection:
            existing = {row[1] for row in connection.exec_driver_sql("PRAGMA table_info(findings)")}
            for name, sql_type in required_columns.items():
                if name not in existing:
                    connection.exec_driver_sql(f"ALTER TABLE findings ADD COLUMN {name} {sql_type}")

            existing_chains = {row[1] for row in connection.exec_driver_sql("PRAGMA table_info(attack_chains)")}
            for name, sql_type in required_attack_chain_columns.items():
                if name not in existing_chains:
                    connection.exec_driver_sql(f"ALTER TABLE attack_chains ADD COLUMN {name} {sql_type}")
    print("✅ Database initialized")


def get_db():
    """
    Get database session
    Use this in API routes
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


if __name__ == "__main__":
    # Run this file directly to initialize database
    init_db()
    print(f"Database created at: {DATABASE_URL}")

# Export SessionLocal so dependencies.py can import it
__all__ = ['engine', 'SessionLocal', 'Base', 'init_db', 'get_db']
