"""
Pydantic schemas for request/response validation
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List
from datetime import datetime
from enum import Enum

# NEW (Day 7)
from app.config import ScanMode

# ==================
# ENUMS
# ==================

class ScanTypeEnum(str, Enum):
    """Types of scans"""
    CODE = "code"
    WEB = "web"
    COMBINED = "combined"


class StatusEnum(str, Enum):
    """Scan status"""
    QUEUED = "queued"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityEnum(str, Enum):
    """Vulnerability severity"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ==================
# REQUEST SCHEMAS
# ==================

class CodeScanRequest(BaseModel):
    """Request to scan code repository"""

    repo_url: Optional[HttpUrl] = Field(
        None,
        description="GitHub repository URL"
    )

    scan_type: ScanTypeEnum = Field(
        ScanTypeEnum.CODE,
        description="Type of scan"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "repo_url": "https://github.com/example/vulnerable-app",
                "scan_type": "code"
            }
        }


class WebScanRequest(BaseModel):
    """
    Request to scan a web application.
    Supports both passive and active scan modes.
    Active mode requires explicit user consent.
    """

    domain: str = Field(
        ...,
        description="Domain or IP to scan (e.g. example.com or 192.168.1.1)"
    )

    scan_mode: ScanMode = Field(
        default=ScanMode.PASSIVE,
        description="passive (safe default) or active (sqlmap testing)"
    )

    consent_confirmed: bool = Field(
        default=False,
        description="Must be True before any active scan is allowed."
    )

    active_urls: List[str] = Field(
        default_factory=list,
        description=(
            "URLs containing query parameters to test with sqlmap "
            "during active scans. Example: "
            "['http://example.com/search?q=test']"
        )
    )

    class Config:
        json_schema_extra = {
            "example_passive": {
                "domain": "example.com",
                "scan_mode": "passive"
            },
            "example_active": {
                "domain": "example.com",
                "scan_mode": "active",
                "consent_confirmed": True,
                "active_urls": [
                    "http://example.com/search?q=test"
                ]
            }
        }


class AnalyzeRequest(BaseModel):
    """Request to analyze scan results"""

    scan_id: str = Field(
        ...,
        description="ID of the scan to analyze"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "scan_abc123"
            }
        }


class CombinedScanRequest(BaseModel):
    """
    Request for the full ShieldLabs flagship scan:
    code repository + web domain + cross-domain attack chain analysis.
    This is the most powerful endpoint -- runs everything together.
    """

    repo_url: HttpUrl = Field(
        ...,
        description="GitHub repository URL to scan for code vulnerabilities"
    )

    domain: str = Field(
        ...,
        description="Domain to scan for web vulnerabilities (e.g. yourapp.com)"
    )

    scan_mode: ScanMode = Field(
        default=ScanMode.PASSIVE,
        description="passive (safe default) or active (sqlmap SQLi testing, requires consent)"
    )

    consent_confirmed: bool = Field(
        default=False,
        description="Must be True to enable active scan mode."
    )

    active_urls: List[str] = Field(
        default_factory=list,
        description="URLs containing query parameters to test with sqlmap during combined active scans."
    )

class CreatePRRequest(BaseModel):
    """Request to create a GitHub PR with auto-applied fixes"""

    scan_id: str = Field(
        ...,
        description="Scan ID to generate fixes from"
    )
    github_token: str = Field(
        ...,
        description="GitHub personal access token with repo write access. "
                    "Create at github.com/settings/tokens — needs 'repo' scope."
    )
    repo_url: HttpUrl = Field(
        ...,
        description="The GitHub repository URL to create the PR on"
    )
    finding_ids: Optional[List[str]] = Field(
        default=None,
        description="Optional finding IDs to include. Omit to include every eligible finding."
    )

    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "scan_abc123",
                "github_token": "ghp_yourpersonalaccesstoken",
                "repo_url": "https://github.com/yourname/yourapp"
            }
        }


class PRResult(BaseModel):
    """Result of creating an auto-fix PR"""

    success: bool
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None
    branch_name: str = ""
    fixes_applied: int = 0
    fixes_skipped: int = 0
    applied_details: List[dict] = []
    skipped_details: List[dict] = []
    validation_details: List[dict] = []
    error: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "repo_url": "https://github.com/yourorg/yourapp",
                "domain": "yourapp.com",
                "scan_mode": "passive",
                "consent_confirmed": False
            }
        }

class AttackChainSchema(BaseModel):
    """A cross-domain attack chain linking multiple findings"""
    chain_id: str
    finding_ids: List[str]
    finding_types: List[str]
    severity: SeverityEnum
    attack_chain: List[str]       # Step-by-step attack path
    time_to_exploit: str
    impact: str
    reasoning: str = ""

    class Config:
        from_attributes = True
# ==================
# RESPONSE SCHEMAS
# ==================

class ScanResponse(BaseModel):
    """Response when scan is initiated"""

    scan_id: str
    status: StatusEnum
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "scan_abc123",
                "status": "queued",
                "message": "Scan queued successfully"
            }
        }


class FindingSchema(BaseModel):
    """Individual vulnerability finding"""

    finding_id: str
    vuln_type: str
    severity: SeverityEnum
    cvss_score: Optional[float] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    url: Optional[str] = None
    port: Optional[int] = None
    description: str
    vulnerable_code: Optional[str] = None
    fixed_code: Optional[str] = None
    fix_explanation: Optional[str] = None
    remediation_time: Optional[str] = None
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    is_false_positive: bool = False

    class Config:
        from_attributes = True


class ResultsResponse(BaseModel):
    """Complete scan results"""

    scan_id: str
    status: StatusEnum
    scan_type: ScanTypeEnum
    repo_url: Optional[str] = None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[FindingSchema]
    attack_chains: List[AttackChainSchema] = []   # ← ADD THIS
    report_path: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class HealthResponse(BaseModel):
    """Health check response"""

    status: str
    app: str
    version: str
    debug: bool
    services: dict


class ErrorResponse(BaseModel):
    """Error response"""

    error: str
    detail: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "error": "Invalid scan ID",
                "detail": "Scan with ID 'xyz' not found"
            }
        }
