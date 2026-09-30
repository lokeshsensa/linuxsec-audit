from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from app.models.finding import Finding

class AuditSummary(BaseModel):
    id: str
    hostname: str
    os_name: str
    is_demo: bool
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "completed"
    risk_score: int = 0
    risk_level: str = "LOW"
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warning_count: int = 0
    not_available_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    model_config = ConfigDict(from_attributes=True)

class AuditDetail(AuditSummary):
    system_info: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)

class AuditCreateRequest(BaseModel):
    demo_mode: Optional[bool] = None
