from enum import Enum
from typing import Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_AVAILABLE = "NOT_AVAILABLE"

class Category(str, Enum):
    SYSTEM = "System"
    USERS = "Users"
    PASSWORDS = "Passwords"
    SSH = "SSH"
    PERMISSIONS = "Permissions"
    SERVICES = "Services"
    NETWORK = "Network"
    FIREWALL = "Firewall"
    UPDATES = "Updates"
    CRON = "Cron"
    KERNEL = "Kernel"

class Finding(BaseModel):
    id: str = Field(..., description="Unique finding ID")
    audit_id: str = Field(..., description="Parent audit run ID")
    category: str = Field(..., description="Audit category")
    title: str = Field(..., description="Concise human-readable finding title")
    description: str = Field(..., description="Detailed explanation of the issue")
    severity: Severity = Field(..., description="Severity level")
    status: Status = Field(..., description="Status (PASS, FAIL, WARNING, NOT_AVAILABLE)")
    evidence: Optional[str] = Field(None, description="Observed system evidence")
    recommendation: str = Field(..., description="Remediation steps and best practices")
    technical_details: Optional[str] = Field(None, description="Configuration paths, values, standards")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(from_attributes=True)
