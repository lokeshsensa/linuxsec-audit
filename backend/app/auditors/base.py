import uuid
from abc import ABC, abstractmethod
from typing import List, Optional
from datetime import datetime, timezone
from app.models.finding import Finding, Severity, Status, Category
from app.core.logger import audit_logger

class BaseAuditor(ABC):
    category: str = "General"

    def __init__(self, demo_mode: bool = False):
        self.demo_mode = demo_mode

    @abstractmethod
    def audit(self, audit_id: str) -> List[Finding]:
        """Perform the audit and return a list of findings."""
        pass

    def create_finding(
        self,
        audit_id: str,
        title: str,
        description: str,
        severity: Severity,
        status: Status,
        evidence: Optional[str] = None,
        recommendation: str = "",
        technical_details: Optional[str] = None,
        category: Optional[str] = None
    ) -> Finding:
        return Finding(
            id=str(uuid.uuid4())[:8],
            audit_id=audit_id,
            category=category or self.category,
            title=title,
            description=description,
            severity=severity,
            status=status,
            evidence=evidence,
            recommendation=recommendation,
            technical_details=technical_details,
            created_at=datetime.now(timezone.utc)
        )

    def safe_audit(self, audit_id: str) -> List[Finding]:
        """Wrap audit execution in a safety envelope to ensure zero crashes."""
        try:
            return self.audit(audit_id)
        except Exception as e:
            audit_logger.error(f"Auditor '{self.category}' encountered unexpected exception: {e}")
            return [
                self.create_finding(
                    audit_id=audit_id,
                    title=f"{self.category} Audit Partial Execution",
                    description=f"The {self.category} auditor could not complete all checks due to an unexpected system error.",
                    severity=Severity.INFO,
                    status=Status.NOT_AVAILABLE,
                    evidence=f"Exception: {type(e).__name__}: {str(e)}",
                    recommendation="Review system logs and ensure auditing user has standard read permissions for system inspection.",
                    technical_details="Execution caught in safe_audit wrapper."
                )
            ]
