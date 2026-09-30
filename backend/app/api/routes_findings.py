from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database.database import get_db
from app.database.models import FindingRecord, AuditRecord
from app.models.finding import Finding, Severity, Status

router = APIRouter(tags=["Findings"])

@router.get("/findings", response_model=List[Finding])
def get_all_findings(
    audit_id: Optional[str] = Query(None, description="Optional specific audit ID. If omitted, uses latest audit."),
    category: Optional[str] = Query(None, description="Filter by category"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    status: Optional[str] = Query(None, description="Filter by status (PASS, FAIL, WARNING, NOT_AVAILABLE)"),
    search: Optional[str] = Query(None, description="Search keyword in title or description"),
    db: Session = Depends(get_db)
):
    target_audit_id = audit_id
    if not target_audit_id:
        latest = db.query(AuditRecord).order_by(AuditRecord.started_at.desc()).first()
        if not latest:
            return []
        target_audit_id = latest.id

    query = db.query(FindingRecord).filter(FindingRecord.audit_id == target_audit_id)

    if category:
        query = query.filter(FindingRecord.category.ilike(f"%{category}%"))
    if severity:
        query = query.filter(FindingRecord.severity == severity.upper())
    if status:
        query = query.filter(FindingRecord.status == status.upper())
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (FindingRecord.title.ilike(search_pattern)) |
            (FindingRecord.description.ilike(search_pattern)) |
            (FindingRecord.evidence.ilike(search_pattern))
        )

    records = query.all()
    return [
        Finding(
            id=f.id,
            audit_id=f.audit_id,
            category=f.category,
            title=f.title,
            description=f.description,
            severity=Severity(f.severity) if f.severity in Severity._value2member_map_ else Severity.INFO,
            status=Status(f.status) if f.status in Status._value2member_map_ else Status.NOT_AVAILABLE,
            evidence=f.evidence,
            recommendation=f.recommendation,
            technical_details=f.technical_details,
            created_at=f.created_at
        )
        for f in records
    ]

@router.get("/audit/{audit_id}/findings", response_model=List[Finding])
def get_audit_findings(
    audit_id: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    return get_all_findings(
        audit_id=audit_id,
        category=category,
        severity=severity,
        status=status,
        search=search,
        db=db
    )
