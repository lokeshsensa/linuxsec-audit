from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database.database import get_db
from app.database.models import AuditRecord, FindingRecord
from app.models.audit import AuditDetail, AuditSummary, AuditCreateRequest
from app.models.finding import Finding, Severity, Status
from app.core.audit_engine import AuditEngine

router = APIRouter(tags=["Audit"])

@router.post("/audit/start", response_model=AuditDetail)
def start_audit(
    request: Optional[AuditCreateRequest] = None,
    db: Session = Depends(get_db)
):
    """Trigger a new security audit run."""
    demo = request.demo_mode if (request and request.demo_mode is not None) else None
    engine = AuditEngine(demo_mode=demo)
    detail = engine.run_audit(db=db)
    return detail

@router.get("/audits", response_model=List[AuditSummary])
def get_audit_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Retrieve historical audit summaries."""
    records = db.query(AuditRecord).order_by(AuditRecord.started_at.desc()).limit(limit).all()
    summaries = []
    for r in records:
        summaries.append(AuditSummary(
            id=r.id,
            hostname=r.hostname,
            os_name=r.os_name,
            is_demo=r.is_demo,
            started_at=r.started_at,
            completed_at=r.completed_at,
            status=r.status,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            total_checks=r.total_checks,
            passed_checks=r.passed_checks,
            failed_checks=r.failed_checks,
            warning_count=r.warning_count,
            not_available_count=r.not_available_count,
            critical_count=r.critical_count,
            high_count=r.high_count,
            medium_count=r.medium_count,
            low_count=r.low_count,
            info_count=r.info_count
        ))
    return summaries

@router.get("/audit/{audit_id}", response_model=AuditDetail)
def get_audit_by_id(audit_id: str, db: Session = Depends(get_db)):
    """Retrieve complete audit details and findings by audit ID."""
    r = db.query(AuditRecord).filter(AuditRecord.id == audit_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Audit with ID {audit_id} not found.")

    findings = [
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
        for f in r.findings
    ]

    return AuditDetail(
        id=r.id,
        hostname=r.hostname,
        os_name=r.os_name,
        is_demo=r.is_demo,
        started_at=r.started_at,
        completed_at=r.completed_at,
        status=r.status,
        risk_score=r.risk_score,
        risk_level=r.risk_level,
        total_checks=r.total_checks,
        passed_checks=r.passed_checks,
        failed_checks=r.failed_checks,
        warning_count=r.warning_count,
        not_available_count=r.not_available_count,
        critical_count=r.critical_count,
        high_count=r.high_count,
        medium_count=r.medium_count,
        low_count=r.low_count,
        info_count=r.info_count,
        system_info=r.get_system_info(),
        findings=findings
    )
