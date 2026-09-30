import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.config import settings
from app.core.logger import audit_logger
from app.core.risk_engine import RiskEngine
from app.models.finding import Finding, Severity, Status
from app.models.audit import AuditDetail
from app.database.models import AuditRecord, FindingRecord
from app.demo.demo_data import get_demo_system_info, get_demo_findings

# Auditors
from app.auditors.system import SystemAuditor
from app.auditors.users import UserAuditor
from app.auditors.passwords import PasswordPolicyAuditor
from app.auditors.ssh import SshAuditor
from app.auditors.permissions import PermissionAuditor
from app.auditors.services import ServiceAuditor
from app.auditors.network import NetworkAuditor
from app.auditors.firewall import FirewallAuditor
from app.auditors.updates import UpdateAuditor
from app.auditors.cron import CronAuditor
from app.auditors.kernel import KernelAuditor

class AuditEngine:
    def __init__(self, demo_mode: Optional[bool] = None):
        self.demo_mode = settings.DEMO_MODE if demo_mode is None else demo_mode

    def run_audit(self, db: Optional[Session] = None) -> AuditDetail:
        audit_id = f"aud-{uuid.uuid4().hex[:8]}"
        started_at = datetime.utcnow()
        audit_logger.info(f"Starting audit [{audit_id}] (demo_mode={self.demo_mode})")

        all_findings: List[Finding] = []
        system_info: Dict[str, Any] = {}

        if self.demo_mode:
            # Simulated realistic enterprise Linux audit
            system_info = get_demo_system_info()
            all_findings = get_demo_findings(audit_id)
        else:
            # Live Linux system audit
            sys_auditor = SystemAuditor()
            try:
                system_info = sys_auditor.collect_info()
            except Exception as e:
                audit_logger.error(f"Error collecting system info: {e}")
                system_info = {"hostname": "localhost", "os_name": "Linux", "error": str(e)}

            auditors = [
                sys_auditor,
                UserAuditor(),
                PasswordPolicyAuditor(),
                SshAuditor(),
                PermissionAuditor(),
                ServiceAuditor(),
                NetworkAuditor(),
                FirewallAuditor(),
                UpdateAuditor(),
                CronAuditor(),
                KernelAuditor(),
            ]

            for auditor in auditors:
                try:
                    audit_logger.info(f"Running auditor: {auditor.category}")
                    auditor_findings = auditor.safe_audit(audit_id)
                    all_findings.extend(auditor_findings)
                except Exception as e:
                    audit_logger.error(f"Auditor {auditor.category} failed unexpectedly: {e}")
                    all_findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        audit_id=audit_id,
                        category=auditor.category,
                        title=f"{auditor.category} check error",
                        description=f"Auditor encountered an unexpected exception: {e}",
                        severity=Severity.INFO,
                        status=Status.NOT_AVAILABLE,
                        evidence=str(e),
                        recommendation="Check system logs for details.",
                        technical_details="AuditEngine loop exception catcher",
                        created_at=datetime.utcnow()
                    ))

        completed_at = datetime.utcnow()

        # Calculate risk metrics
        risk_score, risk_level, counts = RiskEngine.calculate_score(all_findings)

        total_checks = len(all_findings)
        passed_checks = counts.get("PASS", 0)
        failed_checks = counts.get("FAIL", 0)
        warning_count = counts.get("WARNING", 0)
        not_avail_count = counts.get("NOT_AVAILABLE", 0)

        crit_count = counts.get("CRITICAL", 0)
        high_count = counts.get("HIGH", 0)
        med_count = counts.get("MEDIUM", 0)
        low_count = counts.get("LOW", 0)
        info_count = counts.get("INFO", 0)

        detail = AuditDetail(
            id=audit_id,
            hostname=system_info.get("hostname", "unknown"),
            os_name=system_info.get("distribution", system_info.get("os_name", "Linux")),
            is_demo=self.demo_mode,
            started_at=started_at,
            completed_at=completed_at,
            status="completed",
            risk_score=risk_score,
            risk_level=risk_level,
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            warning_count=warning_count,
            not_available_count=not_avail_count,
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            info_count=info_count,
            system_info=system_info,
            findings=all_findings
        )

        # Store in database if session provided
        if db:
            try:
                record = AuditRecord(
                    id=detail.id,
                    hostname=detail.hostname,
                    os_name=detail.os_name,
                    is_demo=detail.is_demo,
                    started_at=detail.started_at,
                    completed_at=detail.completed_at,
                    status=detail.status,
                    risk_score=detail.risk_score,
                    risk_level=detail.risk_level,
                    total_checks=detail.total_checks,
                    passed_checks=detail.passed_checks,
                    failed_checks=detail.failed_checks,
                    warning_count=detail.warning_count,
                    not_available_count=detail.not_available_count,
                    critical_count=detail.critical_count,
                    high_count=detail.high_count,
                    medium_count=detail.medium_count,
                    low_count=detail.low_count,
                    info_count=detail.info_count,
                )
                record.set_system_info(system_info)
                db.add(record)

                for f in all_findings:
                    f_rec = FindingRecord(
                        id=f.id,
                        audit_id=detail.id,
                        category=f.category,
                        title=f.title,
                        description=f.description,
                        severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                        status=f.status.value if hasattr(f.status, "value") else str(f.status),
                        evidence=f.evidence,
                        recommendation=f.recommendation,
                        technical_details=f.technical_details,
                        created_at=f.created_at
                    )
                    db.add(f_rec)

                db.commit()
                audit_logger.info(f"Audit [{audit_id}] persisted to database.")
            except Exception as e:
                db.rollback()
                audit_logger.error(f"Failed to persist audit to database: {e}")

        audit_logger.info(f"Audit [{audit_id}] finished. Risk score: {risk_score}/100 ({risk_level}). Checks: {total_checks}")
        return detail
