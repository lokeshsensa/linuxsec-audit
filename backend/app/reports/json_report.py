import json
from typing import Dict, Any
from app.models.audit import AuditDetail

class JsonReportGenerator:
    @staticmethod
    def generate(audit: AuditDetail) -> str:
        """Export audit report as formatted JSON."""
        data = {
            "meta": {
                "tool": "LinuxSecAudit",
                "version": "1.0.0",
                "report_format": "JSON",
                "exported_at": audit.completed_at.isoformat() if audit.completed_at else None,
            },
            "audit_summary": {
                "audit_id": audit.id,
                "hostname": audit.hostname,
                "os": audit.os_name,
                "is_demo": audit.is_demo,
                "risk_score": audit.risk_score,
                "risk_level": audit.risk_level,
                "started_at": audit.started_at.isoformat(),
                "completed_at": audit.completed_at.isoformat() if audit.completed_at else None,
                "total_checks": audit.total_checks,
                "passed_checks": audit.passed_checks,
                "failed_checks": audit.failed_checks,
                "warning_count": audit.warning_count,
                "not_available_count": audit.not_available_count,
                "severity_breakdown": {
                    "critical": audit.critical_count,
                    "high": audit.high_count,
                    "medium": audit.medium_count,
                    "low": audit.low_count,
                    "info": audit.info_count,
                }
            },
            "system_info": audit.system_info,
            "findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                    "description": f.description,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "technical_details": f.technical_details,
                    "created_at": f.created_at.isoformat(),
                }
                for f in audit.findings
            ]
        }
        return json.dumps(data, indent=2)
