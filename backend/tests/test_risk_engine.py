import pytest
from datetime import datetime
from app.models.finding import Finding, Severity, Status
from app.core.risk_engine import RiskEngine

def test_risk_engine_all_pass():
    findings = [
        Finding(
            id="f1",
            audit_id="a1",
            category="System",
            title="Clean check",
            description="Check passed",
            severity=Severity.INFO,
            status=Status.PASS,
            recommendation="None",
            created_at=datetime.utcnow()
        )
    ]
    score, level, counts = RiskEngine.calculate_score(findings)
    assert score == 0
    assert level == "LOW RISK"
    assert counts["PASS"] == 1
    assert counts["FAIL"] == 0

def test_risk_engine_critical_fail():
    findings = [
        Finding(
            id=f"f{i}",
            audit_id="a1",
            category="SSH",
            title=f"Critical issue {i}",
            description="PermitEmptyPasswords yes",
            severity=Severity.CRITICAL,
            status=Status.FAIL,
            recommendation="Fix it",
            created_at=datetime.utcnow()
        )
        for i in range(10)
    ]
    score, level, counts = RiskEngine.calculate_score(findings)
    assert score == 100
    assert level == "CRITICAL RISK"
    assert counts["CRITICAL"] == 10
    assert counts["FAIL"] == 10

def test_risk_engine_mixed_findings():
    findings = [
        Finding(
            id="f1",
            audit_id="a1",
            category="Users",
            title="User issue",
            description="Non root UID 0",
            severity=Severity.HIGH,
            status=Status.FAIL,
            recommendation="Review",
            created_at=datetime.utcnow()
        ),
        Finding(
            id="f2",
            audit_id="a1",
            category="Firewall",
            title="Firewall warning",
            description="Firewall inactive",
            severity=Severity.MEDIUM,
            status=Status.WARNING,
            recommendation="Enable",
            created_at=datetime.utcnow()
        ),
        Finding(
            id="f3",
            audit_id="a1",
            category="Permissions",
            title="Permissions ok",
            description="Permissions ok",
            severity=Severity.INFO,
            status=Status.PASS,
            recommendation="None",
            created_at=datetime.utcnow()
        )
    ]
    score, level, counts = RiskEngine.calculate_score(findings)
    assert 0 < score < 100
    assert counts["HIGH"] == 1
    assert counts["MEDIUM"] == 1
    assert counts["PASS"] == 1
    assert counts["FAIL"] == 1
    assert counts["WARNING"] == 1
