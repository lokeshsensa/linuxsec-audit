import pytest
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
from app.models.finding import Status

def test_system_auditor_collects_info():
    auditor = SystemAuditor()
    info = auditor.collect_info()
    assert "hostname" in info
    assert "os_name" in info
    assert "disk_percent_used" in info
    findings = auditor.safe_audit("test-audit")
    assert isinstance(findings, list)
    assert len(findings) > 0

def test_auditors_safe_execution_never_crashes():
    auditors = [
        UserAuditor(),
        PasswordPolicyAuditor(),
        SshAuditor(),
        PermissionAuditor(),
        ServiceAuditor(),
        NetworkAuditor(),
        FirewallAuditor(),
        UpdateAuditor(),
        CronAuditor(),
        KernelAuditor()
    ]
    for a in auditors:
        res = a.safe_audit("test-audit")
        assert isinstance(res, list)
        for f in res:
            assert f.category is not None
            assert f.status in [Status.PASS, Status.FAIL, Status.WARNING, Status.NOT_AVAILABLE]
