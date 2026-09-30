import os
import stat
import pwd
import grp
from typing import List, Dict, Any
from app.auditors.base import BaseAuditor
from app.models.finding import Finding, Severity, Status

CRON_DIRS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs"
]

class CronAuditor(BaseAuditor):
    category = "Cron"

    def audit(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []
        world_writable_cron: List[str] = []
        non_root_cron: List[str] = []
        scanned_count = 0

        for path in CRON_DIRS:
            if not os.path.exists(path):
                continue

            targets = []
            if os.path.isfile(path):
                targets.append(path)
            elif os.path.isdir(path):
                try:
                    for entry in os.scandir(path):
                        if entry.is_file(follow_symlinks=False):
                            targets.append(entry.path)
                except PermissionError:
                    continue

            for file_path in targets:
                scanned_count += 1
                try:
                    st = os.lstat(file_path)
                    mode = stat.S_IMODE(st.st_mode)

                    # Check 1: World-writable cron file
                    if mode & stat.S_IWOTH:
                        world_writable_cron.append(f"{file_path} (mode: {oct(mode)})")

                    # Check 2: Non-root ownership on system cron directories
                    if not file_path.startswith("/var/spool/cron") and st.st_uid != 0:
                        owner = str(st.st_uid)
                        try:
                            owner = pwd.getpwuid(st.st_uid).pw_name
                        except Exception:
                            pass
                        non_root_cron.append(f"{file_path} (owner: {owner})")

                except (PermissionError, FileNotFoundError):
                    continue

        if world_writable_cron:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title=f"World-writable cron scheduled task files detected ({len(world_writable_cron)} found)",
                description=f"Identified scheduled task files with world-writable permissions: {', '.join(world_writable_cron[:5])}. Cron tasks typically execute with root privileges; any local attacker can edit these files to achieve instantaneous root privilege escalation.",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                evidence=f"Files: {'; '.join(world_writable_cron)}",
                recommendation="Immediately remove write permissions for non-root users: `chmod go-w <cron_file>` and verify file contents for unauthorized tampering.",
                technical_details="stat.S_IWOTH bit set on cron job file."
            ))
        elif non_root_cron:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title=f"System cron jobs owned by non-root users ({len(non_root_cron)} found)",
                description=f"System scheduled task files in /etc/cron.* are owned by non-root accounts: {', '.join(non_root_cron[:5])}. Owning accounts can manipulate execution commands.",
                severity=Severity.HIGH,
                status=Status.WARNING,
                evidence=f"Non-root cron files: {'; '.join(non_root_cron)}",
                recommendation="Change cron file ownership to root: `sudo chown root:root <cron_file>`.",
                technical_details="UID != 0 on files in /etc/cron*."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Scheduled task (cron) files securely permissioned",
                description=f"Scanned {scanned_count} cron definition files across system directories. All inspected files have restricted permissions and are owned by root.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"Scanned {scanned_count} files across: {', '.join(CRON_DIRS[:4])}...",
                recommendation="Maintain strict file permission controls on scheduled automation scripts.",
                technical_details="Verified lack of world-write bits and validated root ownership."
            ))

        return findings
