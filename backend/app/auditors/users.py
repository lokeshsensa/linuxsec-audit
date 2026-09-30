import os
import pwd
import grp
from typing import List, Dict, Any
from app.auditors.base import BaseAuditor
from app.models.finding import Finding, Severity, Status

VALID_SHELLS = {"/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/zsh", "/bin/dash", "/usr/bin/bash", "/bin/fish"}
DISABLED_SHELLS = {"/bin/false", "/usr/sbin/nologin", "/sbin/nologin", "/dev/null"}

class UserAuditor(BaseAuditor):
    category = "Users"

    def audit(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []

        try:
            users = pwd.getpwall()
        except Exception as e:
            return [
                self.create_finding(
                    audit_id=audit_id,
                    title="User database inaccessible",
                    description="Could not query system user accounts via POSIX pwd interface.",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    evidence=str(e),
                    recommendation="Ensure the audit execution process has read access to the local user database.",
                    technical_details="pwd.getpwall() failure."
                )
            ]

        # 1. UID 0 Accounts (Critical security check)
        uid_zero_users = [u.pw_name for u in users if u.pw_uid == 0]
        non_root_uid_zero = [u for u in uid_zero_users if u != "root"]

        if non_root_uid_zero:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Additional UID 0 account detected",
                description=f"System accounts with UID 0 other than 'root' were detected: {', '.join(non_root_uid_zero)}. Any account with UID 0 possesses unrestricted root privileges on the Linux operating system, bypassing standard authentication layers and access controls.",
                severity=Severity.HIGH,
                status=Status.FAIL,
                evidence=f"UID 0 accounts: {', '.join(uid_zero_users)}",
                recommendation="Investigate why these accounts have UID 0. Remove or reassign UIDs for all non-root accounts to follow the principle of least privilege.",
                technical_details="POSIX kernel identifies superuser privileges purely by numeric UID == 0."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Superuser UID 0 restricted to root account",
                description="Only the default 'root' account possesses UID 0. No hidden backdoor or auxiliary superuser accounts detected.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"UID 0 accounts: {', '.join(uid_zero_users)}",
                recommendation="Maintain strict control over user creation and periodic auditing of /etc/passwd.",
                technical_details="Checked pwd.getpwall() for pw_uid == 0."
            ))

        # 2. System accounts with interactive login shells
        system_users_with_shell = []
        for u in users:
            # Common convention: UID < 1000 (or < 500 in RHEL) is a system daemon
            if 0 < u.pw_uid < 1000:
                if u.pw_shell in VALID_SHELLS and u.pw_shell not in DISABLED_SHELLS:
                    # Ignore standard operational exceptions if any (e.g. sync, git)
                    system_users_with_shell.append(f"{u.pw_name} (UID {u.pw_uid}, Shell: {u.pw_shell})")

        if system_users_with_shell:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="System daemon accounts possess interactive login shells",
                description=f"The following system service accounts (UID < 1000) have interactive login shells assigned: {', '.join(system_users_with_shell[:5])}{'...' if len(system_users_with_shell) > 5 else ''}. If a daemon is compromised or has an insecure credential, attackers can leverage the shell for interactive command execution.",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                evidence=f"Count: {len(system_users_with_shell)} accounts: {'; '.join(system_users_with_shell[:4])}",
                recommendation="Change shells for system daemon accounts to '/usr/sbin/nologin' or '/bin/false' using `usermod -s /usr/sbin/nologin <username>`.",
                technical_details="System accounts (UID < 1000) should be non-interactive unless specifically required."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="System daemon accounts properly configured with non-login shells",
                description="All system service accounts (UID < 1000) have their shells set to nologin or false, preventing direct interactive login.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence="No system service accounts found with interactive login shells.",
                recommendation="Continue enforcing disabled shells for all newly installed service accounts.",
                technical_details="Verified /etc/passwd shell field against known interactive shells."
            ))

        # 3. Sudo / Administrative Group Membership
        admin_groups = ["sudo", "wheel", "admin"]
        admin_members = set()
        for g_name in admin_groups:
            try:
                g = grp.getgrnam(g_name)
                admin_members.update(g.gr_mem)
            except KeyError:
                pass

        if len(admin_members) > 5:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Excessive number of administrative (sudo/wheel) users",
                description=f"A large number of users ({len(admin_members)}) belong to administrative groups (sudo, wheel, admin): {', '.join(sorted(admin_members))}. Broad administrative delegation increases the attack surface.",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                evidence=f"Admin group members: {', '.join(sorted(admin_members))}",
                recommendation="Review the list of administrative users and remove sudo privileges from inactive or unneeded accounts.",
                technical_details=f"Evaluated memberships in groups: {', '.join(admin_groups)}"
            ))
        elif len(admin_members) > 0:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Administrative (sudo/wheel) group membership managed",
                description=f"Identified {len(admin_members)} user(s) with administrative sudo/wheel privileges.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"Users: {', '.join(sorted(admin_members))}",
                recommendation="Audit sudoer lists periodically.",
                technical_details="Admin group membership within expected limits."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="No standard sudo/wheel group members identified",
                description="No users were identified in standard sudo, wheel, or admin groups. Sudo may be managed via direct /etc/sudoers rules or active directory integration.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence="No members found in sudo/wheel/admin groups.",
                recommendation="Ensure designated administrative users have proper access control configured.",
                technical_details="POSIX group query for sudo, wheel, admin."
            ))

        return findings
