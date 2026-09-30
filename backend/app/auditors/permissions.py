import os
import stat
import pwd
import grp
from typing import List, Dict, Any, Tuple
from app.auditors.base import BaseAuditor
from app.models.finding import Finding, Severity, Status
from app.config import settings

# Sensitive files to audit
SENSITIVE_FILES = [
    {
        "path": "/etc/passwd",
        "max_mode": 0o644,
        "must_not_be_world_writable": True,
        "expected_owners": ["root"],
        "criticality": Severity.HIGH,
    },
    {
        "path": "/etc/group",
        "max_mode": 0o644,
        "must_not_be_world_writable": True,
        "expected_owners": ["root"],
        "criticality": Severity.HIGH,
    },
    {
        "path": "/etc/shadow",
        "max_mode": 0o640,
        "must_not_be_world_readable": True,
        "must_not_be_world_writable": True,
        "expected_owners": ["root"],
        "criticality": Severity.CRITICAL,
    },
    {
        "path": "/etc/gshadow",
        "max_mode": 0o640,
        "must_not_be_world_readable": True,
        "must_not_be_world_writable": True,
        "expected_owners": ["root"],
        "criticality": Severity.CRITICAL,
    },
    {
        "path": "/etc/sudoers",
        "max_mode": 0o440,
        "must_not_be_world_readable": True,
        "must_not_be_world_writable": True,
        "expected_owners": ["root"],
        "criticality": Severity.HIGH,
    },
    {
        "path": "/etc/ssh/sshd_config",
        "max_mode": 0o644,
        "must_not_be_world_writable": True,
        "expected_owners": ["root"],
        "criticality": Severity.HIGH,
    },
]

# Standard expected Linux SUID binaries
STANDARD_SUID_BINARIES = {
    "/bin/su", "/usr/bin/su",
    "/bin/mount", "/usr/bin/mount",
    "/bin/umount", "/usr/bin/umount",
    "/usr/bin/passwd",
    "/usr/bin/sudo", "/usr/bin/sudoedit",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/libexec/dbus-daemon-launch-helper",
}

class PermissionAuditor(BaseAuditor):
    category = "Permissions"

    def _get_owner_group_name(self, uid: int, gid: int) -> Tuple[str, str]:
        owner_name = str(uid)
        group_name = str(gid)
        try:
            owner_name = pwd.getpwuid(uid).pw_name
        except Exception:
            pass
        try:
            group_name = grp.getgrgid(gid).gr_name
        except Exception:
            pass
        return owner_name, group_name

    def audit_sensitive_files(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []

        for target in SENSITIVE_FILES:
            path = target["path"]
            if not os.path.exists(path):
                findings.append(self.create_finding(
                    audit_id=audit_id,
                    title=f"Sensitive file {path} not present",
                    description=f"The expected system configuration file {path} does not exist on this host.",
                    severity=Severity.INFO,
                    status=Status.NOT_AVAILABLE,
                    evidence=f"File not found: {path}",
                    recommendation="Verify whether this system uses non-standard authentication or configuration stores.",
                    technical_details=f"Checked os.path.exists('{path}')"
                ))
                continue

            try:
                st = os.stat(path)
                mode = stat.S_IMODE(st.st_mode)
                octal_mode = oct(mode)
                owner_name, group_name = self._get_owner_group_name(st.st_uid, st.st_gid)

                is_world_writable = bool(mode & stat.S_IWOTH)
                is_world_readable = bool(mode & stat.S_IROTH)

                # Check 1: World Writable
                if target.get("must_not_be_world_writable") and is_world_writable:
                    findings.append(self.create_finding(
                        audit_id=audit_id,
                        title=f"Critical system file {path} is world-writable",
                        description=f"The file {path} has world-writable permission bits set ({octal_mode}). Any local user or compromised service can modify this file, allowing immediate privilege escalation or denial of service.",
                        severity=target["criticality"],
                        status=Status.FAIL,
                        evidence=f"Path: {path}, Mode: {octal_mode}, Owner: {owner_name}:{group_name}",
                        recommendation=f"Immediately remove world-write permissions: `chmod o-w {path}`.",
                        technical_details=f"stat mode: {octal_mode}, S_IWOTH bit is set."
                    ))

                # Check 2: World Readable on sensitive credential stores
                elif target.get("must_not_be_world_readable") and is_world_readable:
                    findings.append(self.create_finding(
                        audit_id=audit_id,
                        title=f"Protected credential file {path} is world-readable",
                        description=f"The file {path} has permissions {octal_mode} allowing unprivileged local users to read it. Protected files such as shadow contain password hashes which must remain accessible strictly to root or designated shadow group.",
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        evidence=f"Path: {path}, Mode: {octal_mode}, Owner: {owner_name}:{group_name}",
                        recommendation=f"Restrict file read permissions: `chmod 0640 {path}` or `chmod 0600 {path}`.",
                        technical_details=f"stat mode: {octal_mode}, S_IROTH bit is set."
                    ))

                # Check 3: Unexpected ownership
                elif st.st_uid != 0 and "root" in target.get("expected_owners", []):
                    findings.append(self.create_finding(
                        audit_id=audit_id,
                        title=f"Sensitive file {path} is not owned by root",
                        description=f"File {path} is owned by user '{owner_name}' (UID {st.st_uid}) instead of root (UID 0). Non-root ownership allows the owning account to alter system security configuration.",
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        evidence=f"Path: {path}, Current Owner: {owner_name}, Expected: root",
                        recommendation=f"Change file ownership to root: `chown root {path}`.",
                        technical_details=f"st_uid={st.st_uid}"
                    ))
                else:
                    findings.append(self.create_finding(
                        audit_id=audit_id,
                        title=f"Permissions for {path} are correctly restricted",
                        description=f"File {path} has safe permissions ({octal_mode}) and is owned by {owner_name}:{group_name}.",
                        severity=Severity.INFO,
                        status=Status.PASS,
                        evidence=f"Path: {path}, Mode: {octal_mode}, Owner: {owner_name}:{group_name}",
                        recommendation="Maintain restrictive permissions.",
                        technical_details=f"Complies with expected maximum mode {oct(target['max_mode'])}."
                    ))
            except PermissionError:
                findings.append(self.create_finding(
                    audit_id=audit_id,
                    title=f"Insufficient privileges to inspect {path}",
                    description=f"Permission was denied when reading metadata for {path}. The file is likely protected as expected, but elevated privileges are needed to verify exact permissions.",
                    severity=Severity.INFO,
                    status=Status.NOT_AVAILABLE,
                    evidence=f"PermissionError on os.stat('{path}')",
                    recommendation="Run audit with appropriate read permissions to verify metadata.",
                    technical_details="os.stat raised PermissionError."
                ))
            except Exception as e:
                pass

        return findings

    def audit_world_writable_files(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []
        world_writable_found = []

        # Safe directories to scan without traversing virtual filesystems
        scan_dirs = settings.WORLD_WRITABLE_PATHS

        for base_dir in scan_dirs:
            if not os.path.exists(base_dir):
                continue

            try:
                for root, dirs, files in os.walk(base_dir, followlinks=False):
                    # Limit scan depth to avoid hanging
                    depth = root.count(os.sep) - base_dir.count(os.sep)
                    if depth > 3:
                        dirs.clear()
                        continue

                    for name in files:
                        file_path = os.path.join(root, name)
                        try:
                            # Use lstat to not follow symlinks
                            st = os.lstat(file_path)
                            if stat.S_ISREG(st.st_mode) and (st.st_mode & stat.S_IWOTH):
                                mode_oct = oct(stat.S_IMODE(st.st_mode))
                                owner, grp_name = self._get_owner_group_name(st.st_uid, st.st_gid)
                                world_writable_found.append({
                                    "path": file_path,
                                    "mode": mode_oct,
                                    "owner": f"{owner}:{grp_name}"
                                })
                        except (PermissionError, FileNotFoundError):
                            continue

                    # Also check directory permissions
                    for d_name in dirs:
                        dir_path = os.path.join(root, d_name)
                        try:
                            st = os.lstat(dir_path)
                            # Check world writable directory without sticky bit (stat.S_ISVTX)
                            if stat.S_ISDIR(st.st_mode) and (st.st_mode & stat.S_IWOTH) and not (st.st_mode & stat.S_ISVTX):
                                mode_oct = oct(stat.S_IMODE(st.st_mode))
                                owner, grp_name = self._get_owner_group_name(st.st_uid, st.st_gid)
                                world_writable_found.append({
                                    "path": dir_path + "/",
                                    "mode": mode_oct,
                                    "owner": f"{owner}:{grp_name}",
                                    "is_dir": True
                                })
                        except (PermissionError, FileNotFoundError):
                            continue
            except Exception:
                continue

        if world_writable_found:
            count = len(world_writable_found)
            sample_items = [f"{item['path']} ({item['mode']}, {item['owner']})" for item in world_writable_found[:5]]
            findings.append(self.create_finding(
                audit_id=audit_id,
                title=f"World-writable files or directories detected ({count} found)",
                description=f"Identified {count} world-writable files or directories within designated system paths ({', '.join(scan_dirs)}). World-writable regular files allow any unprivileged local user to modify application scripts or configuration.",
                severity=Severity.HIGH,
                status=Status.FAIL,
                evidence=f"Sample: {'; '.join(sample_items)}{' (and more...)' if count > 5 else ''}",
                recommendation="Remove world-write permissions using `chmod o-w <path>` or assign sticky bit to directories `chmod +t <dir>`.",
                technical_details="Identified regular files and non-sticky directories with stat.S_IWOTH flag set."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="No unsafe world-writable files identified in monitored paths",
                description=f"Scanned configured paths ({', '.join(scan_dirs)}) and found no regular files or non-sticky directories with world-writable permission bits.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"Paths searched: {', '.join(scan_dirs)}",
                recommendation="Maintain periodic scanning for newly created world-writable artifacts.",
                technical_details="Verified lack of stat.S_IWOTH on regular files."
            ))

        return findings

    def audit_suid_sgid(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []
        suid_binaries = []
        unusual_suid = []

        scan_dirs = settings.SUID_SCAN_PATHS

        for base_dir in scan_dirs:
            if not os.path.exists(base_dir):
                continue

            try:
                for entry in os.scandir(base_dir):
                    try:
                        if entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            mode = st.st_mode
                            is_suid = bool(mode & stat.S_ISUID)
                            is_sgid = bool(mode & stat.S_ISGID)

                            if is_suid or is_sgid:
                                octal = oct(stat.S_IMODE(mode))
                                owner, grp_name = self._get_owner_group_name(st.st_uid, st.st_gid)
                                full_path = entry.path

                                suid_binaries.append(full_path)
                                if full_path not in STANDARD_SUID_BINARIES:
                                    unusual_suid.append(f"{full_path} ({octal}, {owner}:{grp_name})")
                    except (PermissionError, FileNotFoundError):
                        continue
            except Exception:
                continue

        if unusual_suid:
            count = len(unusual_suid)
            findings.append(self.create_finding(
                audit_id=audit_id,
                title=f"Unusual or non-standard SUID/SGID binaries detected ({count} found)",
                description=f"Identified {count} executable file(s) with SetUID or SetGID permission bits that are not in the standard Linux system binary baseline. SUID binaries execute with the privileges of their owner (often root) and must be rigorously vetted to avoid privilege escalation.",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                evidence=f"Unusual SUID files: {'; '.join(unusual_suid[:5])}",
                recommendation="Review the necessity of SUID permissions for each non-standard binary. Remove SUID bit if not strictly required: `chmod u-s <path>`.",
                technical_details="Compared against known system baseline list of standard Linux SUID binaries."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="SUID/SGID executables conform to standard system baseline",
                description=f"Identified {len(suid_binaries)} SUID/SGID binaries, all belonging to standard system utilities (such as passwd, sudo, mount). No unknown or suspicious SUID binaries detected in monitored directories.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"Total standard SUID binaries: {len(suid_binaries)}",
                recommendation="Monitor file integrity of SUID binaries (e.g. using AIDE or auditd).",
                technical_details="Evaluated standard paths: " + ", ".join(scan_dirs)
            ))

        return findings

    def audit(self, audit_id: str) -> List[Finding]:
        results = []
        results.extend(self.audit_sensitive_files(audit_id))
        results.extend(self.audit_world_writable_files(audit_id))
        results.extend(self.audit_suid_sgid(audit_id))
        return results
