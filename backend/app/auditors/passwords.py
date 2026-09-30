import os
import re
from typing import List, Dict, Optional
from app.auditors.base import BaseAuditor
from app.models.finding import Finding, Severity, Status

class PasswordPolicyAuditor(BaseAuditor):
    category = "Passwords"

    # Best-practice security thresholds (CIS Benchmark aligned)
    RECOMMENDED_MIN_LEN = 12
    RECOMMENDED_MAX_DAYS = 90
    RECOMMENDED_MIN_DAYS = 1
    RECOMMENDED_WARN_AGE = 7

    def _parse_login_defs(self) -> Dict[str, str]:
        """Safely parse /etc/login.defs key-value configuration."""
        config: Dict[str, str] = {}
        if not os.path.exists("/etc/login.defs"):
            return config

        try:
            with open("/etc/login.defs", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        config[parts[0].upper()] = parts[1]
        except Exception:
            pass
        return config

    def _check_pam_quality(self) -> Optional[str]:
        """Check for pam_pwquality or pam_cracklib in /etc/pam.d/."""
        pam_files = [
            "/etc/pam.d/common-password",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth"
        ]
        for p_file in pam_files:
            if os.path.exists(p_file):
                try:
                    with open(p_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        if "pam_pwquality.so" in content:
                            return f"pam_pwquality enabled in {p_file}"
                        if "pam_cracklib.so" in content:
                            return f"pam_cracklib enabled in {p_file}"
                except Exception:
                    continue
        return None

    def audit(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []
        login_defs = self._parse_login_defs()

        if not login_defs and not os.path.exists("/etc/login.defs"):
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Login definitions (/etc/login.defs) not found",
                description="The standard Linux account policy file /etc/login.defs was not found on this system.",
                severity=Severity.LOW,
                status=Status.NOT_AVAILABLE,
                evidence="File /etc/login.defs does not exist.",
                recommendation="If on a custom distribution, verify where default user password aging policies are configured.",
                technical_details="POSIX /etc/login.defs path missing."
            ))
            return findings

        # 1. PASS_MIN_LEN (Minimum Password Length)
        min_len_val = login_defs.get("PASS_MIN_LEN")
        if min_len_val is not None:
            try:
                min_len = int(min_len_val)
                if min_len < self.RECOMMENDED_MIN_LEN:
                    findings.append(self.create_finding(
                        audit_id=audit_id,
                        title="Minimum password length below recommended security threshold",
                        description=f"The configured minimum password length in /etc/login.defs is {min_len} characters. Industry standards (CIS, NIST) recommend a minimum length of at least {self.RECOMMENDED_MIN_LEN} characters to protect against brute-force and offline credential cracking.",
                        severity=Severity.MEDIUM,
                        status=Status.FAIL,
                        evidence=f"PASS_MIN_LEN: {min_len} (Recommended: >= {self.RECOMMENDED_MIN_LEN})",
                        recommendation=f"Update PASS_MIN_LEN in /etc/login.defs to at least {self.RECOMMENDED_MIN_LEN} or enforce length via pam_pwquality.so `minlen={self.RECOMMENDED_MIN_LEN}`.",
                        technical_details=f"/etc/login.defs PASS_MIN_LEN={min_len}"
                    ))
                else:
                    findings.append(self.create_finding(
                        audit_id=audit_id,
                        title="Minimum password length satisfies security baseline",
                        description=f"Configured minimum password length is {min_len} characters, meeting or exceeding modern baseline requirements.",
                        severity=Severity.INFO,
                        status=Status.PASS,
                        evidence=f"PASS_MIN_LEN: {min_len}",
                        recommendation="Maintain strict password length requirements.",
                        technical_details=f"/etc/login.defs PASS_MIN_LEN={min_len}"
                    ))
            except ValueError:
                pass
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="PASS_MIN_LEN not explicitly defined in /etc/login.defs",
                description="PASS_MIN_LEN is not set in /etc/login.defs. Modern Linux systems often delegate length enforcement to PAM modules (pam_pwquality).",
                severity=Severity.LOW,
                status=Status.WARNING,
                evidence="PASS_MIN_LEN key absent in /etc/login.defs",
                recommendation="Explicitly define PASS_MIN_LEN in /etc/login.defs or verify pam_pwquality enforces minlen.",
                technical_details="Default system fallback applies when unconfigured."
            ))

        # 2. PASS_MAX_DAYS (Password Expiration / Aging)
        max_days_val = login_defs.get("PASS_MAX_DAYS")
        if max_days_val is not None:
            try:
                max_days = int(max_days_val)
                if max_days > self.RECOMMENDED_MAX_DAYS or max_days >= 99999:
                    findings.append(self.create_finding(
                        audit_id=audit_id,
                        title="Password maximum lifetime is too long or infinite",
                        description=f"PASS_MAX_DAYS is configured as {max_days} days. Passwords that never expire or have extended lifespans increase exposure window if credentials are leaked or compromised.",
                        severity=Severity.MEDIUM,
                        status=Status.WARNING,
                        evidence=f"PASS_MAX_DAYS: {max_days} (Recommended: <= {self.RECOMMENDED_MAX_DAYS})",
                        recommendation=f"Configure PASS_MAX_DAYS in /etc/login.defs to a reasonable rotation cycle (e.g. {self.RECOMMENDED_MAX_DAYS} days) according to organizational security policy.",
                        technical_details=f"/etc/login.defs PASS_MAX_DAYS={max_days}"
                    ))
                else:
                    findings.append(self.create_finding(
                        audit_id=audit_id,
                        title="Password expiration lifetime complies with policy",
                        description=f"PASS_MAX_DAYS is set to {max_days} days.",
                        severity=Severity.INFO,
                        status=Status.PASS,
                        evidence=f"PASS_MAX_DAYS: {max_days}",
                        recommendation="Ensure password rotation procedures are documented.",
                        technical_details=f"/etc/login.defs PASS_MAX_DAYS={max_days}"
                    ))
            except ValueError:
                pass

        # 3. PASS_MIN_DAYS
        min_days_val = login_defs.get("PASS_MIN_DAYS")
        if min_days_val is not None:
            try:
                min_days = int(min_days_val)
                if min_days < self.RECOMMENDED_MIN_DAYS:
                    findings.append(self.create_finding(
                        audit_id=audit_id,
                        title="Minimum password change delay not enforced",
                        description=f"PASS_MIN_DAYS is set to {min_days}. Without a minimum change interval, users forced to change passwords can immediately cycle back to their original password.",
                        severity=Severity.LOW,
                        status=Status.WARNING,
                        evidence=f"PASS_MIN_DAYS: {min_days} (Recommended: >= {self.RECOMMENDED_MIN_DAYS})",
                        recommendation=f"Set PASS_MIN_DAYS to at least {self.RECOMMENDED_MIN_DAYS} in /etc/login.defs.",
                        technical_details=f"/etc/login.defs PASS_MIN_DAYS={min_days}"
                    ))
            except ValueError:
                pass

        # 4. PAM Complexity Enforcement
        pam_status = self._check_pam_quality()
        if pam_status:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="PAM password complexity enforcement module detected",
                description="The system uses a dedicated PAM password quality module (such as pam_pwquality or pam_cracklib) to enforce entropy and complexity rules.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=pam_status,
                recommendation="Periodically review /etc/security/pwquality.conf to ensure minimum credit parameters are configured.",
                technical_details="Inspected /etc/pam.d/* files."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="PAM password complexity enforcement module not identified",
                description="Neither pam_pwquality nor pam_cracklib could be confirmed in standard PAM authentication stacks. Users may be allowed to set simple, predictable passwords.",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                evidence="No active pam_pwquality.so or pam_cracklib.so found in /etc/pam.d/ common configuration files.",
                recommendation="Install and configure libpam-pwquality (Debian/Ubuntu) or pam_pwquality (RHEL/CentOS) and configure minlen, dcredit, ucredit, and lcredit.",
                technical_details="Standard PAM stack search."
            ))

        return findings
