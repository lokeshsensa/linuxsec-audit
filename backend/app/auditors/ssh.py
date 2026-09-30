import os
import glob
from typing import List, Dict, Optional
from app.auditors.base import BaseAuditor
from app.models.finding import Finding, Severity, Status
from app.core.command_runner import CommandRunner

class SshAuditor(BaseAuditor):
    category = "SSH"

    def _parse_sshd_config(self) -> Dict[str, str]:
        """Safely parse sshd_config and drop-in configurations."""
        config: Dict[str, str] = {}
        paths = ["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*.conf")

        for path in paths:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            k = parts[0].strip().lower()
                            v = parts[1].strip()
                            # First directive takes precedence in OpenSSH, but we record configuration
                            if k not in config:
                                config[k] = v
            except Exception:
                continue
        return config

    def audit(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []
        sshd_config = self._parse_sshd_config()

        if not sshd_config and not os.path.exists("/etc/ssh/sshd_config"):
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="OpenSSH server configuration file not found",
                description="The OpenSSH daemon configuration file /etc/ssh/sshd_config does not exist. SSH server may not be installed or enabled on this system.",
                severity=Severity.INFO,
                status=Status.NOT_AVAILABLE,
                evidence="File /etc/ssh/sshd_config not present.",
                recommendation="If this host does not require remote SSH management, keeping SSH uninstalled reduces the attack surface.",
                technical_details="Checked /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf"
            ))
            return findings

        # 1. PermitEmptyPasswords (CRITICAL risk if yes)
        empty_pass = sshd_config.get("permitemptypasswords", "no").lower()
        if empty_pass == "yes":
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="SSH permits blank/empty passwords",
                description="The SSH daemon is explicitly configured with 'PermitEmptyPasswords yes'. This allows any account without a password set to be logged into over the network without authentication, leading to immediate system compromise.",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                evidence="PermitEmptyPasswords yes",
                recommendation="Immediately set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config and reload SSH daemon (`sudo systemctl reload sshd`).",
                technical_details="OpenSSH directive PermitEmptyPasswords controls unauthenticated access for blank passwords."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="SSH empty password logins disallowed",
                description="SSH correctly disallows login attempts with blank or empty passwords.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"PermitEmptyPasswords {empty_pass}",
                recommendation="Maintain 'PermitEmptyPasswords no'.",
                technical_details="OpenSSH directive PermitEmptyPasswords set to no (or defaulted)."
            ))

        # 2. PermitRootLogin (HIGH risk if yes)
        root_login = sshd_config.get("permitrootlogin", "prohibit-password").lower()
        if root_login == "yes":
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="SSH root login is permitted without restriction",
                description="Direct root login via SSH is enabled ('PermitRootLogin yes'). Attackers frequently target the root username with automated credential stuffing, brute force, and password spraying attacks.",
                severity=Severity.HIGH,
                status=Status.FAIL,
                evidence="PermitRootLogin yes",
                recommendation="Change 'PermitRootLogin' to 'no' (or 'prohibit-password' if key-based root login is mandatory for automation) in /etc/ssh/sshd_config.",
                technical_details="/etc/ssh/sshd_config PermitRootLogin=yes"
            ))
        elif root_login in ("no", "prohibit-password", "without-password"):
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="SSH direct root password login restricted",
                description=f"Direct SSH root login with password is restricted ('PermitRootLogin {root_login}').",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"PermitRootLogin {root_login}",
                recommendation="Best practice is 'PermitRootLogin no', requiring users to log in with an unprivileged account and elevate via sudo.",
                technical_details=f"PermitRootLogin set to {root_login}."
            ))

        # 3. PasswordAuthentication (MEDIUM risk if yes)
        pwd_auth = sshd_config.get("passwordauthentication", "yes").lower()
        if pwd_auth == "yes":
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="SSH password authentication is enabled",
                description="Password authentication is enabled ('PasswordAuthentication yes'). Passwords are vulnerable to brute-force attacks, credential stuffing, and phishing compared to asymmetric SSH public key authentication.",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                evidence="PasswordAuthentication yes",
                recommendation="Deploy SSH public keys (ed25519 or rsa-4096) for all authorized users and configure 'PasswordAuthentication no'.",
                technical_details="/etc/ssh/sshd_config PasswordAuthentication=yes"
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="SSH password authentication is disabled",
                description="Password authentication is disabled. Authentication relies on cryptographic public keys or multi-factor authentication, significantly reducing brute-force exposure.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"PasswordAuthentication {pwd_auth}",
                recommendation="Ensure private keys are secured with strong passphrases and protected with hardware tokens where feasible.",
                technical_details="PasswordAuthentication is configured to no."
            ))

        # 4. X11Forwarding (LOW risk if yes)
        x11_fwd = sshd_config.get("x11forwarding", "no").lower()
        if x11_fwd == "yes":
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="SSH X11 graphical forwarding is enabled",
                description="X11Forwarding is enabled ('X11Forwarding yes'). Unless the server specifically hosts interactive graphical applications, X11 forwarding introduces risks of keystroke logging and display sniffing on untrusted client sessions.",
                severity=Severity.LOW,
                status=Status.WARNING,
                evidence="X11Forwarding yes",
                recommendation="Disable X11 forwarding by setting 'X11Forwarding no' in /etc/ssh/sshd_config unless explicitly required.",
                technical_details="/etc/ssh/sshd_config X11Forwarding=yes"
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="SSH X11 forwarding is disabled",
                description="X11 forwarding is disabled, minimizing GUI attack vectors.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"X11Forwarding {x11_fwd}",
                recommendation="Maintain X11 forwarding disabled.",
                technical_details="X11Forwarding set to no."
            ))

        # 5. MaxAuthTries (Brute force limiting)
        max_tries_str = sshd_config.get("maxauthtries", "6")
        try:
            max_tries = int(max_tries_str)
            if max_tries > 4:
                findings.append(self.create_finding(
                    audit_id=audit_id,
                    title="SSH maximum authentication tries exceeds recommended limit",
                    description=f"MaxAuthTries is set to {max_tries} (default is 6). Setting a lower limit (e.g. 3 or 4) mitigates online brute force password guessing attempts per session.",
                    severity=Severity.LOW,
                    status=Status.WARNING,
                    evidence=f"MaxAuthTries {max_tries} (Recommended: <= 4)",
                    recommendation="Set 'MaxAuthTries 4' or lower in /etc/ssh/sshd_config.",
                    technical_details=f"MaxAuthTries={max_tries}"
                ))
            else:
                findings.append(self.create_finding(
                    audit_id=audit_id,
                    title="SSH maximum authentication tries is appropriately limited",
                    description=f"MaxAuthTries is set to {max_tries}.",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    evidence=f"MaxAuthTries {max_tries}",
                    recommendation="Continue enforcing low authentication retry limits.",
                    technical_details=f"MaxAuthTries={max_tries}"
                ))
        except ValueError:
            pass

        return findings
