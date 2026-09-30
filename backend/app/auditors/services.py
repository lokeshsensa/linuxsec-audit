import shutil
from typing import List, Dict, Any
from app.auditors.base import BaseAuditor
from app.models.finding import Finding, Severity, Status
from app.core.command_runner import CommandRunner

# Services categorized by security implication
INSECURE_LEGACY_SERVICES = {
    "telnet": "Insecure unencrypted remote shell protocol; transmits credentials in cleartext.",
    "rsh": "Legacy unencrypted remote shell protocol without cryptographic verification.",
    "rlogin": "Legacy unencrypted remote login protocol; highly vulnerable to spoofing.",
    "rexec": "Legacy unencrypted remote execution daemon.",
    "nis": "Network Information Service; vulnerable to unauthorized credential enumeration.",
    "tftp": "Trivial File Transfer Protocol; unauthenticated and unencrypted.",
    "xinetd": "Legacy super-server that may spawn unencrypted services.",
    "vsftpd": "Standard FTP daemon transmitting credentials in plain text unless FTPS/TLS is strictly enforced.",
    "proftpd": "FTP daemon vulnerable to credential sniffing over cleartext.",
}

SENSITIVE_DAEMONS = {
    "redis": "In-memory datastore frequently targeted if bound to 0.0.0.0 without authentication.",
    "mongod": "Document database requiring strict authentication and local binding.",
    "mysqld": "Relational database server; should not be exposed directly to untrusted networks.",
    "postgresql": "PostgreSQL database server.",
    "docker": "Container daemon with root-equivalent socket access.",
}

class ServiceAuditor(BaseAuditor):
    category = "Services"

    @staticmethod
    def list_services() -> List[Dict[str, Any]]:
        """Safely fetch running system services."""
        services: List[Dict[str, Any]] = []

        if not CommandRunner.is_available("systemctl"):
            return services

        # Run systemctl list-units safely
        code, stdout, _ = CommandRunner.run([
            "systemctl", "list-units", "--type=service", "--state=running,failed", "--no-pager", "--no-legend"
        ])

        if code == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split(None, 4)
                if len(parts) >= 4:
                    unit_name = parts[0].strip()
                    load_state = parts[1].strip()
                    active_state = parts[2].strip()
                    sub_state = parts[3].strip()
                    description = parts[4].strip() if len(parts) > 4 else ""
                    services.append({
                        "name": unit_name,
                        "load": load_state,
                        "active": active_state,
                        "sub": sub_state,
                        "description": description,
                        "is_failed": sub_state == "failed" or active_state == "failed",
                    })

        return services

    def audit(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []

        if not CommandRunner.is_available("systemctl"):
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="systemctl utility unavailable",
                description="The systemctl command is not available in PATH. The host may be running a non-systemd init system (e.g., OpenRC, SysVinit, runit) or running in a container.",
                severity=Severity.INFO,
                status=Status.NOT_AVAILABLE,
                evidence="Command 'systemctl' not found.",
                recommendation="If auditing a container or lightweight VM, verify service supervision method.",
                technical_details="CommandRunner.is_available('systemctl') returned False."
            ))
            return findings

        services = self.list_services()

        # Check: Failed services
        failed_services = [s["name"] for s in services if s.get("is_failed")]
        if failed_services:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title=f"Failed system service units detected ({len(failed_services)} failed)",
                description=f"The following system services are in a failed state: {', '.join(failed_services[:5])}. Failed services can indicate system instability or broken security controls (e.g. failing firewall, logging, or antivirus agents).",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                evidence=f"Failed services: {', '.join(failed_services)}",
                recommendation="Investigate service failure causes using `journalctl -u <service_name>` and resolve errors.",
                technical_details="systemctl list-units reported sub_state == failed"
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="No failed systemd services detected",
                description="All active systemd units are running normally with no failed services reported.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"Total active services examined: {len(services)}",
                recommendation="Continue system health and uptime monitoring.",
                technical_details="systemctl state check: 0 failed units."
            ))

        # Check: Insecure legacy protocols
        running_names = [s["name"].lower() for s in services]
        detected_insecure = []
        for s_key, risk_desc in INSECURE_LEGACY_SERVICES.items():
            for name in running_names:
                if s_key in name:
                    detected_insecure.append(f"{name} ({risk_desc})")

        if detected_insecure:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Insecure legacy service protocol detected running",
                description=f"The system is running legacy or unencrypted network services: {'; '.join(detected_insecure)}. These protocols transmit passwords and data without encryption, exposing them to eavesdropping and man-in-the-middle attacks.",
                severity=Severity.HIGH,
                status=Status.FAIL,
                evidence=f"Insecure services: {'; '.join(detected_insecure)}",
                recommendation="Disable and mask legacy services: `sudo systemctl stop <svc> && sudo systemctl mask <svc>`. Transition to secure encrypted alternatives (SSH, SFTP, TLS).",
                technical_details="Identified against baseline of insecure legacy services."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="No legacy unencrypted services detected",
                description="Common legacy insecure protocols (telnet, rsh, rlogin, tftp) were not found running on the system.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence="No telnet, rsh, rlogin, tftp, or legacy FTP daemons found.",
                recommendation="Maintain policy preventing deployment of unencrypted administration daemons.",
                technical_details="Verified against INSECURE_LEGACY_SERVICES."
            ))

        # Check: Sensitive databases or daemons
        exposed_daemons = []
        for s_key, desc in SENSITIVE_DAEMONS.items():
            for name in running_names:
                if s_key in name:
                    exposed_daemons.append(f"{name} ({desc})")

        if exposed_daemons:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title=f"Sensitive database or management service running ({len(exposed_daemons)} detected)",
                description=f"Detected sensitive services running: {'; '.join(exposed_daemons)}. Ensure these services are bound exclusively to localhost (127.0.0.1) or protected by firewall rules and strong authentication.",
                severity=Severity.LOW,
                status=Status.WARNING,
                evidence=f"Services: {'; '.join(exposed_daemons)}",
                recommendation="Verify network binding addresses and authentication configuration for these services.",
                technical_details="Cross-referenced active units with high-value daemon catalog."
            ))

        return findings
