import re
import socket
from typing import List, Dict, Any, Tuple
from app.auditors.base import BaseAuditor
from app.models.finding import Finding, Severity, Status
from app.core.command_runner import CommandRunner

COMMON_PORTS_INFO = {
    21: ("FTP", "File Transfer Protocol (Cleartext)"),
    22: ("SSH", "Secure Shell Daemon"),
    23: ("Telnet", "Telnet Remote Shell (Insecure Cleartext)"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Hypertext Transfer Protocol (Cleartext)"),
    110: ("POP3", "Post Office Protocol (Cleartext)"),
    143: ("IMAP", "Internet Message Access Protocol (Cleartext)"),
    443: ("HTTPS", "HTTP over TLS/SSL"),
    3306: ("MySQL", "MySQL / MariaDB Database"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    6379: ("Redis", "Redis In-Memory Key-Value Store"),
    8080: ("HTTP-Alt", "Web Application / Proxy"),
    27017: ("MongoDB", "MongoDB NoSQL Database"),
}

HIGH_RISK_EXPOSED_PORTS = {21, 23, 6379, 27017, 3306, 5432}

class NetworkAuditor(BaseAuditor):
    category = "Network"

    @staticmethod
    def get_listening_ports() -> List[Dict[str, Any]]:
        """Safely fetch listening ports using ss or netstat."""
        ports: List[Dict[str, Any]] = []

        # Try ss first
        if CommandRunner.is_available("ss"):
            code, stdout, _ = CommandRunner.run(["ss", "-tuln"])
            if code == 0 and stdout:
                lines = stdout.splitlines()
                # Skip header
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[0].upper()
                        state = parts[1].upper()
                        local_addr = parts[4]

                        # Parse IP and port
                        # E.g. 0.0.0.0:22 or [::]:22 or 127.0.0.1:6379
                        port_num = None
                        ip_addr = local_addr
                        if ":" in local_addr:
                            ip_addr, port_str = local_addr.rsplit(":", 1)
                            ip_addr = ip_addr.strip("[]*")
                            try:
                                port_num = int(port_str)
                            except ValueError:
                                continue

                        if port_num is not None:
                            service_info = COMMON_PORTS_INFO.get(port_num, ("Unknown", "Service"))
                            is_loopback = ip_addr in ("127.0.0.1", "::1", "localhost")
                            ports.append({
                                "protocol": proto,
                                "state": state,
                                "address": ip_addr or "0.0.0.0",
                                "port": port_num,
                                "service_name": service_info[0],
                                "service_description": service_info[1],
                                "is_loopback": is_loopback,
                                "raw": local_addr
                            })
                return ports

        # Try netstat if ss is unavailable
        if CommandRunner.is_available("netstat"):
            code, stdout, _ = CommandRunner.run(["netstat", "-tuln"])
            if code == 0 and stdout:
                for line in stdout.splitlines():
                    if line.startswith(("tcp", "udp")):
                        parts = line.split()
                        if len(parts) >= 4:
                            proto = parts[0].upper()
                            local_addr = parts[3]
                            if ":" in local_addr:
                                ip_addr, port_str = local_addr.rsplit(":", 1)
                                try:
                                    port_num = int(port_str)
                                    service_info = COMMON_PORTS_INFO.get(port_num, ("Unknown", "Service"))
                                    is_loopback = ip_addr in ("127.0.0.1", "::1")
                                    ports.append({
                                        "protocol": proto,
                                        "state": "LISTEN",
                                        "address": ip_addr,
                                        "port": port_num,
                                        "service_name": service_info[0],
                                        "service_description": service_info[1],
                                        "is_loopback": is_loopback,
                                        "raw": local_addr
                                    })
                                except ValueError:
                                    continue
                return ports

        return ports

    def audit(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []
        listening_ports = self.get_listening_ports()

        if not listening_ports and not CommandRunner.is_available("ss") and not CommandRunner.is_available("netstat"):
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Network socket auditing tools (ss/netstat) unavailable",
                description="Neither 'ss' (iproute2) nor 'netstat' (net-tools) is installed in the system PATH. Unable to inspect active listening network sockets.",
                severity=Severity.INFO,
                status=Status.NOT_AVAILABLE,
                evidence="Neither 'ss' nor 'netstat' found in PATH.",
                recommendation="Install 'iproute2' to enable network socket auditing.",
                technical_details="CommandRunner.is_available returned False for ss and netstat."
            ))
            return findings

        # Check: Total listening ports count
        wildcard_ports = [p for p in listening_ports if not p["is_loopback"]]
        loopback_ports = [p for p in listening_ports if p["is_loopback"]]

        # Check: Dangerous unencrypted or internal database ports exposed on all interfaces (0.0.0.0 / ::)
        exposed_high_risk = []
        for p in wildcard_ports:
            port = p["port"]
            if port in HIGH_RISK_EXPOSED_PORTS:
                name, desc = COMMON_PORTS_INFO.get(port, ("Unknown", ""))
                exposed_high_risk.append(f"Port {port} ({name}) bound to {p['address']}")

        if exposed_high_risk:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="High-risk or database port exposed on public interface",
                description=f"The following sensitive or unencrypted services are listening on external network interfaces: {', '.join(exposed_high_risk)}. Exposing databases or unencrypted protocols to untrusted networks creates severe risk of unauthorized access or interception.",
                severity=Severity.HIGH,
                status=Status.FAIL,
                evidence=f"Exposed services: {', '.join(exposed_high_risk)}",
                recommendation="Bind database and management services strictly to loopback (127.0.0.1) in their configuration files, or block external access via host firewall.",
                technical_details="Identified listening socket bound to 0.0.0.0 or [::] matching HIGH_RISK_EXPOSED_PORTS."
            ))

        # Check: Overall listening attack surface
        if len(wildcard_ports) > 10:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title=f"Extensive network listening attack surface ({len(wildcard_ports)} exposed ports)",
                description=f"Identified {len(wildcard_ports)} ports listening on non-loopback network interfaces. Each exposed port expands the potential attack surface and requires ongoing patch management and monitoring.",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                evidence=f"Exposed ports count: {len(wildcard_ports)}, Loopback ports count: {len(loopback_ports)}",
                recommendation="Review all listening ports and decommission unneeded network services or bind them to 127.0.0.1.",
                technical_details=f"Ports: {', '.join(str(p['port']) for p in wildcard_ports[:10])}..."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Network listening ports within normal baseline",
                description=f"Found {len(wildcard_ports)} external listening port(s) and {len(loopback_ports)} loopback-restricted port(s). The listening attack surface is compact.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"Exposed ports: {', '.join(str(p['port']) for p in wildcard_ports) or 'None'}",
                recommendation="Maintain strict control over opened network services.",
                technical_details=f"Audited via {CommandRunner.is_available('ss') and 'ss' or 'netstat'}."
            ))

        return findings
