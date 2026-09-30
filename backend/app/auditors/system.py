import os
import platform
import socket
import sys
import shutil
from typing import Dict, Any, List, Tuple
from app.auditors.base import BaseAuditor
from app.models.finding import Finding, Severity, Status
from app.core.command_runner import CommandRunner

class SystemAuditor(BaseAuditor):
    category = "System"

    def collect_info(self) -> Dict[str, Any]:
        """Collect comprehensive system information safely."""
        info: Dict[str, Any] = {
            "hostname": socket.gethostname(),
            "os_name": platform.system(),
            "os_release": platform.release(),
            "kernel_version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "current_user": "unknown",
            "current_uid": -1,
            "privilege_level": "Standard User",
            "distribution": "Unknown Linux",
            "uptime_seconds": 0,
            "uptime_human": "Unknown",
            "cpu_count": os.cpu_count() or 1,
            "memory_total_mb": 0,
            "memory_available_mb": 0,
            "disk_total_gb": 0.0,
            "disk_used_gb": 0.0,
            "disk_free_gb": 0.0,
            "disk_percent_used": 0.0,
            "package_manager": "None detected",
        }

        # Current user & UID
        try:
            import pwd
            uid = os.getuid()
            info["current_uid"] = uid
            info["current_user"] = pwd.getpwuid(uid).pw_name
            if uid == 0:
                info["privilege_level"] = "Root / UID 0"
            else:
                # Check sudo capability safely without prompting
                code, _, _ = CommandRunner.run(["id", "-Gn"])
                if any(grp in code for grp in ["sudo", "wheel", "admin"]):
                    info["privilege_level"] = "Standard User (Sudo Group Member)"
                else:
                    info["privilege_level"] = "Standard Unprivileged User"
        except Exception:
            info["current_user"] = os.getenv("USER", "unknown")

        # Distribution detection via /etc/os-release
        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    os_rel = {}
                    for line in f:
                        if "=" in line:
                            k, v = line.strip().split("=", 1)
                            os_rel[k] = v.strip('"\'')
                    info["distribution"] = os_rel.get("PRETTY_NAME", os_rel.get("NAME", "Linux"))
            except Exception:
                info["distribution"] = f"{platform.system()} {platform.release()}"
        else:
            info["distribution"] = f"{platform.system()} {platform.release()}"

        # Uptime via /proc/uptime if available
        if os.path.exists("/proc/uptime"):
            try:
                with open("/proc/uptime", "r", encoding="utf-8") as f:
                    up_secs = float(f.readline().split()[0])
                    info["uptime_seconds"] = int(up_secs)
                    days = int(up_secs // 86400)
                    hours = int((up_secs % 86400) // 3600)
                    minutes = int((up_secs % 3600) // 60)
                    info["uptime_human"] = f"{days}d {hours}h {minutes}m"
            except Exception:
                pass
        else:
            code, out, _ = CommandRunner.run(["uptime"])
            if code == 0 and out:
                info["uptime_human"] = out

        # Memory via /proc/meminfo
        if os.path.exists("/proc/meminfo"):
            try:
                mem = {}
                with open("/proc/meminfo", "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.split(":")
                        if len(parts) == 2:
                            mem[parts[0].strip()] = parts[1].strip()
                if "MemTotal" in mem:
                    total_kb = int(mem["MemTotal"].split()[0])
                    info["memory_total_mb"] = total_kb // 1024
                if "MemAvailable" in mem:
                    avail_kb = int(mem["MemAvailable"].split()[0])
                    info["memory_available_mb"] = avail_kb // 1024
            except Exception:
                pass

        # Disk usage via statvfs on root partition
        try:
            st = os.statvfs("/")
            total_bytes = st.f_blocks * st.f_frsize
            free_bytes = st.f_bavail * st.f_frsize
            used_bytes = total_bytes - free_bytes
            info["disk_total_gb"] = round(total_bytes / (1024 ** 3), 2)
            info["disk_free_gb"] = round(free_bytes / (1024 ** 3), 2)
            info["disk_used_gb"] = round(used_bytes / (1024 ** 3), 2)
            if total_bytes > 0:
                info["disk_percent_used"] = round((used_bytes / total_bytes) * 100, 1)
        except Exception:
            pass

        # Package manager detection
        for pm in ["apt", "dnf", "yum", "pacman", "zypper"]:
            if shutil.which(pm):
                info["package_manager"] = pm
                break

        return info

    def audit(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []
        info = self.collect_info()

        # Check: Running as root
        if info["current_uid"] == 0:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Audit running directly as root user",
                description="The security audit was executed under UID 0 (root). While root permits complete inspection of protected system files, running audit utilities as root may introduce operational risks if malicious input is encountered.",
                severity=Severity.LOW,
                status=Status.WARNING,
                evidence=f"UID: 0, User: {info['current_user']}",
                recommendation="Run auditing tools as a standard dedicated auditor user with targeted read-only capabilities or specific sudo rules where necessary.",
                technical_details="POSIX UID 0 possesses unrestricted kernel and filesystem rights."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Audit executed with standard user privileges",
                description="The audit process is running under an unprivileged user ID, adhering to the principle of least privilege.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"UID: {info['current_uid']}, User: {info['current_user']}, Level: {info['privilege_level']}",
                recommendation="Continue adhering to least privilege execution.",
                technical_details=f"Current effective UID: {info['current_uid']}"
            ))

        # Check: Disk space pressure
        if info["disk_percent_used"] >= 90.0:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Root partition disk usage critically high",
                description=f"Root partition disk space utilization is at {info['disk_percent_used']}%. High disk pressure can lead to denial of service, failure of security logging systems, and crash of critical daemons.",
                severity=Severity.HIGH,
                status=Status.FAIL,
                evidence=f"Total: {info['disk_total_gb']} GB, Used: {info['disk_used_gb']} GB ({info['disk_percent_used']}%)",
                recommendation="Investigate root disk consumption, archive or rotate large system logs, clean package cache, and extend filesystem capacity.",
                technical_details="Monitored via statvfs('/') filesystem block accounting."
            ))
        elif info["disk_percent_used"] >= 80.0:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Root partition disk usage elevated",
                description=f"Root partition is {info['disk_percent_used']}% full. System may soon face log rotation or service instability if storage grows unchecked.",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                evidence=f"Used: {info['disk_used_gb']} GB / {info['disk_total_gb']} GB ({info['disk_percent_used']}%)",
                recommendation="Monitor storage consumption and establish automated log rotation and cleanup policies.",
                technical_details="statvfs('/') threshold > 80%."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Root partition storage capacity healthy",
                description="Sufficient storage headroom is available on the root filesystem for logging and normal operations.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"Disk utilization: {info['disk_percent_used']}% ({info['disk_free_gb']} GB free)",
                recommendation="Maintain continuous storage monitoring.",
                technical_details="statvfs('/') threshold < 80%."
            ))

        return findings
