import os
from typing import List
from app.auditors.base import BaseAuditor
from app.models.finding import Finding, Severity, Status

class KernelAuditor(BaseAuditor):
    category = "Kernel"

    def _read_sysctl(self, path: str) -> str:
        """Safely read a /proc/sys key."""
        if not os.path.exists(path):
            return ""
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return ""

    def audit(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []

        if not os.path.exists("/proc/sys"):
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Linux /proc/sys filesystem interface unavailable",
                description="The virtual /proc/sys interface is not available. The system is either non-Linux or operating in an isolated non-standard sandbox container.",
                severity=Severity.INFO,
                status=Status.NOT_AVAILABLE,
                evidence="Path /proc/sys does not exist.",
                recommendation="Run kernel hardening audit on a standard Linux kernel host or VM.",
                technical_details="os.path.exists('/proc/sys') returned False."
            ))
            return findings

        # 1. ASLR (Address Space Layout Randomization)
        aslr_val = self._read_sysctl("/proc/sys/kernel/randomize_va_space")
        if aslr_val == "2":
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Address Space Layout Randomization (ASLR) fully enabled",
                description="ASLR is set to mode 2 (Full Randomization). Stack, VDSO page, shared memory libraries, and data segments are randomized in memory, preventing buffer overflow and ROP chain exploitation.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence="kernel.randomize_va_space = 2",
                recommendation="Maintain kernel.randomize_va_space = 2 in /etc/sysctl.conf.",
                technical_details="/proc/sys/kernel/randomize_va_space is 2."
            ))
        elif aslr_val == "1":
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="ASLR only partially enabled (Conservative Randomization)",
                description="ASLR is set to mode 1 (Conservative). Stack, VDSO, and mmap are randomized, but heap/brk data segments remain predictable.",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                evidence="kernel.randomize_va_space = 1 (Expected: 2)",
                recommendation="Enable full ASLR by adding `kernel.randomize_va_space = 2` to /etc/sysctl.d/99-security.conf and running `sysctl -p`.",
                technical_details="/proc/sys/kernel/randomize_va_space is 1."
            ))
        elif aslr_val == "0":
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Address Space Layout Randomization (ASLR) is disabled",
                description="ASLR is completely disabled (0). Memory addresses are static, allowing memory corruption vulnerabilities and binary exploits to be weaponized reliably.",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                evidence="kernel.randomize_va_space = 0",
                recommendation="Immediately enable ASLR: `sysctl -w kernel.randomize_va_space=2` and persist in /etc/sysctl.conf.",
                technical_details="/proc/sys/kernel/randomize_va_space is 0."
            ))

        # 2. SUID Dumpable (Core dump security)
        dumpable_val = self._read_sysctl("/proc/sys/fs/suid_dumpable")
        if dumpable_val in ("0", ""):
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="SUID process core dumps disabled",
                description="suid_dumpable is configured to 0. Elevated or setuid binaries will not produce core dump files that unprivileged users could inspect for secrets or memory tokens.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"fs.suid_dumpable = {dumpable_val or '0'}",
                recommendation="Keep suid_dumpable disabled.",
                technical_details="/proc/sys/fs/suid_dumpable is 0."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="SUID process core dumps enabled or in debug mode",
                description=f"fs.suid_dumpable is set to {dumpable_val}. Core dumps of privileged processes can leak sensitive memory, cryptographic keys, or credentials to disk.",
                severity=Severity.HIGH,
                status=Status.FAIL,
                evidence=f"fs.suid_dumpable = {dumpable_val} (Expected: 0)",
                recommendation="Disable SUID core dumps: `sysctl -w fs.suid_dumpable=0`.",
                technical_details=f"fs.suid_dumpable={dumpable_val}"
            ))

        # 3. Kernel dmesg restrict
        dmesg_val = self._read_sysctl("/proc/sys/kernel/dmesg_restrict")
        if dmesg_val == "1":
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Kernel dmesg log buffer restricted to superusers",
                description="dmesg_restrict is set to 1. Unprivileged users cannot read the kernel syslog buffer, preventing enumeration of hardware addresses, memory mappings, and kernel crash signatures.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence="kernel.dmesg_restrict = 1",
                recommendation="Maintain kernel.dmesg_restrict = 1.",
                technical_details="/proc/sys/kernel/dmesg_restrict is 1."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Kernel dmesg log buffer accessible to unprivileged users",
                description="dmesg_restrict is set to 0. Any local user can execute `dmesg` to inspect kernel logs, which may reveal system memory layout, driver errors, or leaked sensitive identifiers.",
                severity=Severity.LOW,
                status=Status.WARNING,
                evidence=f"kernel.dmesg_restrict = {dmesg_val or '0'} (Expected: 1)",
                recommendation="Restrict dmesg access by configuring `kernel.dmesg_restrict = 1` in /etc/sysctl.d/99-security.conf.",
                technical_details="dmesg_restrict is 0."
            ))

        # 4. IP Forwarding
        ip_fwd = self._read_sysctl("/proc/sys/net/ipv4/ip_forward")
        if ip_fwd == "1":
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="IPv4 packet forwarding enabled",
                description="net.ipv4.ip_forward is set to 1. Unless this host is functioning as a router, VPN gateway, or container host (Docker/Kubernetes), IP forwarding can permit unauthorized network routing across interfaces.",
                severity=Severity.LOW,
                status=Status.WARNING,
                evidence="net.ipv4.ip_forward = 1",
                recommendation="If this machine is not a network router, disable forwarding: `sysctl -w net.ipv4.ip_forward=0`.",
                technical_details="/proc/sys/net/ipv4/ip_forward is 1."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="IPv4 packet forwarding is disabled",
                description="Host is not routing packets between interfaces, maintaining normal endpoint isolation.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence="net.ipv4.ip_forward = 0",
                recommendation="Keep ip_forward disabled on endpoint servers.",
                technical_details="net.ipv4.ip_forward is 0."
            ))

        return findings
