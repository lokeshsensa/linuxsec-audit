import re
from typing import List, Tuple
from app.auditors.base import BaseAuditor
from app.models.finding import Finding, Severity, Status
from app.core.command_runner import CommandRunner

class UpdateAuditor(BaseAuditor):
    category = "Updates"

    def _check_apt(self) -> Tuple[int, int, str]:
        """Check APT updates on Debian/Ubuntu safely (simulation flag -s)."""
        if not CommandRunner.is_available("apt-get"):
            return -1, -1, ""

        code, stdout, stderr = CommandRunner.run(["apt-get", "-s", "upgrade"])
        if code != 0:
            return -1, -1, stderr

        total_updates = 0
        security_updates = 0

        # Parse apt simulation output
        for line in stdout.splitlines():
            if line.startswith("Inst "):
                total_updates += 1
                if "security" in line.lower() or "cve" in line.lower():
                    security_updates += 1

        return total_updates, security_updates, f"APT detected {total_updates} upgradable packages ({security_updates} security)."

    def _check_dnf(self) -> Tuple[int, int, str]:
        """Check DNF updates on Fedora / RHEL / AlmaLinux / Rocky."""
        if not CommandRunner.is_available("dnf"):
            return -1, -1, ""

        code, stdout, stderr = CommandRunner.run(["dnf", "check-update", "--security"])
        # dnf check-update returns 100 if updates are available, 0 if none
        if code in (0, 100):
            lines = [l for l in stdout.splitlines() if l.strip() and not l.startswith("Last metadata")]
            sec_count = len(lines)
            return sec_count, sec_count, f"DNF detected {sec_count} security updates."
        return -1, -1, stderr

    def _check_pacman(self) -> Tuple[int, int, str]:
        """Check Pacman updates on Arch Linux."""
        if not CommandRunner.is_available("pacman"):
            return -1, -1, ""
        code, stdout, stderr = CommandRunner.run(["pacman", "-Qu"])
        if code == 0:
            lines = [l for l in stdout.splitlines() if l.strip()]
            return len(lines), 0, f"Pacman detected {len(lines)} pending package updates."
        return -1, -1, stderr

    def audit(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []

        total_upd = -1
        sec_upd = -1
        summary = ""

        if CommandRunner.is_available("apt-get"):
            total_upd, sec_upd, summary = self._check_apt()
        elif CommandRunner.is_available("dnf"):
            total_upd, sec_upd, summary = self._check_dnf()
        elif CommandRunner.is_available("pacman"):
            total_upd, sec_upd, summary = self._check_pacman()

        if total_upd == -1:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="System package update status could not be queried offline",
                description="Package manager simulation check did not return update metrics. This commonly occurs when local package cache has not been refreshed, network is unconfigured, or elevated privileges are required for package caches.",
                severity=Severity.INFO,
                status=Status.NOT_AVAILABLE,
                evidence="Package simulation returned non-zero status or tool uninstalled.",
                recommendation="Run package manager sync periodically (e.g. `sudo apt update` or `sudo dnf check-update`) to ensure vulnerability metadata is current.",
                technical_details="Attempted non-destructive simulation via apt-get -s / dnf check-update."
            ))
            return findings

        if sec_upd > 0:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title=f"Pending security updates detected ({sec_upd} security updates)",
                description=f"Identified {sec_upd} security-critical package update(s) available for installation out of {total_upd} total pending updates. Unpatched software can expose known CVE vulnerabilities to local or remote exploitation.",
                severity=Severity.HIGH if sec_upd > 5 else Severity.MEDIUM,
                status=Status.FAIL,
                evidence=summary,
                recommendation="Review and apply outstanding security packages using your distribution's update manager (e.g., `sudo apt-get upgrade -y` or `sudo dnf upgrade --security`). Test in staging first.",
                technical_details="Extracted from package simulation query."
            ))
        elif total_upd > 0:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title=f"General software updates available ({total_upd} packages)",
                description=f"There are {total_upd} general software packages available for upgrade. While no explicit security advisories were tagged in simulation, general updates frequently include bug fixes and stability improvements.",
                severity=Severity.LOW,
                status=Status.WARNING,
                evidence=summary,
                recommendation="Schedule regular maintenance window to apply pending package updates.",
                technical_details="Simulated package upgrade check."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="System packages appear fully up to date",
                description="No pending package upgrades or security advisories were detected based on local package cache.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence="0 pending updates reported by package manager.",
                recommendation="Continue periodic package cache updates and patching cadence.",
                technical_details="Package manager query reported 0 upgradable packages."
            ))

        return findings
