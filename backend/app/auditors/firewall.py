from typing import List, Dict, Any, Tuple
from app.auditors.base import BaseAuditor
from app.models.finding import Finding, Severity, Status
from app.core.command_runner import CommandRunner

class FirewallAuditor(BaseAuditor):
    category = "Firewall"

    def _check_ufw(self) -> Tuple[bool, bool, str]:
        """Check UFW (Uncomplicated Firewall). Returns (detected, active, details)."""
        if not CommandRunner.is_available("ufw"):
            return False, False, ""
        code, stdout, stderr = CommandRunner.run(["ufw", "status"])
        if code == 0:
            is_active = "Status: active" in stdout
            return True, is_active, stdout
        return True, False, stderr or "UFW query requires elevated privileges or returned error"

    def _check_firewalld(self) -> Tuple[bool, bool, str]:
        """Check firewalld (Red Hat / Fedora / CentOS). Returns (detected, active, details)."""
        if not CommandRunner.is_available("firewall-cmd"):
            return False, False, ""
        code, stdout, stderr = CommandRunner.run(["firewall-cmd", "--state"])
        if code == 0 and "running" in stdout:
            return True, True, stdout
        return True, False, stderr or stdout or "firewall-cmd inactive"

    def _check_nftables(self) -> Tuple[bool, bool, str]:
        """Check nftables."""
        if not CommandRunner.is_available("nft"):
            return False, False, ""
        code, stdout, stderr = CommandRunner.run(["nft", "list", "ruleset"])
        if code == 0 and stdout:
            return True, True, "nftables rules active"
        return True, False, stderr or "nftables ruleset empty or unprivileged"

    def _check_iptables(self) -> Tuple[bool, bool, str]:
        """Check legacy iptables."""
        if not CommandRunner.is_available("iptables"):
            return False, False, ""
        code, stdout, stderr = CommandRunner.run(["iptables", "-L", "-n"])
        if code == 0:
            # Check if there are user-defined rules beyond default empty chains
            has_rules = len([line for line in stdout.splitlines() if line and not line.startswith("Chain") and not line.startswith("target")]) > 0
            return True, has_rules, "iptables rules present" if has_rules else "iptables chains default/empty"
        return True, False, stderr or "iptables query unprivileged"

    def audit(self, audit_id: str) -> List[Finding]:
        findings: List[Finding] = []

        ufw_detected, ufw_active, ufw_details = self._check_ufw()
        firewalld_detected, firewalld_active, firewalld_details = self._check_firewalld()
        nft_detected, nft_active, nft_details = self._check_nftables()
        ipt_detected, ipt_active, ipt_details = self._check_iptables()

        detected_frameworks = []
        if ufw_detected: detected_frameworks.append("ufw")
        if firewalld_detected: detected_frameworks.append("firewalld")
        if nft_detected: detected_frameworks.append("nftables")
        if ipt_detected: detected_frameworks.append("iptables")

        is_any_active = ufw_active or firewalld_active or nft_active or ipt_active

        if not detected_frameworks:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="No recognized Linux firewall tooling installed",
                description="None of the standard Linux host firewall utilities (ufw, firewalld, nftables, iptables) were detected on this machine. Without host-level packet filtering, all incoming network traffic reaches listening services directly.",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                evidence="No ufw, firewall-cmd, nft, or iptables found in PATH.",
                recommendation="Install and enable an appropriate host firewall for your distribution (e.g. `sudo apt install ufw && sudo ufw enable` or `sudo dnf install firewalld && sudo systemctl enable --now firewalld`). Note: Host firewalls may be optional if filtering is performed by an upstream hardware firewall or cloud security group.",
                technical_details="PATH check across standard Linux packet filtering binaries."
            ))
        elif is_any_active:
            active_names = []
            if ufw_active: active_names.append("UFW")
            if firewalld_active: active_names.append("firewalld")
            if nft_active: active_names.append("nftables")
            if ipt_active: active_names.append("iptables")

            findings.append(self.create_finding(
                audit_id=audit_id,
                title=f"Host firewall is active and filtering network traffic ({', '.join(active_names)})",
                description=f"Active host firewall mechanism verified: {', '.join(active_names)}. Inbound and outbound packets are governed by packet filtering rules, providing defense-in-depth against unauthorized service access.",
                severity=Severity.INFO,
                status=Status.PASS,
                evidence=f"Active firewall: {', '.join(active_names)}",
                recommendation="Regularly audit firewall rulesets to ensure obsolete port allowances are pruned.",
                technical_details=f"Verified active rules via {', '.join(active_names)} status commands."
            ))
        else:
            findings.append(self.create_finding(
                audit_id=audit_id,
                title="Firewall utilities present but host firewall is inactive or unconfigured",
                description=f"Firewall management tools were detected ({', '.join(detected_frameworks)}), but no active filtering ruleset or daemon was observed running. Unless upstream network security groups or cloud firewalls restrict ingress, listening ports remain directly reachable.",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                evidence=f"Detected: {', '.join(detected_frameworks)}, but none reported active filtering status.",
                recommendation="Enable host firewall (e.g., `sudo ufw enable` or `sudo systemctl start firewalld`). Ensure standard administration ports (like SSH) are allowed before enabling.",
                technical_details=f"Tools found: {', '.join(detected_frameworks)}; active=False."
            ))

        return findings
