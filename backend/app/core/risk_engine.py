from typing import List, Dict, Any, Tuple
from app.models.finding import Finding, Severity, Status

# Documented severity weights
SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# Maximum reference penalty points before 0-100 normalization
# Calibrated so that typical systems with a few High/Medium findings land in Elevated/Moderate (30-55),
# while systems with multiple Critical/High vulnerabilities reach Critical (80-100).
MAX_REFERENCE_SCORE = 85.0

class RiskEngine:
    @staticmethod
    def calculate_score(findings: List[Finding]) -> Tuple[int, str, Dict[str, int]]:
        """
        Calculate transparent 0-100 risk score and level from audit findings.
        
        Methodology:
        Only non-PASS findings (FAIL and WARNING) contribute to risk penalty.
        Raw Risk Penalty = Sum(Severity_Weight * Status_Multiplier)
          where Status_Multiplier = 1.0 for FAIL, 0.6 for WARNING.
        Normalized Score = min(100, round((Raw Risk Penalty / MAX_REFERENCE_SCORE) * 100))
        """
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        
        status_counts = {
            "PASS": 0,
            "FAIL": 0,
            "WARNING": 0,
            "NOT_AVAILABLE": 0,
        }

        raw_penalty = 0.0

        for f in findings:
            # Count severity
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev_str in severity_counts:
                severity_counts[sev_str] += 1

            # Count status
            stat_str = f.status.value if hasattr(f.status, "value") else str(f.status)
            if stat_str in status_counts:
                status_counts[stat_str] += 1

            # Only contribute to risk score if check failed or issued a warning
            if stat_str in ("FAIL", "WARNING"):
                sev_enum = Severity(sev_str) if sev_str in Severity._value2member_map_ else Severity.INFO
                weight = SEVERITY_WEIGHTS.get(sev_enum, 0)
                multiplier = 1.0 if stat_str == "FAIL" else 0.6
                raw_penalty += (weight * multiplier)

        # Normalize to 0-100
        normalized_score = min(100, int(round((raw_penalty / MAX_REFERENCE_SCORE) * 100)))

        # Risk level determination based on specification:
        # 0–19: LOW RISK
        # 20–39: MODERATE RISK
        # 40–59: ELEVATED RISK
        # 60–79: HIGH RISK
        # 80–100: CRITICAL RISK
        if normalized_score >= 80:
            risk_level = "CRITICAL RISK"
        elif normalized_score >= 60:
            risk_level = "HIGH RISK"
        elif normalized_score >= 40:
            risk_level = "ELEVATED RISK"
        elif normalized_score >= 20:
            risk_level = "MODERATE RISK"
        else:
            risk_level = "LOW RISK"

        counts_summary = {**severity_counts, **status_counts}
        return normalized_score, risk_level, counts_summary
