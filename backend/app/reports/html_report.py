import html
from datetime import datetime
from app.models.audit import AuditDetail

class HtmlReportGenerator:
    @staticmethod
    def generate(audit: AuditDetail) -> str:
        """Generate a complete standalone HTML security audit report."""
        sev_colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
            "INFO": "#64748b"
        }
        
        status_badges = {
            "PASS": '<span style="background:#065f46;color:#34d399;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:600;">PASS</span>',
            "FAIL": '<span style="background:#7f1d1d;color:#f87171;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:600;">FAIL</span>',
            "WARNING": '<span style="background:#78350f;color:#fbbf24;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:600;">WARNING</span>',
            "NOT_AVAILABLE": '<span style="background:#334155;color:#94a3b8;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:600;">N/A</span>',
        }

        # Build findings rows
        findings_html = []
        for f in audit.findings:
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            stat_str = f.status.value if hasattr(f.status, "value") else str(f.status)
            color = sev_colors.get(sev_str, "#64748b")
            status_badge = status_badges.get(stat_str, stat_str)

            evidence_block = ""
            if f.evidence:
                evidence_block = f"""
                <div style="margin-top:8px;padding:8px 12px;background:#090d16;border-radius:6px;border-left:3px solid {color};font-family:monospace;font-size:13px;color:#cbd5e1;">
                    <strong>Evidence:</strong> {html.escape(f.evidence)}
                </div>
                """

            tech_block = ""
            if f.technical_details:
                tech_block = f"""
                <div style="margin-top:6px;font-size:12px;color:#64748b;">
                    <strong>Technical context:</strong> {html.escape(f.technical_details)}
                </div>
                """

            findings_html.append(f"""
            <div style="background:#131b2e;border:1px solid #1e293b;border-radius:8px;padding:16px;margin-bottom:14px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <div>
                        <span style="background:{color}22;color:{color};border:1px solid {color};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;margin-right:8px;">{sev_str}</span>
                        <span style="color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px;font-weight:600;">[{html.escape(f.category)}]</span>
                        <strong style="color:#f8fafc;font-size:16px;margin-left:8px;">{html.escape(f.title)}</strong>
                    </div>
                    <div>{status_badge}</div>
                </div>
                <p style="color:#94a3b8;font-size:14px;margin:6px 0;line-height:1.5;">{html.escape(f.description)}</p>
                {evidence_block}
                <div style="margin-top:10px;padding:8px 12px;background:#064e3b22;border:1px solid #04785744;border-radius:6px;color:#6ee7b7;font-size:13px;">
                    <strong>Remediation:</strong> {html.escape(f.recommendation)}
                </div>
                {tech_block}
            </div>
            """)

        all_findings_str = "\n".join(findings_html)

        # Risk score badge color
        if audit.risk_score >= 80:
            score_color = "#ef4444"
        elif audit.risk_score >= 60:
            score_color = "#f97316"
        elif audit.risk_score >= 40:
            score_color = "#eab308"
        elif audit.risk_score >= 20:
            score_color = "#3b82f6"
        else:
            score_color = "#10b981"

        mode_badge = '<span style="background:#f59e0b;color:#000;font-weight:bold;padding:4px 10px;border-radius:4px;font-size:12px;">DEMO MODE</span>' if audit.is_demo else '<span style="background:#10b981;color:#fff;font-weight:bold;padding:4px 10px;border-radius:4px;font-size:12px;">LIVE SYSTEM AUDIT</span>'

        sys_info = audit.system_info or {}
        sys_rows = "".join([f"<tr><td style='padding:6px 12px;color:#94a3b8;border-bottom:1px solid #1e293b;'>{html.escape(str(k))}</td><td style='padding:6px 12px;color:#f8fafc;border-bottom:1px solid #1e293b;font-family:monospace;'>{html.escape(str(v))}</td></tr>" for k, v in list(sys_info.items())[:12]])

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Security Audit Report - {html.escape(audit.hostname)}</title>
    <style>
        body {{
            background-color: #0b0f19;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #1e293b;
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: #131b2e;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 16px;
            text-align: center;
            flex: 1;
            margin: 0 8px;
        }}
        .score-circle {{
            font-size: 42px;
            font-weight: 800;
            color: {score_color};
            margin: 8px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #131b2e;
            border-radius: 8px;
            overflow: hidden;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin:0;font-size:26px;color:#f8fafc;letter-spacing:0.5px;">🛡️ LinuxSecAudit Assessment Report</h1>
                <p style="margin:4px 0 0 0;color:#94a3b8;font-size:14px;">Defensive Linux Configuration & Vulnerability Assessment</p>
            </div>
            <div>
                {mode_badge}
            </div>
        </div>

        <div style="display:flex;margin:0 -8px 24px -8px;">
            <div class="metric-card">
                <div style="color:#94a3b8;font-size:12px;text-transform:uppercase;font-weight:bold;">Overall Risk Score</div>
                <div class="score-circle">{audit.risk_score}<span style="font-size:20px;color:#64748b;">/100</span></div>
                <div style="font-size:13px;font-weight:bold;color:{score_color};">{audit.risk_level}</div>
            </div>
            <div class="metric-card">
                <div style="color:#94a3b8;font-size:12px;text-transform:uppercase;font-weight:bold;">Total Checks</div>
                <div style="font-size:36px;font-weight:800;color:#f8fafc;margin:8px 0;">{audit.total_checks}</div>
                <div style="font-size:13px;color:#34d399;">{audit.passed_checks} Passed | {audit.failed_checks} Failed | {audit.warning_count} Warnings</div>
            </div>
            <div class="metric-card">
                <div style="color:#94a3b8;font-size:12px;text-transform:uppercase;font-weight:bold;">High & Critical Risk</div>
                <div style="font-size:36px;font-weight:800;color:#ef4444;margin:8px 0;">{audit.critical_count + audit.high_count}</div>
                <div style="font-size:13px;color:#94a3b8;">{audit.critical_count} Critical, {audit.high_count} High, {audit.medium_count} Med</div>
            </div>
        </div>

        <div style="margin-bottom:30px;">
            <h2 style="font-size:18px;color:#f8fafc;border-left:4px solid #3b82f6;padding-left:10px;margin-bottom:12px;">System Profile</h2>
            <table>
                {sys_rows}
            </table>
        </div>

        <div style="margin-bottom:30px;">
            <h2 style="font-size:18px;color:#f8fafc;border-left:4px solid #3b82f6;padding-left:10px;margin-bottom:12px;">Detailed Security Findings & Remediation</h2>
            {all_findings_str}
        </div>

        <div style="margin-top:40px;padding:16px;background:#0f172a;border:1px solid #1e293b;border-radius:8px;font-size:12px;color:#64748b;line-height:1.6;">
            <strong>Audit Disclaimer & Methodology:</strong> This report was generated by LinuxSecAudit defensive auditing engine. 
            The scoring algorithm calculates raw penalties based on CIS/NIST severity weighting (Critical: 10, High: 7, Medium: 4, Low: 2, Info: 0) with status multipliers.
            This tool performs configuration analysis and defensive checks; it does not constitute an exhaustive penetration test. All remediations should be tested in staging environments prior to production application.
            <br><em>Report Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Host: {html.escape(audit.hostname)}</em>
        </div>
    </div>
</body>
</html>
        """
