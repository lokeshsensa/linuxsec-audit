import sys
import argparse
from pathlib import Path
from app.config import settings
from app.core.audit_engine import AuditEngine
from app.reports.json_report import JsonReportGenerator
from app.reports.csv_report import CsvReportGenerator
from app.reports.html_report import HtmlReportGenerator
from app.database.database import init_db, SessionLocal

def main():
    parser = argparse.ArgumentParser(
        prog="LinuxSecAudit",
        description="Linux Security Audit Tool - Authorized defensive security configuration & vulnerability auditor"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Run a security audit on the local Linux system")
    audit_parser.add_argument("--demo", action="store_true", help="Force demo/simulation mode")
    audit_parser.add_argument("--json", action="store_true", help="Output audit results in JSON format")
    audit_parser.add_argument("--html", action="store_true", help="Output audit results in HTML format")
    audit_parser.add_argument("--csv", action="store_true", help="Output audit results in CSV format")
    audit_parser.add_argument("-o", "--output", type=str, help="Save report to specified file path")
    audit_parser.add_argument("-v", "--verbose", action="store_true", help="Display all individual checks and details")

    # Status / Info command
    info_parser = subparsers.add_parser("info", help="Show system overview and auditing capabilities")

    args = parser.parse_args()

    if not args.command or args.command == "audit":
        is_demo = True if getattr(args, "demo", False) else settings.DEMO_MODE

        # Initialize DB and run audit
        init_db()
        db = SessionLocal()
        try:
            engine = AuditEngine(demo_mode=is_demo)
            detail = engine.run_audit(db=db)
        finally:
            db.close()

        # Handle file exports
        if getattr(args, "json", False) or (args.output and args.output.endswith(".json")):
            out_content = JsonReportGenerator.generate(detail)
            if args.output:
                Path(args.output).write_text(out_content, encoding="utf-8")
                print(f"[+] JSON report saved to {args.output}")
            else:
                print(out_content)
            return

        if getattr(args, "html", False) or (args.output and args.output.endswith(".html")):
            out_content = HtmlReportGenerator.generate(detail)
            if args.output:
                Path(args.output).write_text(out_content, encoding="utf-8")
                print(f"[+] HTML report saved to {args.output}")
            else:
                print(out_content)
            return

        if getattr(args, "csv", False) or (args.output and args.output.endswith(".csv")):
            out_content = CsvReportGenerator.generate(detail)
            if args.output:
                Path(args.output).write_text(out_content, encoding="utf-8")
                print(f"[+] CSV report saved to {args.output}")
            else:
                print(out_content)
            return

        # Pretty Terminal Console Output
        banner = r"""
  _     _                  ____            _             _ _ _   
 | |   (_)_ __  _   ___  _/ ___|  ___  ___/ \  _   _  __| (_) |_ 
 | |   | | '_ \| | | \ \/ \___ \ / _ \/ __/ _ \| | | |/ _` | | __|
 | |___| | | | | |_| |>  < ___) |  __/ (_/ ___ \ |_| | (_| | | |_ 
 |_____|_|_| |_|\__,_/_/\_\____/ \___|\__/_/   \_\__,_|\__,_|_|\__|
        """
        print(banner)
        mode_str = "[DEMO MODE]" if detail.is_demo else "[LIVE SYSTEM AUDIT]"
        print(f"=== {mode_str} - HOST: {detail.hostname} ===")
        print(f"OS: {detail.os_name} | Kernel: {detail.system_info.get('kernel_version', 'N/A')}")
        print(f"Audit ID: {detail.id} | Timestamp: {detail.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print("-" * 65)
        print(f"OVERALL RISK SCORE : {detail.risk_score}/100 [{detail.risk_level}]")
        print(f"TOTAL CHECKS       : {detail.total_checks} (PASS: {detail.passed_checks} | FAIL: {detail.failed_checks} | WARN: {detail.warning_count})")
        print(f"SEVERITY BREAKDOWN : CRITICAL: {detail.critical_count} | HIGH: {detail.high_count} | MEDIUM: {detail.medium_count} | LOW: {detail.low_count}")
        print("-" * 65)

        print("\n[!] TOP SECURITY FINDINGS & RECOMMENDATIONS:")
        for idx, f in enumerate(detail.findings, 1):
            if f.status.value in ("FAIL", "WARNING") or getattr(args, "verbose", False):
                color_tag = f"[{f.severity.value}]"
                print(f"\n{idx}. {color_tag} {f.title} ({f.category}) - {f.status.value}")
                print(f"   Desc: {f.description}")
                if f.evidence:
                    print(f"   Evidence: {f.evidence}")
                print(f"   Fix:  {f.recommendation}")

        print("\n" + "=" * 65)
        print(f"[✓] Audit complete. To view in browser, start the dashboard or run:")
        print(f"    python -m app.cli audit --html -o report.html\n")

    elif args.command == "info":
        from app.auditors.system import SystemAuditor
        info = SystemAuditor().collect_info()
        print("\n=== LinuxSecAudit System Profile ===")
        for k, v in info.items():
            print(f"{k:20}: {v}")
        print()

if __name__ == "__main__":
    main()
