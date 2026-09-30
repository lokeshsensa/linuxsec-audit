import csv
import io
from app.models.audit import AuditDetail

class CsvReportGenerator:
    @staticmethod
    def generate(audit: AuditDetail) -> str:
        """Export findings to CSV format."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)

        # Header row
        writer.writerow([
            "Audit ID",
            "Hostname",
            "Finding ID",
            "Category",
            "Severity",
            "Status",
            "Title",
            "Description",
            "Evidence",
            "Recommendation",
            "Technical Details"
        ])

        for f in audit.findings:
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            stat_str = f.status.value if hasattr(f.status, "value") else str(f.status)
            writer.writerow([
                audit.id,
                audit.hostname,
                f.id,
                f.category,
                sev_str,
                stat_str,
                f.title,
                f.description,
                f.evidence or "",
                f.recommendation,
                f.technical_details or ""
            ])

        return output.getvalue()
