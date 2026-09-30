from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import AuditRecord
from app.api.routes_audit import get_audit_by_id
from app.reports.json_report import JsonReportGenerator
from app.reports.csv_report import CsvReportGenerator
from app.reports.html_report import HtmlReportGenerator

router = APIRouter(tags=["Reports"])

@router.get("/reports/{audit_id}/json")
def get_report_json(audit_id: str, db: Session = Depends(get_db)):
    detail = get_audit_by_id(audit_id, db=db)
    json_data = JsonReportGenerator.generate(detail)
    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=linuxsec_audit_{audit_id}.json"}
    )

@router.get("/reports/{audit_id}/csv")
def get_report_csv(audit_id: str, db: Session = Depends(get_db)):
    detail = get_audit_by_id(audit_id, db=db)
    csv_data = CsvReportGenerator.generate(detail)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=linuxsec_audit_{audit_id}.csv"}
    )

@router.get("/reports/{audit_id}/html", response_class=HTMLResponse)
def get_report_html(audit_id: str, db: Session = Depends(get_db)):
    detail = get_audit_by_id(audit_id, db=db)
    html_content = HtmlReportGenerator.generate(detail)
    return HTMLResponse(content=html_content)
