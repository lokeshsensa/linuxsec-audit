import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.core.logger import audit_logger
from app.database.database import init_db, SessionLocal
from app.database.models import AuditRecord
from app.core.audit_engine import AuditEngine

# API Routers
from app.api.routes_system import router as system_router
from app.api.routes_audit import router as audit_router
from app.api.routes_findings import router as findings_router
from app.api.routes_reports import router as reports_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB schema
    audit_logger.info("Initializing database schema...")
    init_db()

    # Pre-seed initial audit if database is completely empty
    db = SessionLocal()
    try:
        count = db.query(AuditRecord).count()
        if count == 0:
            audit_logger.info("Database empty on initial start; executing initial baseline audit...")
            engine = AuditEngine()
            engine.run_audit(db=db)
    except Exception as e:
        audit_logger.warning(f"Initial seed audit skipped: {e}")
    finally:
        db.close()

    yield
    audit_logger.info("Shutting down LinuxSecAudit backend.")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Authorized Linux Defensive Security Auditing & Risk Assessment Platform",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all during development & local evaluation
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers under /api
app.include_router(system_router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(findings_router, prefix="/api")
app.include_router(reports_router, prefix="/api")

@app.get("/")
def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "mode": "DEMO_MODE" if settings.DEMO_MODE else "LIVE_MODE",
        "docs_url": "/docs",
        "health_url": "/api/health"
    }
