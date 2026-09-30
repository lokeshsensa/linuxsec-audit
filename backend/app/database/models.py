import json
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class AuditRecord(Base):
    __tablename__ = "audits"

    id = Column(String(64), primary_key=True, index=True)
    hostname = Column(String(255), default="unknown")
    os_name = Column(String(255), default="Linux")
    is_demo = Column(Boolean, default=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(50), default="running")
    
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(50), default="LOW")
    
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    warning_count = Column(Integer, default=0)
    not_available_count = Column(Integer, default=0)
    
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    system_info_json = Column(Text, default="{}")

    # Relationships
    findings = relationship("FindingRecord", back_populates="audit", cascade="all, delete-orphan")

    def get_system_info(self) -> dict:
        try:
            return json.loads(self.system_info_json or "{}")
        except Exception:
            return {}

    def set_system_info(self, info: dict):
        self.system_info_json = json.dumps(info)


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, index=True)
    audit_id = Column(String(64), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    category = Column(String(100), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False, index=True)
    status = Column(String(50), nullable=False, index=True)
    evidence = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=False)
    technical_details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    audit = relationship("AuditRecord", back_populates="findings")
