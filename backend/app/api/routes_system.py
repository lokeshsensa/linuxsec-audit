from fastapi import APIRouter, Depends
from typing import Dict, Any, List
from app.config import settings
from app.auditors.system import SystemAuditor
from app.auditors.services import ServiceAuditor
from app.auditors.network import NetworkAuditor
from app.demo.demo_data import get_demo_system_info, get_demo_services, get_demo_listening_ports

router = APIRouter(tags=["System"])

@router.get("/health")
def get_health() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "demo_mode": settings.DEMO_MODE,
    }

@router.get("/system")
def get_system_profile() -> Dict[str, Any]:
    if settings.DEMO_MODE:
        return get_demo_system_info()
    return SystemAuditor().collect_info()

@router.get("/services")
def get_services() -> List[Dict[str, Any]]:
    if settings.DEMO_MODE:
        return get_demo_services()
    return ServiceAuditor.list_services()

@router.get("/network/ports")
def get_network_ports() -> List[Dict[str, Any]]:
    if settings.DEMO_MODE:
        return get_demo_listening_ports()
    return NetworkAuditor.get_listening_ports()
