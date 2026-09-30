import os
import platform
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    APP_NAME: str = "LinuxSecAudit"
    VERSION: str = "1.0.0"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Auto-enable demo mode if not on Linux unless explicitly overridden
    DEMO_MODE: bool = os.getenv("DEMO_MODE", "true" if platform.system() != "Linux" else "false").lower() in ("true", "1", "yes")
    
    DATABASE_URL: str = f"sqlite:///{BASE_DIR}/linuxsec_audit.db"
    REPORTS_DIR: Path = BASE_DIR / "reports"
    LOGS_DIR: Path = BASE_DIR / "logs"
    LOG_FILE: Path = BASE_DIR / "logs" / "audit.log"
    
    # Safe scan directories
    WORLD_WRITABLE_PATHS: list[str] = ["/etc", "/opt", "/usr/local", "/var/log"]
    SUID_SCAN_PATHS: list[str] = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/opt", "/usr/local/bin"]
    
    # Command execution timeouts (in seconds)
    COMMAND_TIMEOUT: int = 10
    
    # Allowed origins for CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

# Ensure directories exist
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
settings.LOGS_DIR.mkdir(parents=True, exist_ok=True)
