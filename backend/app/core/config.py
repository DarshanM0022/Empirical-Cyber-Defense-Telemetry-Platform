import os
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "AegisX Cybersecurity Platform"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str = os.getenv("AEGISX_DATABASE_URL", "sqlite:///./aegisx.db")
    SECRET_KEY: str = os.getenv("AEGISX_SECRET_KEY", "aegisx-dev-secret-key-change-in-prod")
    DEFAULT_ORGANIZATION: str = os.getenv("AEGISX_DEFAULT_ORGANIZATION", "SecOps-Primary")
    SCANNER_USER_AGENT: str = "AegisX-Defensive-Security-Scanner/0.1 (+https://github.com/aegisx/security)"
    SCANNER_TIMEOUT_SECONDS: float = 10.0

settings = Settings()
