"""Central configuration loaded from environment / .env."""
from __future__ import annotations

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mock_mode: bool = True

    # LLM
    llm_provider: str = "groq"            # groq | openrouter | mock
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    openrouter_api_key: str = ""
    openrouter_model: str = "meta-llama/llama-3.1-8b-instruct:free"

    # ServiceNow (SOAR / ticketing)
    servicenow_url: str = "http://localhost:8001"
    servicenow_user: str = "admin"
    servicenow_password: str = "admin"

    # Storage
    chroma_dir: str = "./data/chroma"
    sqlite_url: str = "sqlite:///./data/aegis.db"

    # Scanning
    default_scan_target: str = "http://localhost:5000"
    # built-in scanners only touch loopback/private hosts unless this is true
    allow_external_scans: bool = False

    @property
    def llm_is_live(self) -> bool:
        if self.mock_mode:
            return False
        if self.llm_provider == "groq":
            return bool(self.groq_api_key)
        if self.llm_provider == "openrouter":
            return bool(self.openrouter_api_key)
        return False


@lru_cache
def get_settings() -> Settings:
    return Settings()
