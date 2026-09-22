"""
Application configuration loaded from environment variables / .env file.
All settings have sensible defaults so the app runs without any .env file.
"""

import os
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Gemini AI ──────────────────────────────────────────────────────────────
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"

    # ── Limits ─────────────────────────────────────────────────────────────────
    max_file_size_mb: int = 10
    text_max_chars: int = 50_000
    url_fetch_timeout: float = 8.0
    domain_lookup_timeout: float = 5.0

    # ── Database ───────────────────────────────────────────────────────────────
    database_url: str = "sqlite:///./inspector.db"

    # ── CORS ───────────────────────────────────────────────────────────────────
    cors_origins: str = "*"

    # ── Scoring thresholds (configurable) ─────────────────────────────────────
    domain_new_days: int = 30      # under this → max domain penalty
    domain_young_days: int = 90    # under this → medium domain penalty
    domain_mature_days: int = 365  # under this → low penalty

    class Config:
        env_file = os.path.join(os.path.dirname(__file__), ".env")
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"

    @property
    def max_file_size_bytes(self) -> int:
        return self.max_file_size_mb * 1024 * 1024

    @property
    def cors_origins_list(self) -> list[str]:
        if self.cors_origins == "*":
            return ["*"]
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
