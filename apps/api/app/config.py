"""Environment configuration validated at boot."""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # core
    database_url: str = Field(default="postgresql+psycopg://audit:audit@localhost:5432/audit")
    redis_url: str = Field(default="redis://localhost:6379/0")

    # storage
    s3_endpoint: str | None = None
    s3_region: str = "us-east-1"
    s3_bucket: str = "virgil"
    s3_access_key: str | None = None
    s3_secret_key: str | None = None

    # limits
    job_timeout_seconds: int = 900
    max_repo_bytes: int = 524_288_000  # 500 MB
    max_upload_bytes: int = 524_288_000

    # llm
    llm_provider: str = "anthropic"
    llm_model: str = "claude-opus-4-7"
    llm_max_tokens_per_audit: int = 200_000
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None

    # api
    api_cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # secrets
    secret_encryption_key: str | None = None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
