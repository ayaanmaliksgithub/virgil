from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql+psycopg://audit:audit@localhost:5432/audit"
    redis_url: str = "redis://localhost:6379/0"

    work_root: str = "/var/audit/work"

    s3_endpoint: str | None = None
    s3_region: str = "us-east-1"
    s3_bucket: str = "virgil"
    s3_access_key: str | None = None
    s3_secret_key: str | None = None

    scan_timeout_seconds: int = 600
    max_repo_bytes: int = 524_288_000

    llm_provider: str = "anthropic"
    llm_model: str = "claude-opus-4-7"
    llm_max_tokens_per_audit: int = 200_000
    # Hard global cap on Anthropic spend per UTC day. Once exceeded, every
    # provider call short-circuits to {} (same as the post-error circuit
    # breaker). Counter is per-day in Redis under virgil:llm:spend:YYYY-MM-DD.
    llm_daily_budget_usd: float = 10.0
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None

    semgrep_rulesets: str = "p/owasp-top-ten,p/security-audit,p/secrets"

    container_runtime: str = "docker"
    scanner_image: str = "virgil/scanner:latest"
    sandbox_cpus: str = "2"
    sandbox_memory: str = "4g"
    sandbox_pids: int = 512

    secret_encryption_key: str | None = None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
