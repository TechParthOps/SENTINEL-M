"""Central configuration (pydantic-settings). All env vars use SENTINEL_ prefix (ADR-001)."""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_", env_file=".env", extra="ignore", case_sensitive=False
    )

    app_name: str = "SENTINEL-M"
    version: str = "0.1.0"
    environment: str = "development"

    # Local-first data directory (SQLite DB lives here by default)
    data_dir: str = str(_BACKEND_DIR / "data")
    db_url: str = ""  # empty -> derive sqlite under data_dir

    # Security — operator MUST set SENTINEL_SECRET_KEY in real deployments
    secret_key: str = "insecure-development-key-do-not-use"
    token_ttl_minutes: int = 480
    allow_self_registration: bool = True  # non-admin roles may self-register (see SECURITY.md)
    ingest_token: str = ""  # optional X-Ingest-Token for telemetry collectors

    # Rate limiting (in-memory, per identity)
    ratelimit_enabled: bool = True
    login_ratelimit_per_min: int = 10
    ingest_ratelimit_per_min: int = 1200

    # Ingestion limits
    max_batch_events: int = 1000

    seed_admin_password: str = ""  # installer/smoke-test convenience; generated if empty

    @property
    def secret_key_is_insecure(self) -> bool:
        return self.secret_key in (
            "insecure-development-key-do-not-use",
            "change-me-generate-a-real-key",
            "",
        )

    def model_post_init(self, __context) -> None:  # noqa: D105
        if not self.db_url:
            Path(self.data_dir).mkdir(parents=True, exist_ok=True)
            self.db_url = f"sqlite:///{Path(self.data_dir).as_posix()}/sentinel.db"
        else:
            # ensure the local dir exists for sqlite urls
            if self.db_url.startswith("sqlite"):
                Path(self.data_dir).mkdir(parents=True, exist_ok=True)


settings = Settings()