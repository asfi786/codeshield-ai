"""Application configuration for CodeShield AI.

Settings are loaded from environment variables (and an optional ``.env``
file) via pydantic-settings. Every field has a sane default so the
application boots with zero configuration and no network access is
performed at import time.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the CodeShield AI backend."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "CodeShield AI"
    version: str = "1.0.0"
    debug: bool = False
    github_token: str | None = None
    allowed_origins: list[str] = ["*"]
    max_files: int = 120
    max_files_deep: int = 300
    request_timeout: float = 30.0
    # "async": POST /analyze returns 202 + job id, work runs in background
    # (proper servers: Docker, Render, VPS).
    # "sync": POST /analyze runs the pipeline inline and returns the full
    # report (serverless hosts like Vercel where background tasks do not
    # survive the response).
    analyze_mode: str = "async"
    # Google OAuth sign-in (https://console.cloud.google.com/apis/credentials).
    # The OAuth client's authorized redirect URI must be
    # <origin>/api/v1/auth/google/callback.
    google_client_id: str | None = None
    google_client_secret: str | None = None
    # Secret used to sign session JWTs. Set a long random value in
    # production; when unset, an ephemeral secret is generated at startup
    # (sessions then don't survive restarts).
    session_secret: str | None = None


settings = Settings()
