"""Central environment configuration for Ledgerly's backend integrations.

Secrets are read only by the server process. The browser must never receive
OpenAI or Google OAuth client secrets.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env", override=False)


def _flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _integer(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _number(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _scopes() -> tuple[str, ...]:
    raw = os.getenv(
        "GMAIL_OAUTH_SCOPES",
        "https://www.googleapis.com/auth/gmail.readonly "
        "https://www.googleapis.com/auth/gmail.send openid email",
    )
    return tuple(dict.fromkeys(part.strip() for part in raw.split() if part.strip()))


@dataclass(frozen=True)
class Settings:
    supabase_url: str = os.getenv("SUPABASE_URL", "") or os.getenv("VITE_SUPABASE_URL", "")
    supabase_anon_key: str = os.getenv("SUPABASE_ANON_KEY", "") or os.getenv("VITE_SUPABASE_ANON_KEY", "")
    supabase_service_role_key: str = (os.getenv("SUPABASE_SECRET_KEY", "")
                                      or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")).strip()
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "").strip()
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-5.4-mini").strip() or "gpt-5.4-mini"
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").strip()
    openai_timeout_seconds: float = _number("OPENAI_TIMEOUT_SECONDS", 30, 1, 180)
    openai_max_retries: int = _integer("OPENAI_MAX_RETRIES", 2, 0, 5)
    ai_features_enabled: bool = _flag("AI_FEATURES_ENABLED")
    gmail_client_id: str = os.getenv("GMAIL_OAUTH_CLIENT_ID", "").strip()
    gmail_client_secret: str = os.getenv("GMAIL_OAUTH_CLIENT_SECRET", "").strip()
    gmail_redirect_uri: str = os.getenv("GMAIL_OAUTH_REDIRECT_URI", "").strip()
    gmail_scopes: tuple[str, ...] = _scopes()
    gmail_pubsub_topic: str = os.getenv("GMAIL_PUBSUB_TOPIC", "").strip()
    frontend_public_url: str = os.getenv("FRONTEND_PUBLIC_URL", "http://localhost:5173").strip().rstrip("/")
    gmail_features_enabled: bool = _flag("GMAIL_FEATURES_ENABLED")
    email_send_enabled: bool = _flag("EMAIL_SEND_ENABLED")
    integration_token_encryption_key: str = (
        os.getenv("INTEGRATION_TOKEN_ENCRYPTION_KEY", "").strip()
        or os.getenv("CLIO_TOKEN_ENCRYPTION_KEY", "").strip()
    )
    clio_client_id: str = os.getenv("CLIO_CLIENT_ID", "").strip()
    clio_client_secret: str = os.getenv("CLIO_CLIENT_SECRET", "").strip()
    clio_redirect_uri: str = os.getenv("CLIO_REDIRECT_URI", "").strip()
    clio_region: str = os.getenv("CLIO_REGION", "us").strip().lower()
    clio_default_currency: str = os.getenv("CLIO_DEFAULT_CURRENCY", "USD").strip().upper()
    clio_token_encryption_key: str = os.getenv("CLIO_TOKEN_ENCRYPTION_KEY", "").strip()
    clio_features_enabled: bool = _flag("CLIO_FEATURES_ENABLED")

    @property
    def supabase_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_anon_key and "YOUR_PROJECT" not in self.supabase_url)

    @property
    def openai_configured(self) -> bool:
        return bool(self.openai_api_key)

    @property
    def gmail_oauth_configured(self) -> bool:
        return bool(self.gmail_client_id and self.gmail_client_secret and self.gmail_redirect_uri
                    and self.integration_token_encryption_key and self.supabase_configured
                    and self.supabase_service_role_key)

    @property
    def clio_configured(self) -> bool:
        return bool(
            self.clio_features_enabled
            and self.clio_client_id
            and self.clio_client_secret
            and self.clio_redirect_uri
            and self.clio_token_encryption_key
            and self.supabase_configured
            and self.supabase_service_role_key
            and self.clio_region in {"us", "eu", "ca", "au"}
            and len(self.clio_default_currency) == 3
            and self.clio_default_currency.isalpha()
        )


settings = Settings()
