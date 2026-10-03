"""Runtime settings, all from environment variables (THREATFEED_*)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"THREATFEED_{name}", default)


def _env_bool(name: str, default: bool = False) -> bool:
    return _env(name, "1" if default else "0").lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    db_path: str = field(default_factory=lambda: _env("DB_PATH", str(PROJECT_ROOT / "threatfeed.db")))
    base_url: str = field(default_factory=lambda: _env("BASE_URL", "http://localhost:8000"))
    poll_interval_seconds: int = field(default_factory=lambda: int(_env("POLL_INTERVAL", "60")))
    ingest_enabled: bool = field(default_factory=lambda: _env_bool("INGEST", True))
    researchers_path: str = field(
        default_factory=lambda: _env("RESEARCHERS", str(PROJECT_ROOT / "config" / "researchers.json"))
    )
    ads_path: str = field(default_factory=lambda: _env("ADS", str(PROJECT_ROOT / "config" / "ads.json")))

    # Source credentials. A source with no credentials it needs is skipped.
    x_bearer_token: str = field(default_factory=lambda: _env("X_BEARER_TOKEN"))
    bluesky_handle: str = field(default_factory=lambda: _env("BLUESKY_HANDLE"))
    bluesky_app_password: str = field(default_factory=lambda: _env("BLUESKY_APP_PASSWORD"))
    reddit_user_agent: str = field(
        default_factory=lambda: _env("REDDIT_USER_AGENT", "threat-feed/0.1 (security research aggregator)")
    )
    demo_source: bool = field(default_factory=lambda: _env_bool("DEMO_SOURCE", True))

    # Billing (Stripe). With no secret key, checkout is unavailable and only
    # the explicit dev-upgrade switch can grant Pro.
    stripe_secret_key: str = field(default_factory=lambda: _env("STRIPE_SECRET_KEY"))
    stripe_webhook_secret: str = field(default_factory=lambda: _env("STRIPE_WEBHOOK_SECRET"))
    stripe_pro_price_id: str = field(default_factory=lambda: _env("STRIPE_PRO_PRICE_ID"))
    pro_price_display: str = field(default_factory=lambda: _env("PRO_PRICE_DISPLAY", "$19/mo"))
    dev_billing: bool = field(default_factory=lambda: _env_bool("DEV_BILLING", False))

    # Optional third-party ad network for the Free tier (EthicalAds suits a
    # developer/security audience: no tracking cookies). Empty = house ads only.
    ethicalads_publisher: str = field(default_factory=lambda: _env("ETHICALADS_PUBLISHER"))


def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
