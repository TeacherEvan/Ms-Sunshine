from __future__ import annotations

import os

KEYS = [
    "CHANNEL_ID",
    "CHANNEL_SECRET",
    "LINE_ALLOWED_USER_ID",
    "LINE_ALLOWED_GROUP_IDS",
    "LINE_TRIGGER_PHRASES",
    "ADMIN_API_KEY",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GOOGLE_REDIRECT_URI",
    "GOOGLE_CALENDAR_ID",
    "DATABASE_URL",
]


def redact(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return value[:4] + "…" + value[-4:]


for key in KEYS:
    print(f"{key}={redact(os.getenv(key, ''))}")
