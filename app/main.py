from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import urlencode

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

GOOGLE_SCOPES = ("https://www.googleapis.com/auth/calendar.events",)
MAX_BODY_BYTES_DEFAULT = 1_048_576
MAX_EVENT_AGE_SECONDS_DEFAULT = 600


class ConfigError(RuntimeError):
    pass


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    init_db(settings)
    yield


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def parse_csv(raw: str, *, lower: bool = False) -> list[str]:
    values = []
    for item in raw.split(","):
        value = " ".join(item.strip().split())
        if not value:
            continue
        values.append(value.lower() if lower else value)
    return values


def parse_positive_int(raw: str | None, default: int) -> int:
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def build_app() -> FastAPI:
    docs_enabled = env_flag("ENABLE_API_DOCS", False)
    app_instance = FastAPI(
        title="Ms Sunshine",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )
    allowed_hosts = parse_csv(os.getenv("ALLOWED_HOSTS", ""))
    if allowed_hosts:
        app_instance.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    return app_instance


app = build_app()


@dataclass(frozen=True)
class Settings:
    channel_id: str
    channel_secret: str
    allowed_user_id: str
    allowed_group_ids: tuple[str, ...]
    trigger_phrases: tuple[str, ...]
    database_url: str
    db_path: Path
    admin_api_key: str
    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str
    google_calendar_id: str
    max_body_bytes: int
    max_event_age_seconds: int


@dataclass(frozen=True)
class LineMessageEvent:
    event_id: str
    user_id: str
    group_id: str
    text: str
    received_at: str


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    database_url = os.getenv("DATABASE_URL", "sqlite:///./data/sunshine.db").strip()
    db_path = resolve_sqlite_path(database_url)
    return Settings(
        channel_id=os.getenv("CHANNEL_ID", "").strip(),
        channel_secret=os.getenv("CHANNEL_SECRET", "").strip(),
        allowed_user_id=os.getenv("LINE_ALLOWED_USER_ID", "").strip(),
        allowed_group_ids=tuple(parse_csv(os.getenv("LINE_ALLOWED_GROUP_IDS", ""))),
        trigger_phrases=tuple(parse_csv(os.getenv("LINE_TRIGGER_PHRASES", "sunshine,Ms Sunshine"), lower=True)),
        database_url=database_url,
        db_path=db_path,
        admin_api_key=os.getenv("ADMIN_API_KEY", "").strip(),
        google_client_id=os.getenv("GOOGLE_CLIENT_ID", "").strip(),
        google_client_secret=os.getenv("GOOGLE_CLIENT_SECRET", "").strip(),
        google_redirect_uri=os.getenv("GOOGLE_REDIRECT_URI", "").strip(),
        google_calendar_id=os.getenv("GOOGLE_CALENDAR_ID", "").strip(),
        max_body_bytes=parse_positive_int(os.getenv("MAX_WEBHOOK_BODY_BYTES"), MAX_BODY_BYTES_DEFAULT),
        max_event_age_seconds=parse_positive_int(os.getenv("MAX_EVENT_AGE_SECONDS"), MAX_EVENT_AGE_SECONDS_DEFAULT),
    )


def resolve_sqlite_path(database_url: str) -> Path:
    prefix = "sqlite:///"
    if "://" in database_url and not database_url.startswith(prefix):
        raise ConfigError("Only sqlite:/// DATABASE_URL values are supported in this build")
    raw_path = database_url[len(prefix) :] if database_url.startswith(prefix) else database_url
    path = Path(raw_path)
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    return path


def redact(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return value[:4] + "…" + value[-4:]


def redact_database_url(database_url: str) -> str:
    if database_url.startswith("sqlite:///"):
        return database_url
    if "://" not in database_url:
        return database_url
    scheme, rest = database_url.split("://", 1)
    if "@" not in rest:
        return database_url
    _, host_part = rest.rsplit("@", 1)
    return f"{scheme}://***:***@{host_part}"


def settings_errors(settings: Settings) -> list[str]:
    errors: list[str] = []
    if not settings.channel_id:
        errors.append("CHANNEL_ID is required")
    if not settings.channel_secret:
        errors.append("CHANNEL_SECRET is required")
    if not settings.allowed_user_id:
        errors.append("LINE_ALLOWED_USER_ID is required")
    if not settings.trigger_phrases:
        errors.append("LINE_TRIGGER_PHRASES is required")
    if not settings.admin_api_key:
        errors.append("ADMIN_API_KEY is required for admin routes")
    if not settings.google_client_id:
        errors.append("GOOGLE_CLIENT_ID is required")
    if not settings.google_client_secret:
        errors.append("GOOGLE_CLIENT_SECRET is required")
    if not settings.google_redirect_uri:
        errors.append("GOOGLE_REDIRECT_URI is required")
    if not settings.google_calendar_id:
        errors.append("GOOGLE_CALENDAR_ID is required")
    return errors


def normalize_text(text: str) -> str:
    return " ".join(text.lower().strip().split())


def has_trigger(text: str, settings: Settings) -> bool:
    normalized = normalize_text(text)
    return any(trigger in normalized for trigger in settings.trigger_phrases)


def allowed_user(user_id: str, settings: Settings) -> bool:
    return bool(settings.allowed_user_id) and user_id == settings.allowed_user_id


def allowed_group(group_id: str, settings: Settings) -> bool:
    return bool(group_id) and (not settings.allowed_group_ids or group_id in settings.allowed_group_ids)


def ensure_admin(x_admin_key: str | None, settings: Settings) -> None:
    if not settings.admin_api_key:
        raise HTTPException(status_code=404, detail="not found")
    if not x_admin_key or not hmac.compare_digest(x_admin_key, settings.admin_api_key):
        raise HTTPException(status_code=401, detail="unauthorized")


def verify_line_signature(body: bytes, signature: str | None, settings: Settings) -> None:
    if not settings.channel_secret:
        raise HTTPException(status_code=503, detail="channel secret not configured")
    if not signature:
        raise HTTPException(status_code=401, detail="missing signature")
    digest = hmac.new(settings.channel_secret.encode("utf-8"), body, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode("utf-8")
    if not hmac.compare_digest(expected, signature.strip()):
        raise HTTPException(status_code=401, detail="invalid signature")


def parse_payload(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid json payload") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid payload")
    return payload


def is_recent_event(event: dict[str, Any], settings: Settings) -> bool:
    timestamp = event.get("timestamp")
    if not isinstance(timestamp, int):
        return False
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    age_ms = now_ms - timestamp
    return 0 <= age_ms <= settings.max_event_age_seconds * 1000


def stable_event_id(event: dict[str, Any]) -> str:
    webhook_event_id = event.get("webhookEventId")
    if isinstance(webhook_event_id, str) and webhook_event_id.strip():
        return webhook_event_id.strip()
    canonical = json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def extract_line_message_event(event: dict[str, Any], settings: Settings) -> LineMessageEvent | None:
    if event.get("type") != "message":
        return None
    message = event.get("message")
    source = event.get("source")
    if not isinstance(message, dict) or not isinstance(source, dict):
        return None
    if message.get("type") != "text":
        return None
    user_id = source.get("userId", "")
    group_id = source.get("groupId") or source.get("roomId") or ""
    text = message.get("text", "")
    if not isinstance(user_id, str) or not isinstance(group_id, str) or not isinstance(text, str):
        return None
    if not is_recent_event(event, settings):
        return None
    if not allowed_user(user_id, settings):
        return None
    if not allowed_group(group_id, settings):
        return None
    if not has_trigger(text, settings):
        return None
    return LineMessageEvent(
        event_id=stable_event_id(event),
        user_id=user_id,
        group_id=group_id,
        text=text.strip(),
        received_at=datetime.now(timezone.utc).isoformat(),
    )


def connect_db(settings: Settings) -> sqlite3.Connection:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.db_path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def init_db(settings: Settings) -> None:
    with connect_db(settings) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_event_id TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                note_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                due_at TEXT,
                timezone TEXT,
                calendar_event_id TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE
            )
            """
        )


def can_open_db(settings: Settings) -> bool:
    try:
        with connect_db(settings) as connection:
            connection.execute("SELECT 1")
        return True
    except sqlite3.Error:
        return False


def save_event(event: LineMessageEvent, settings: Settings) -> bool:
    try:
        with connect_db(settings) as connection:
            cursor = connection.execute(
                "INSERT INTO notes(source_event_id, user_id, group_id, text, created_at) VALUES(?,?,?,?,?)",
                (event.event_id, event.user_id, event.group_id, event.text, event.received_at),
            )
            connection.execute(
                "INSERT INTO tasks(note_id, title, due_at, timezone, calendar_event_id, status, created_at) VALUES(?,?,?,?,?,?,?)",
                (cursor.lastrowid, event.text[:120], None, None, None, "pending", event.received_at),
            )
        return True
    except sqlite3.IntegrityError:
        return False

@app.get("/health", include_in_schema=False)
def health() -> dict[str, bool]:
    return {"ok": True}


@app.get("/ready", include_in_schema=False)
def ready() -> JSONResponse:
    settings = get_settings()
    errors = settings_errors(settings)
    healthy = not errors and can_open_db(settings)
    status_code = 200 if healthy else 503
    return JSONResponse({"ok": healthy}, status_code=status_code)


@app.get("/admin/config", include_in_schema=False)
def admin_config(x_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
    settings = get_settings()
    ensure_admin(x_admin_key, settings)
    errors = settings_errors(settings)
    return {
        "ok": not errors,
        "errors": errors,
        "redacted": {
            "CHANNEL_ID": redact(settings.channel_id),
            "LINE_ALLOWED_USER_ID": redact(settings.allowed_user_id),
            "LINE_ALLOWED_GROUP_IDS": len(settings.allowed_group_ids),
            "LINE_TRIGGER_PHRASES": list(settings.trigger_phrases),
            "DATABASE_URL": redact_database_url(settings.database_url),
            "GOOGLE_CLIENT_ID": redact(settings.google_client_id),
            "GOOGLE_CALENDAR_ID": redact(settings.google_calendar_id),
        },
    }


@app.get("/admin/google/oauth-url", include_in_schema=False)
def admin_google_oauth_url(
    x_admin_key: str | None = Header(default=None),
    state: str = Query(default="sunshine-google-oauth"),
) -> dict[str, str]:
    settings = get_settings()
    ensure_admin(x_admin_key, settings)
    if not settings.google_client_id or not settings.google_redirect_uri:
        raise HTTPException(status_code=503, detail="google oauth is not configured")
    query = urlencode(
        {
            "client_id": settings.google_client_id,
            "redirect_uri": settings.google_redirect_uri,
            "response_type": "code",
            "scope": " ".join(GOOGLE_SCOPES),
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
    )
    return {"url": f"https://accounts.google.com/o/oauth2/v2/auth?{query}"}


@app.post("/webhook/line", include_in_schema=False)
async def line_webhook(request: Request, x_line_signature: str | None = Header(default=None)) -> dict[str, int]:
    settings = get_settings()
    body = await request.body()
    if len(body) > settings.max_body_bytes:
        raise HTTPException(status_code=413, detail="payload too large")
    verify_line_signature(body, x_line_signature, settings)
    payload = parse_payload(body)
    events = payload.get("events", [])
    if not isinstance(events, list):
        raise HTTPException(status_code=400, detail="events must be a list")

    accepted = 0
    ignored = 0
    for event in events:
        if not isinstance(event, dict):
            ignored += 1
            continue
        parsed = extract_line_message_event(event, settings)
        if not parsed:
            ignored += 1
            continue
        if save_event(parsed, settings):
            accepted += 1
        else:
            ignored += 1
    return {"accepted": accepted, "ignored": ignored}


@app.get("/admin/notes", include_in_schema=False)
def admin_notes(
    x_admin_key: str | None = Header(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, list[dict[str, Any]]]:
    settings = get_settings()
    ensure_admin(x_admin_key, settings)
    with connect_db(settings) as connection:
        rows = connection.execute(
            "SELECT id, source_event_id, user_id, group_id, text, created_at FROM notes ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return {"items": [dict(row) for row in rows]}
