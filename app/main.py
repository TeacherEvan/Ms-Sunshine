from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

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
    raw_path = database_url.removeprefix(prefix)
    path = Path(raw_path)
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    return path


def redact(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-4:]


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
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS google_tokens (
                kind TEXT PRIMARY KEY,
                access_token TEXT NOT NULL,
                refresh_token TEXT,
                expires_at TEXT NOT NULL,
                scopes TEXT NOT NULL,
                updated_at TEXT NOT NULL
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
    with connect_db(settings) as connection:
        token_row = _load_token_row(connection)
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
        "google": {
            "connected": token_row is not None,
            "scopes": list(token_row.scopes) if token_row else [],
            "expires_at": token_row.expires_at.isoformat() if token_row else None,
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
            with connect_db(settings) as _sync_conn:
                note_id = _sync_conn.execute(
                    "SELECT id FROM notes WHERE source_event_id = ?",
                    (parsed.event_id,),
                ).fetchone()
                if note_id is not None:
                    sync_note_to_calendar(_sync_conn, note_id["id"])
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


# ---------------------------------------------------------------------------
# Google Calendar sync (added 2026-09-05)
# ---------------------------------------------------------------------------

GOOGLE_OAUTH_STATE = "sunshine-google-oauth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_CALENDAR_EVENTS_ENDPOINT = "https://www.googleapis.com/calendar/v3/calendars/{calendar_id}/events"
TOKEN_REFRESH_SKEW_SECONDS = 60


class GoogleAPIError(RuntimeError):
    """Raised when the Google HTTP API returns a non-2xx response."""


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    refresh_token: str | None
    expires_at: datetime
    scopes: tuple[str, ...]

    @property
    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        return self.expires_at <= now + __import__("datetime").timedelta(seconds=TOKEN_REFRESH_SKEW_SECONDS)

    def to_row(self) -> dict[str, str]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token or "",
            "expires_at": self.expires_at.isoformat(),
            "scopes": " ".join(self.scopes),
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


class GoogleCalendarClient:
    """Thin wrapper around Google OAuth + Calendar REST APIs.

    All HTTP I/O goes through `_request` so tests can subclass and override.
    """

    def __init__(self, settings, *, opener=urlopen) -> None:
        self._settings = settings
        self._opener = opener

    def _request(self, url: str, *, data: dict[str, str] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
        body: bytes | None = None
        req_headers = {"Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        if data is not None:
            body = urlencode(data).encode("utf-8")
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = UrlRequest(url, data=body, headers=req_headers, method="POST" if data is not None else "GET")
        try:
            with self._opener(request, timeout=10) as response:
                raw = response.read()
        except HTTPError as exc:
            raise GoogleAPIError(f"google api error: {exc.code}") from exc
        except URLError as exc:
            raise GoogleAPIError(f"google api unreachable: {exc.reason}") from exc
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GoogleAPIError("google api returned non-json body") from exc

    def exchange_code(self, code: str) -> TokenSet:
        settings = self._settings
        payload = self._request(
            GOOGLE_TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": settings.google_redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        return self._tokens_from_payload(payload)

    def refresh(self, refresh_token: str) -> TokenSet:
        settings = self._settings
        payload = self._request(
            GOOGLE_TOKEN_ENDPOINT,
            data={
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
        )
        return self._tokens_from_payload(payload, fallback_refresh=refresh_token)

    def _tokens_from_payload(self, payload: dict[str, Any], *, fallback_refresh: str | None = None) -> TokenSet:
        access = payload.get("access_token")
        if not access:
            raise GoogleAPIError("google token payload missing access_token")
        expires_in = int(payload.get("expires_in", 3600))
        expires_at = datetime.now(timezone.utc).replace(microsecond=0) + __import__("datetime").timedelta(seconds=expires_in)
        refresh = payload.get("refresh_token") or fallback_refresh
        scopes_raw = payload.get("scope", "")
        scopes = tuple(scopes_raw.split()) if scopes_raw else GOOGLE_SCOPES
        return TokenSet(
            access_token=access,
            refresh_token=refresh,
            expires_at=expires_at,
            scopes=scopes,
        )

    def create_event(
        self,
        token: TokenSet,
        *,
        summary: str,
        start_iso: str,
        end_iso: str,
        timezone_name: str = "UTC",
    ) -> str:
        url = GOOGLE_CALENDAR_EVENTS_ENDPOINT.format(calendar_id=self._settings.google_calendar_id)
        body = json.dumps(
            {
                "summary": summary,
                "start": {"dateTime": start_iso, "timeZone": timezone_name},
                "end": {"dateTime": end_iso, "timeZone": timezone_name},
            }
        ).encode("utf-8")
        request = UrlRequest(
            url,
            data=body,
            headers={
                "Authorization": f"Bearer {token.access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with self._opener(request, timeout=10) as response:
                raw = response.read()
        except HTTPError as exc:
            raise GoogleAPIError(f"google calendar error: {exc.code}") from exc
        except URLError as exc:
            raise GoogleAPIError(f"google calendar unreachable: {exc.reason}") from exc
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GoogleAPIError("google calendar returned non-json body") from exc
        event_id = payload.get("id")
        if not event_id:
            raise GoogleAPIError("google calendar response missing event id")
        return str(event_id)


# Module-level seam so tests can monkeypatch.
def _build_default_client(settings) -> GoogleCalendarClient:
    return GoogleCalendarClient(settings)


def _load_token_row(connection: sqlite3.Connection) -> TokenSet | None:
    row = connection.execute(
        "SELECT access_token, refresh_token, expires_at, scopes FROM google_tokens WHERE kind = 'google'"
    ).fetchone()
    if not row:
        return None
    access, refresh, expires_at_raw, scopes_raw = row["access_token"], row["refresh_token"], row["expires_at"], row["scopes"]
    return TokenSet(
        access_token=access,
        refresh_token=refresh or None,
        expires_at=_parse_iso(expires_at_raw),
        scopes=tuple(scopes_raw.split()) if scopes_raw else GOOGLE_SCOPES,
    )


def _save_token_row(connection: sqlite3.Connection, token: TokenSet) -> None:
    connection.execute(
        """
        INSERT INTO google_tokens(kind, access_token, refresh_token, expires_at, scopes, updated_at)
        VALUES('google', :access_token, :refresh_token, :expires_at, :scopes, :updated_at)
        ON CONFLICT(kind) DO UPDATE SET
            access_token = excluded.access_token,
            refresh_token = excluded.refresh_token,
            expires_at = excluded.expires_at,
            scopes = excluded.scopes,
            updated_at = excluded.updated_at
        """,
        {
            "access_token": token.access_token,
            "refresh_token": token.refresh_token or "",
            "expires_at": token.expires_at.isoformat(),
            "scopes": " ".join(token.scopes),
            "updated_at": _now_iso(),
        },
    )


def _delete_token_row(connection: sqlite3.Connection) -> int:
    cursor = connection.execute("DELETE FROM google_tokens WHERE kind = 'google'")
    return cursor.rowcount


def sync_note_to_calendar(
    connection: sqlite3.Connection,
    note_id: int,
    *,
    client_factory=None,
    settings_factory=get_settings,
    logger=print,
) -> str:
    """Best-effort calendar sync for a saved note.

    Returns the resulting task status ('synced' | 'sync_failed' | 'no_tokens').
    Never raises — failures are logged and recorded on the task row.
    """
    settings = settings_factory()
    if client_factory is None:
        client_factory = globals()["_build_default_client"]
    task_row = connection.execute(
        "SELECT id, title FROM tasks WHERE note_id = ? ORDER BY id DESC LIMIT 1",
        (note_id,),
    ).fetchone()
    if not task_row:
        return "no_tokens"
    task_id = task_row["id"]

    token = _load_token_row(connection)
    if token is None:
        return "no_tokens"

    try:
        if token.is_expired and token.refresh_token:
            refreshed = client_factory(settings).refresh(token.refresh_token)
            token = refreshed
            _save_token_row(connection, token)
        event_id = client_factory(settings).create_event(
            token,
            summary=task_row["title"],
            start_iso=datetime.now(timezone.utc).isoformat(),
            end_iso=(datetime.now(timezone.utc) + __import__("datetime").timedelta(minutes=30)).isoformat(),
        )
    except GoogleAPIError as exc:
        logger(f"calendar sync failed for note {note_id}: {exc}")
        connection.execute(
            "UPDATE tasks SET status = 'sync_failed' WHERE id = ?",
            (task_id,),
        )
        connection.commit()
        return "sync_failed"

    connection.execute(
        "UPDATE tasks SET calendar_event_id = ?, status = 'synced' WHERE id = ?",
        (event_id, task_id),
    )
    connection.commit()
    return "synced"


@app.get("/auth/google/callback", include_in_schema=False)
def auth_google_callback(
    code: str | None = None,
    state: str | None = None,
) -> dict[str, Any]:
    if not code or state != GOOGLE_OAUTH_STATE:
        raise HTTPException(status_code=400, detail="invalid oauth callback")
    settings = get_settings()
    if not settings.google_client_id or not settings.google_client_secret or not settings.google_redirect_uri:
        raise HTTPException(status_code=503, detail="google oauth is not configured")
    client = _build_default_client(settings)
    token = client.exchange_code(code)
    with connect_db(settings) as connection:
        _save_token_row(connection, token)
        connection.commit()
    return {"ok": True, "expires_at": token.expires_at.isoformat()}


@app.delete("/admin/google/token", include_in_schema=False)
def admin_google_token_delete(x_admin_key: str | None = Header(default=None)) -> dict[str, bool]:
    settings = get_settings()
    ensure_admin(x_admin_key, settings)
    with connect_db(settings) as connection:
        removed = _delete_token_row(connection)
        connection.commit()
    return {"ok": True, "removed": removed > 0}
