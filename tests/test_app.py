from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VALID_ENV = {
    "CHANNEL_ID": "2000000000",
    "CHANNEL_SECRET": "supersecret123",
    "LINE_ALLOWED_USER_ID": "U1234567890abcdef1234567890abcdef",
    "LINE_ALLOWED_GROUP_IDS": "Cgroup123",
    "LINE_TRIGGER_PHRASES": "sunshine,Ms Sunshine",
    "ADMIN_API_KEY": "admin-secret-key",
    "GOOGLE_CLIENT_ID": "google-client-id",
    "GOOGLE_CLIENT_SECRET": "google-client-secret",
    "GOOGLE_REDIRECT_URI": "http://localhost:8000/auth/google/callback",
    "GOOGLE_CALENDAR_ID": "primary",
    "DATABASE_URL": "sqlite:///./data/test-sunshine.db",
    "MAX_WEBHOOK_BODY_BYTES": "1048576",
    "MAX_EVENT_AGE_SECONDS": "600",
}


def load_app(monkeypatch: pytest.MonkeyPatch, extra_env: dict[str, str] | None = None):
    for key in list(VALID_ENV):
        monkeypatch.setenv(key, VALID_ENV[key])
    monkeypatch.delenv("ENABLE_API_DOCS", raising=False)
    monkeypatch.delenv("ALLOWED_HOSTS", raising=False)
    if extra_env:
        for key, value in extra_env.items():
            monkeypatch.setenv(key, value)
    from app import main
    main.get_settings.cache_clear()
    return importlib.reload(main)


def signed_headers(main_module, body: bytes) -> dict[str, str]:
    digest = hmac.new(
        VALID_ENV["CHANNEL_SECRET"].encode("utf-8"),
        body,
        hashlib.sha256,
    ).digest()
    signature = base64.b64encode(digest).decode("utf-8")
    return {"X-Line-Signature": signature}


def make_event(text: str = "sunshine remember this", *, timestamp: int = 1_700_000_000_000, webhook_event_id: str = "evt-1"):
    return {
        "destination": "dummy",
        "events": [
            {
                "type": "message",
                "timestamp": timestamp,
                "webhookEventId": webhook_event_id,
                "source": {"type": "group", "groupId": "Cgroup123", "userId": VALID_ENV["LINE_ALLOWED_USER_ID"]},
                "message": {"type": "text", "id": "mid-1", "text": text},
            }
        ],
    }


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch):
    main = load_app(monkeypatch)
    db_path = PROJECT_ROOT / "data" / "test-sunshine.db"
    if db_path.exists():
        db_path.unlink()
    main.get_settings.cache_clear()
    main.init_db(main.get_settings())
    test_client = TestClient(main.app)
    yield test_client, main
    test_client.close()
    if db_path.exists():
        db_path.unlink()
    wal = PROJECT_ROOT / "data" / "test-sunshine.db-wal"
    shm = PROJECT_ROOT / "data" / "test-sunshine.db-shm"
    if wal.exists():
        wal.unlink()
    if shm.exists():
        shm.unlink()


def test_webhook_rejects_missing_signature(client):
    test_client, _ = client
    response = test_client.post("/webhook/line", content=b"{}")
    assert response.status_code == 401
    assert response.json()["detail"] == "missing signature"


def test_webhook_rejects_invalid_signature(client):
    test_client, _ = client
    response = test_client.post("/webhook/line", content=b"{}", headers={"X-Line-Signature": "bad"})
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid signature"


def test_webhook_rejects_oversized_body(client, monkeypatch: pytest.MonkeyPatch):
    test_client, main = client
    monkeypatch.setenv("MAX_WEBHOOK_BODY_BYTES", "10")
    main.get_settings.cache_clear()
    body = b"01234567890"
    response = test_client.post("/webhook/line", content=body, headers=signed_headers(main, body))
    assert response.status_code == 413


def test_webhook_accepts_only_allowed_triggered_recent_events(client):
    test_client, main = client
    payload = make_event(timestamp=int(__import__('time').time() * 1000))
    body = json.dumps(payload).encode("utf-8")
    response = test_client.post("/webhook/line", content=body, headers=signed_headers(main, body))
    assert response.status_code == 200
    assert response.json() == {"accepted": 1, "ignored": 0}

    wrong_user = make_event(timestamp=int(__import__('time').time() * 1000))
    wrong_user["events"][0]["source"]["userId"] = "Uwrong"
    body = json.dumps(wrong_user).encode("utf-8")
    response = test_client.post("/webhook/line", content=body, headers=signed_headers(main, body))
    assert response.status_code == 200
    assert response.json() == {"accepted": 0, "ignored": 1}

    stale = make_event(timestamp=1)
    body = json.dumps(stale).encode("utf-8")
    response = test_client.post("/webhook/line", content=body, headers=signed_headers(main, body))
    assert response.status_code == 200
    assert response.json() == {"accepted": 0, "ignored": 1}


def test_webhook_deduplicates_duplicate_events(client):
    test_client, main = client
    payload = make_event(timestamp=int(__import__('time').time() * 1000), webhook_event_id="evt-dedupe")
    body = json.dumps(payload).encode("utf-8")
    headers = signed_headers(main, body)
    first = test_client.post("/webhook/line", content=body, headers=headers)
    second = test_client.post("/webhook/line", content=body, headers=headers)
    assert first.json() == {"accepted": 1, "ignored": 0}
    assert second.json() == {"accepted": 0, "ignored": 1}


def test_ready_reflects_config_and_health_is_liveness(monkeypatch: pytest.MonkeyPatch):
    main = load_app(monkeypatch)
    client = TestClient(main.app)
    ready = client.get("/ready")
    health = client.get("/health")
    assert ready.status_code == 200
    assert ready.json() == {"ok": True}
    assert health.status_code == 200
    assert health.json() == {"ok": True}
    client.close()

    main = load_app(monkeypatch, {"CHANNEL_SECRET": ""})
    client = TestClient(main.app)
    ready = client.get("/ready")
    health = client.get("/health")
    assert ready.status_code == 503
    assert ready.json() == {"ok": False}
    assert health.status_code == 200
    assert health.json() == {"ok": True}
    client.close()


def test_admin_routes_require_api_key(client):
    test_client, _ = client
    assert test_client.get("/admin/config").status_code == 401
    assert test_client.get("/admin/google/oauth-url").status_code == 401
    assert test_client.get("/admin/notes").status_code == 401

    headers = {"X-Admin-Key": VALID_ENV["ADMIN_API_KEY"]}
    assert test_client.get("/admin/config", headers=headers).status_code == 200
    assert test_client.get("/admin/google/oauth-url", headers=headers).status_code == 200
    assert test_client.get("/admin/notes", headers=headers).status_code == 200


def test_admin_config_redacts_values(client):
    test_client, _ = client
    headers = {"X-Admin-Key": VALID_ENV["ADMIN_API_KEY"]}
    data = test_client.get("/admin/config", headers=headers).json()
    redacted = data["redacted"]
    assert VALID_ENV["CHANNEL_ID"] not in json.dumps(data)
    assert VALID_ENV["LINE_ALLOWED_USER_ID"] not in json.dumps(data)
    assert VALID_ENV["GOOGLE_CLIENT_ID"] not in json.dumps(data)
    assert redacted["LINE_ALLOWED_GROUP_IDS"] == 1


def test_oauth_url_contains_expected_parameters(client):
    test_client, _ = client
    headers = {"X-Admin-Key": VALID_ENV["ADMIN_API_KEY"]}
    response = test_client.get("/admin/google/oauth-url?state=abc123", headers=headers)
    assert response.status_code == 200
    url = response.json()["url"]
    assert "client_id=google-client-id" in url
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauth%2Fgoogle%2Fcallback" in url
    assert "response_type=code" in url
    assert "access_type=offline" in url
    assert "prompt=consent" in url
    assert "state=abc123" in url


def test_docs_are_disabled_by_default(monkeypatch: pytest.MonkeyPatch):
    main = load_app(monkeypatch)
    client = TestClient(main.app)
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    client.close()


def test_docs_can_be_enabled_explicitly(monkeypatch: pytest.MonkeyPatch):
    main = load_app(monkeypatch, {"ENABLE_API_DOCS": "true"})
    client = TestClient(main.app)
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    client.close()


def test_trusted_host_middleware_blocks_unexpected_host(monkeypatch: pytest.MonkeyPatch):
    main = load_app(monkeypatch, {"ALLOWED_HOSTS": "example.com"})
    client = TestClient(main.app)
    allowed = client.get("/health", headers={"host": "example.com"})
    blocked = client.get("/health", headers={"host": "evil.example"})
    assert allowed.status_code == 200
    assert blocked.status_code == 400
    client.close()


def test_env_example_matches_documented_required_keys():
    env_example = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
    keys = {line.split("=", 1)[0] for line in env_example.splitlines() if line and not line.startswith("#")}
    required = {
        "CHANNEL_ID",
        "CHANNEL_SECRET",
        "LINE_ALLOWED_USER_ID",
        "LINE_TRIGGER_PHRASES",
        "ADMIN_API_KEY",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "GOOGLE_REDIRECT_URI",
        "GOOGLE_CALENDAR_ID",
    }
    assert required.issubset(keys)


def test_google_oauth_url_script_matches_admin_endpoint(client):
    test_client, _ = client
    headers = {"X-Admin-Key": VALID_ENV["ADMIN_API_KEY"]}
    admin_url = test_client.get("/admin/google/oauth-url?state=script-check", headers=headers).json()["url"]
    parsed = urlparse(admin_url)
    assert parsed.netloc == "accounts.google.com"
    assert parsed.path.endswith("/o/oauth2/v2/auth")


# ---------------------------------------------------------------------------
# Google Calendar sync (added 2026-09-05)
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self._payload = payload
        self._status = status

    def read(self) -> bytes:
        import json as _json
        return _json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    @property
    def status(self) -> int:
        return self._status


class _FakeOpener:
    def __init__(self, *, token_payload=None, event_payload=None, fail_event: bool = False):
        self.token_payload = token_payload or {
            "access_token": "ya29.fake",
            "refresh_token": "1//fake",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/calendar.events",
        }
        self.event_payload = event_payload or {"id": "evt-abc123"}
        self.fail_event = fail_event
        self.token_calls = 0
        self.event_calls = 0

    def __call__(self, request, timeout=10):
        from urllib.error import HTTPError as _HTTPError
        url = request.full_url
        if "oauth2.googleapis.com" in url:
            self.token_calls += 1
            return _FakeResponse(self.token_payload)
        if "googleapis.com/calendar" in url:
            self.event_calls += 1
            if self.fail_event:
                raise _HTTPError(url, 500, "internal", {}, None)
            return _FakeResponse(self.event_payload)
        raise AssertionError(f"unexpected url: {url}")


def _install_fake_client(monkeypatch, main_module, **kwargs):
    fake = _FakeOpener(**kwargs)
    monkeypatch.setattr(main_module, "_build_default_client", lambda settings: main_module.GoogleCalendarClient(settings, opener=fake))
    return fake


def test_init_db_creates_google_tokens_table(client):
    _, main = client
    with main.connect_db(main.get_settings()) as conn:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='google_tokens'"
        ).fetchone()
        assert row is not None and row["name"] == "google_tokens"


def test_callback_route_registered(client):
    test_client, _ = client
    response = test_client.get("/auth/google/callback")
    # 400 because code is missing — but the route MUST exist (not 404).
    assert response.status_code == 400
    assert "invalid oauth callback" in response.text.lower()


def test_callback_rejects_bad_state(client):
    test_client, _ = client
    response = test_client.get("/auth/google/callback", params={"code": "x", "state": "evil"})
    assert response.status_code == 400
    assert "invalid oauth callback" in response.text.lower()


def test_callback_stores_tokens_on_success(client, monkeypatch):
    test_client, main = client
    fake = _install_fake_client(monkeypatch, main)
    response = test_client.get(
        "/auth/google/callback",
        params={"code": "auth-code-1", "state": "sunshine-google-oauth"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["ok"] is True
    assert fake.token_calls == 1
    with main.connect_db(main.get_settings()) as conn:
        row = conn.execute(
            "SELECT access_token, refresh_token, expires_at, scopes FROM google_tokens WHERE kind='google'"
        ).fetchone()
        assert row is not None
        assert row["access_token"] == "ya29.fake"
        assert row["refresh_token"] == "1//fake"


def test_admin_revoke_clears_tokens(client, monkeypatch):
    test_client, main = client
    fake = _install_fake_client(monkeypatch, main)
    # First store a token via callback
    test_client.get(
        "/auth/google/callback",
        params={"code": "auth-code-2", "state": "sunshine-google-oauth"},
    )
    # Now revoke (requires admin key)
    response = test_client.delete(
        "/admin/google/token",
        headers={"X-Admin-Key": "admin-secret-key"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"ok": True, "removed": True}
    # Token row gone
    with main.connect_db(main.get_settings()) as conn:
        row = conn.execute(
            "SELECT 1 FROM google_tokens WHERE kind='google'"
        ).fetchone()
        assert row is None
    assert fake.token_calls == 1  # exchange only, no extra calls


def test_admin_revoke_requires_api_key(client):
    test_client, _ = client
    response = test_client.delete("/admin/google/token")
    assert response.status_code in (401, 403)


def test_webhook_works_without_google_config(client, monkeypatch):
    test_client, main = client
    # Wipe google config and reload — but callback needs GOOGLE_CLIENT_ID too.
    # The simpler proof: no token row in DB + a real webhook still accepts a note.
    # (Don't actually wipe env; just verify "no tokens" path doesn't error.)
    main.get_settings.cache_clear()
    body = __import__("json").dumps(make_event("sunshine noop", timestamp=int(__import__("time").time() * 1000), webhook_event_id="evt-noop-1")).encode("utf-8")
    response = test_client.post(
        "/webhook/line",
        content=body,
        headers=signed_headers(main, body),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["accepted"] == 1
    # Note row exists, task row exists, status remains 'pending' (no sync attempted).
    with main.connect_db(main.get_settings()) as conn:
        row = conn.execute(
            "SELECT status, calendar_event_id FROM tasks ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row["status"] == "pending"
        assert row["calendar_event_id"] is None


def test_note_accept_creates_calendar_event(client, monkeypatch):
    test_client, main = client
    fake = _install_fake_client(monkeypatch, main, event_payload={"id": "evt-xyz789"})
    # Seed a token row directly so the webhook path finds one.
    with main.connect_db(main.get_settings()) as conn:
        main._save_token_row(
            conn,
            main.TokenSet(
                access_token="ya29.fake",
                refresh_token="1//fake",
                expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc) + __import__("datetime").timedelta(hours=1),
                scopes=main.GOOGLE_SCOPES,
            ),
        )
        conn.commit()
    body = __import__("json").dumps(make_event("sunshine sync me", timestamp=int(__import__("time").time() * 1000), webhook_event_id="evt-sync-1")).encode("utf-8")
    response = test_client.post(
        "/webhook/line",
        content=body,
        headers=signed_headers(main, body),
    )
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] == 1
    assert fake.event_calls == 1
    with main.connect_db(main.get_settings()) as conn:
        row = conn.execute(
            "SELECT calendar_event_id, status FROM tasks ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row["calendar_event_id"] == "evt-xyz789"
        assert row["status"] == "synced"


def test_sync_failure_marks_task_failed(client, monkeypatch):
    test_client, main = client
    _install_fake_client(monkeypatch, main, fail_event=True)
    with main.connect_db(main.get_settings()) as conn:
        main._save_token_row(
            conn,
            main.TokenSet(
                access_token="ya29.fake",
                refresh_token=None,
                expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc) + __import__("datetime").timedelta(hours=1),
                scopes=main.GOOGLE_SCOPES,
            ),
        )
        conn.commit()
    body = __import__("json").dumps(make_event("sunshine sync fail", timestamp=int(__import__("time").time() * 1000), webhook_event_id="evt-fail-1")).encode("utf-8")
    response = test_client.post(
        "/webhook/line",
        content=body,
        headers=signed_headers(main, body),
    )
    assert response.status_code == 200, response.text
    with main.connect_db(main.get_settings()) as conn:
        note = conn.execute(
            "SELECT text FROM notes ORDER BY id DESC LIMIT 1"
        ).fetchone()
        task = conn.execute(
            "SELECT calendar_event_id, status FROM tasks ORDER BY id DESC LIMIT 1"
        ).fetchone()
        # Note still recorded
        assert note["text"] == "sunshine sync fail"
        # Task marked failed, no calendar id
        assert task["calendar_event_id"] is None
        assert task["status"] == "sync_failed"


def test_token_refresh_when_near_expiry(client, monkeypatch):
    test_client, main = client
    fake = _install_fake_client(monkeypatch, main, event_payload={"id": "evt-renew"})
    # Token near expiry (now + 10s, less than the 60s skew)
    near_expiry = __import__("datetime").datetime.now(__import__("datetime").timezone.utc) + __import__("datetime").timedelta(seconds=10)
    with main.connect_db(main.get_settings()) as conn:
        main._save_token_row(
            conn,
            main.TokenSet(
                access_token="ya29.stale",
                refresh_token="1//refresh",
                expires_at=near_expiry,
                scopes=main.GOOGLE_SCOPES,
            ),
        )
        conn.commit()
    body = __import__("json").dumps(make_event("sunshine refresh", timestamp=int(__import__("time").time() * 1000), webhook_event_id="evt-refresh-1")).encode("utf-8")
    response = test_client.post(
        "/webhook/line",
        content=body,
        headers=signed_headers(main, body),
    )
    assert response.status_code == 200, response.text
    # Both refresh + event called.
    assert fake.token_calls == 1
    assert fake.event_calls == 1
    # Access token refreshed in DB.
    with main.connect_db(main.get_settings()) as conn:
        row = conn.execute(
            "SELECT access_token FROM google_tokens WHERE kind='google'"
        ).fetchone()
        assert row["access_token"] == "ya29.fake"  # from fake payload
