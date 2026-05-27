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
    import app.main as main
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
