"""Pure-function unit tests for app.main — no DB, no network, no HTTP."""
from __future__ import annotations

import json

import pytest

from app import main


# --- redact -----------------------------------------------------------------

def test_redact_empty():
    assert main.redact("") == ""


def test_redact_short_value():
    assert main.redact("abc") == "***"
    assert main.redact("12345678") == "***"


def test_redact_long_value():
    assert main.redact("abcdefghi") == "abcd...fghi"
    assert main.redact("supersecret123") == "supe...t123"


# --- redact_database_url -----------------------------------------------------

def test_redact_database_url_sqlite():
    url = "sqlite:///./data/sunshine.db"
    assert main.redact_database_url(url) == url


def test_redact_database_url_no_scheme():
    assert main.redact_database_url("not-a-url") == "not-a-url"


def test_redact_database_url_no_auth():
    assert main.redact_database_url("https://example.com/db") == "https://example.com/db"


def test_redact_database_url_with_auth():
    result = main.redact_database_url("postgres://user:pass@host:5432/db")
    assert result == "postgres://***:***@host:5432/db"


# --- parse_payload -----------------------------------------------------------

def test_parse_payload_valid():
    body = json.dumps({"events": []}).encode("utf-8")
    result = main.parse_payload(body)
    assert result == {"events": []}


def test_parse_payload_invalid_json():
    with pytest.raises(Exception) as exc:
        main.parse_payload(b"not-json")
    assert "invalid json" in str(exc.value).lower()


def test_parse_payload_not_dict():
    with pytest.raises(Exception) as exc:
        main.parse_payload(json.dumps([1, 2, 3]).encode("utf-8"))
    assert "invalid payload" in str(exc.value).lower()


# --- stable_event_id ---------------------------------------------------------

def test_stable_event_id_uses_webhook_event_id():
    event = {"webhookEventId": "evt-123", "other": "data"}
    assert main.stable_event_id(event) == "evt-123"


def test_stable_event_id_strips_whitespace():
    event = {"webhookEventId": "  evt-123  "}
    assert main.stable_event_id(event) == "evt-123"


def test_stable_event_id_falls_back_to_hash():
    event = {"other": "data"}
    result = main.stable_event_id(event)
    assert isinstance(result, str)
    assert len(result) == 64  # sha256 hex


def test_stable_event_id_deterministic():
    event = {"b": 2, "a": 1}
    assert main.stable_event_id(event) == main.stable_event_id(event)


# --- normalize_text / has_trigger -------------------------------------------

def test_normalize_text_collapses_whitespace():
    assert main.normalize_text("  Hello   World  ") == "hello world"


def test_normalize_text_lowercases():
    assert main.normalize_text("SUNSHINE") == "sunshine"


class _FakeSettings:
    trigger_phrases = ("sunshine", "ms sunshine")


def test_has_trigger_matches():
    assert main.has_trigger("sunshine remember this", _FakeSettings()) is True


def test_has_trigger_no_match():
    assert main.has_trigger("hello world", _FakeSettings()) is False


def test_has_trigger_case_insensitive():
    assert main.has_trigger("Ms Sunshine please", _FakeSettings()) is True


# --- allowed_user / allowed_group / ensure_admin ----------------------------

class _Settings2:
    allowed_user_id = "U123"
    allowed_group_ids = ("C1", "C2")
    admin_api_key = "secret"


def test_allowed_user_match():
    assert main.allowed_user("U123", _Settings2()) is True


def test_allowed_user_no_match():
    assert main.allowed_user("U999", _Settings2()) is False


def test_allowed_group_in_list():
    assert main.allowed_group("C1", _Settings2()) is True


def test_allowed_group_not_in_list():
    assert main.allowed_group("C99", _Settings2()) is False


def test_allowed_group_empty_id():
    assert main.allowed_group("", _Settings2()) is False


def test_ensure_admin_missing_key():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        main.ensure_admin(None, _Settings2())
    assert exc.value.status_code == 401


def test_ensure_admin_wrong_key():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        main.ensure_admin("wrong", _Settings2())
    assert exc.value.status_code == 401


def test_ensure_admin_correct_key():
    main.ensure_admin("secret", _Settings2())  # no raise


# --- settings_errors ---------------------------------------------------------

class _EmptySettings:
    channel_id = ""
    channel_secret = ""
    allowed_user_id = ""
    trigger_phrases = ()
    admin_api_key = ""
    google_client_id = ""
    google_client_secret = ""
    google_redirect_uri = ""
    google_calendar_id = ""


def test_settings_errors_all_missing():
    errors = main.settings_errors(_EmptySettings())
    assert len(errors) == 9


class _FullSettings:
    channel_id = "ch"
    channel_secret = "sec"
    allowed_user_id = "u"
    trigger_phrases = ("sunshine",)
    admin_api_key = "key"
    google_client_id = "gid"
    google_client_secret = "gsec"
    google_redirect_uri = "http://x"
    google_calendar_id = "primary"


def test_settings_errors_none():
    assert main.settings_errors(_FullSettings()) == []


# --- _now_iso / _parse_iso ---------------------------------------------------

def test_now_iso_returns_string():
    result = main._now_iso()
    assert isinstance(result, str)
    assert "T" in result


def test_parse_iso_roundtrip():
    parsed = main._parse_iso(main._now_iso())
    assert parsed.tzinfo is not None


# --- health -----------------------------------------------------------------

def test_health_returns_dict():
    result = main.health()
    assert isinstance(result, dict)
    assert "ok" in result
    assert result["ok"] is True
