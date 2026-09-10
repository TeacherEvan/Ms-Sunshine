"""Module-level constants for Ms Sunshine.

Centralises repeated string literals so env-var names, OAuth state, and
error messages cannot drift between call sites.  Every env-var name used
across app/main.py is defined exactly once here.
"""

# --- LINE / admin env-var names (single source of truth) -------------------

ENV_CHANNEL_ID = "CHANNEL_ID"
ENV_CHANNEL_SECRET = "CHANNEL_SECRET"
ENV_LINE_ALLOWED_USER_ID = "LINE_ALLOWED_USER_ID"
ENV_LINE_ALLOWED_GROUP_IDS = "LINE_ALLOWED_GROUP_IDS"
ENV_LINE_TRIGGER_PHRASES = "LINE_TRIGGER_PHRASES"
ENV_ADMIN_API_KEY = "ADMIN_API_KEY"

# --- Google OAuth env-var names --------------------------------------------

ENV_GOOGLE_CLIENT_ID = "GOOGLE_CLIENT_ID"
ENV_GOOGLE_CLIENT_SECRET = "GOOGLE_CLIENT_SECRET"
ENV_GOOGLE_REDIRECT_URI = "GOOGLE_REDIRECT_URI"
ENV_GOOGLE_CALENDAR_ID = "GOOGLE_CALENDAR_ID"

# --- Misc env-var names ----------------------------------------------------

ENV_DATABASE_URL = "DATABASE_URL"
ENV_MAX_WEBHOOK_BODY_BYTES = "MAX_WEBHOOK_BODY_BYTES"
ENV_MAX_EVENT_AGE_SECONDS = "MAX_EVENT_AGE_SECONDS"
ENV_ENABLE_API_DOCS = "ENABLE_API_DOCS"
ENV_ALLOWED_HOSTS = "ALLOWED_HOSTS"

# --- Google OAuth ----------------------------------------------------------

GOOGLE_OAUTH_STATE = "sunshine-google-oauth"
GOOGLE_OAUTH_NOT_CONFIGURED = "google oauth is not configured"

# --- Defaults --------------------------------------------------------------

DEFAULT_TRIGGER_PHRASES = "sunshine,Ms Sunshine"
