from __future__ import annotations

import os
from urllib.parse import urlencode

SCOPES = ("https://www.googleapis.com/auth/calendar.events",)


def main() -> int:
    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "").strip()
    if not client_id or not redirect_uri:
        print("GOOGLE_CLIENT_ID and GOOGLE_REDIRECT_URI are required")
        return 1
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(SCOPES),
            "access_type": "offline",
            "prompt": "consent",
            "state": os.getenv("GOOGLE_OAUTH_STATE", "ms-sunshine-oauth"),
        }
    )
    print(f"https://accounts.google.com/o/oauth2/v2/auth?{query}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
