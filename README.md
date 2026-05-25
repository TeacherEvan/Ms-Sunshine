# Ms Sunshine

Ms Sunshine is a FastAPI service for a LINE group assistant that stays silent by default, accepts only messages from one allowlisted LINE user, records triggered notes, and prepares tasks for Google Calendar sync.

Current capabilities
- verifies LINE webhook signatures with CHANNEL_SECRET
- allows only one LINE user ID
- optionally restricts to specific LINE group IDs
- triggers only when configured phrases appear in text
- stores accepted notes and placeholder tasks in SQLite
- exposes admin-only endpoints with an API key
- generates a Google OAuth consent URL for calendar setup
- disables docs/OpenAPI by default

Endpoints
- GET /health
  - liveness only
- GET /ready
  - readiness; returns 503 if required config or DB access is broken
- POST /webhook/line
  - LINE webhook endpoint
- GET /admin/config
  - admin-only redacted config/status
- GET /admin/google/oauth-url
  - admin-only Google consent URL generator
- GET /admin/notes
  - admin-only note listing

Required environment variables
- CHANNEL_ID
- CHANNEL_SECRET
- LINE_ALLOWED_USER_ID
- LINE_TRIGGER_PHRASES
- ADMIN_API_KEY
- GOOGLE_CLIENT_ID
- GOOGLE_CLIENT_SECRET
- GOOGLE_REDIRECT_URI
- GOOGLE_CALENDAR_ID

Optional environment variables
- LINE_ALLOWED_GROUP_IDS
- DATABASE_URL
- MAX_WEBHOOK_BODY_BYTES
- MAX_EVENT_AGE_SECONDS
- ENABLE_API_DOCS
- ALLOWED_HOSTS

Important constraints
- This build supports sqlite:/// DATABASE_URL only.
- Google Calendar token exchange, callback handling, and token persistence are not implemented yet.
- The current task record is a placeholder derived from the accepted note text.

LINE setup
1. Create a Messaging API channel in LINE Developers.
2. Set the webhook URL to your public endpoint:
   - https://your-domain.example/webhook/line
3. Enable webhook delivery.
4. Put CHANNEL_ID and CHANNEL_SECRET into .env.
5. Set LINE_ALLOWED_USER_ID to your user ID.
6. If you want group restrictions, set LINE_ALLOWED_GROUP_IDS.

Google setup
1. Create OAuth client credentials in Google Cloud.
2. Add your callback URL to the authorized redirect URIs.
3. Put GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, and GOOGLE_CALENDAR_ID into .env.
4. Generate the consent URL:
   - python scripts/google_oauth_url.py
5. Or call the admin endpoint with X-Admin-Key.

Local run
1. Create .env from .env.example
2. Install deps:
   - python3 -m venv .venv
   - . .venv/bin/activate
   - pip install -r requirements.txt
3. Validate env:
   - python scripts/validate_env.py
4. Start with env file loaded:
   - uvicorn app.main:app --host 0.0.0.0 --port 8000 --env-file .env

Docker run
- docker compose up --build

Admin usage
- send header: X-Admin-Key: your ADMIN_API_KEY
- examples:
  - curl -H 'X-Admin-Key: ...' http://localhost:8000/admin/config
  - curl -H 'X-Admin-Key: ...' http://localhost:8000/admin/google/oauth-url
  - curl -H 'X-Admin-Key: ...' http://localhost:8000/admin/notes

Deployment guidance
- expose only /webhook/line publicly if possible
- keep admin endpoints behind internal networking, VPN, or reverse-proxy restrictions
- leave ENABLE_API_DOCS unset in production
- set ALLOWED_HOSTS to your production hostname(s)

License
- MIT. See LICENSE.
