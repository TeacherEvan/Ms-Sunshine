from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REQUIRED = [
    'CHANNEL_ID',
    'CHANNEL_SECRET',
    'LINE_ALLOWED_USER_ID',
    'LINE_TRIGGER_PHRASES',
    'ADMIN_API_KEY',
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'GOOGLE_REDIRECT_URI',
    'GOOGLE_CALENDAR_ID',
]


def redact(value: str) -> str:
    if not value:
        return ''
    if len(value) <= 8:
        return '***'
    return value[:4] + '…' + value[-4:]


def redact_database_url(value: str) -> str:
    if value.startswith('sqlite:///'):
        return value
    if '://' not in value or '@' not in value:
        return value
    scheme, rest = value.split('://', 1)
    _, host = rest.rsplit('@', 1)
    return f'{scheme}://***:***@{host}'


def main() -> int:
    missing = [key for key in REQUIRED if not os.getenv(key)]
    db_url = os.getenv('DATABASE_URL', 'sqlite:///./data/sunshine.db')
    print('Environment summary:')
    for key in REQUIRED:
        print(f'- {key}: {redact(os.getenv(key, ""))}')
    print(f'- DATABASE_URL: {redact_database_url(db_url)}')
    if db_url.startswith('sqlite:///'):
        raw = db_url[len('sqlite:///'):]
        db_path = Path(raw)
        if not db_path.is_absolute():
            db_path = (PROJECT_ROOT / db_path).resolve()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(db_path.parent / '.write_test', 'w', encoding='utf-8') as handle:
                handle.write('ok')
            os.remove(db_path.parent / '.write_test')
            print(f'- DB directory writable: {db_path.parent}')
        except OSError as exc:
            print(f'- DB directory writable: FAILED ({exc})')
            return 1
    elif '://' in db_url:
        print('- DATABASE_URL scheme is not supported by this build')
        return 1
    if missing:
        print('Missing variables:')
        for key in missing:
            print(f'  - {key}')
        return 1
    print('Environment looks usable.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
