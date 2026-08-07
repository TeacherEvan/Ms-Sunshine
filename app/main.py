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
from urllib.parse import urlencode

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")
