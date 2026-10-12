from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")


def required(name: str) -> str:
    value = os.getenv(name)
    if not value or "YOUR-" in value or value in {"AIza...", ""}:
        raise RuntimeError(f"missing/placeholder env var {name}; set it in {ROOT / '.env'}")
    return value


def database_url() -> str:
    raw = required("DATABASE_URL")
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        if host not in {"localhost", "127.0.0.1"}:
            query = dict(parse_qsl(parts.query, keep_blank_values=True))
            query.setdefault("sslmode", "require")
            raw = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    except Exception:
        pass
    return raw


DATABASE_URL = database_url()
GEMINI_API_KEY = required("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
AGENT_MAX_STEPS = int(os.getenv("AGENT_MAX_STEPS", "18"))
AGENT_MAX_TOKENS = int(os.getenv("AGENT_MAX_TOKENS", "120000"))

HOST = "127.0.0.1"
PORT = int(os.getenv("PORT", "8787"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "300"))
CORS_ORIGINS = [
    x.strip()
    for x in os.getenv(
        "CORS_ORIGIN",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if x.strip()
]

ML_DIR = ROOT / "ml"
ANALYZE_PY = ML_DIR / "analyze.py"
