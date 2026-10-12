from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / '.env')


def required(name: str) -> str:
    value = (os.getenv(name) or '').strip()
    bad = not value or 'YOUR-' in value or value in {'AI...' ,'mongodb+srv://USERNAME:PASSWORD@CLUSTER.mongodb.net/'}
    if bad:
        raise RuntimeError(f'missing/placeholder env var {name}; set it in {ROOT / ".env"}')
    return value


MONGODB_URI = required('MONGODB_URI')
MONGODB_DB = os.getenv('MONGODB_DB', 'ai_soc').strip() or 'ai_soc'
GEMINI_API_KEY = required('GEMINI_API_KEY')
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-3.8-flash')
AGENT_MAX_STEPS = int(os.getenv('AGENT_MAX_STEPS', '18'))
AGENT_MAX_TOKENS = int(os.getenv('AGENT_MAX_TOKENS', '120000'))

HOST = '127.0.0.1'
PORT = int(os.getenv('PORT', '8787'))
MAX_UPLOAD_MB = int(os.getenv('MAX_UPLOAD_MB', '300'))
CORS_ORIGINS = [
    x.strip()
    for x in os.getenv(
        'CORS_ORIGIN',
        'http://localhost:5173,http://127.0.0.1:5173',
    ).split(',')
    if x.strip()
]

ML_DIR = ROOT / 'ml'
ANALYZE_PY = ML_DIR / 'analyze.py'
