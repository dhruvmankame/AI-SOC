"""CRITICAL RUNTIME FILE: validates environment variables and resolves detector paths."""

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

# LLM provider. Gemini remains the zero-migration default. Set LLM_PROVIDER=groq
# and GROQ_API_KEY to use Groq's low-latency inference path.
LLM_PROVIDER = (os.getenv('LLM_PROVIDER') or 'gemini').strip().lower()
if LLM_PROVIDER not in {'gemini', 'groq'}:
    raise RuntimeError('LLM_PROVIDER must be either gemini or groq')

GEMINI_API_KEY = (os.getenv('GEMINI_API_KEY') or '').strip()
GROQ_API_KEY = (os.getenv('GROQ_API_KEY') or '').strip()
if LLM_PROVIDER == 'gemini':
    GEMINI_API_KEY = required('GEMINI_API_KEY')
else:
    GROQ_API_KEY = required('GROQ_API_KEY')

# Flash-Lite is a better fit for these short, structured SOC subagent calls.
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-3.5-flash-lite').strip() or 'gemini-3.5-flash-lite'
GROQ_MODEL = os.getenv('GROQ_MODEL', 'openai/gpt-oss-20b').strip() or 'openai/gpt-oss-20b'

# The old implementation slept 13 seconds before almost every model call.
# Keep a conservative Gemini gap, while Groq can normally run without it.
_default_llm_gap = '0' if LLM_PROVIDER == 'groq' else '4'
LLM_MIN_INTERVAL_SECONDS = max(0.0, float(os.getenv('LLM_MIN_INTERVAL_SECONDS', _default_llm_gap)))

# Multiple incidents can run concurrently with Groq. Gemini defaults to one
# incident at a time to reduce free-tier 429s; override explicitly if desired.
_default_agent_concurrency = '3' if LLM_PROVIDER == 'groq' else '1'
AGENT_CONCURRENCY = max(1, int(os.getenv('AGENT_CONCURRENCY', _default_agent_concurrency)))

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
