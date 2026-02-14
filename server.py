import os
import csv
import io
import json
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

import psycopg2
from psycopg2.extras import RealDictCursor

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    StreamingResponse,
    PlainTextResponse,
)
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from openai import OpenAI

app = FastAPI()

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
ADMIN_PANEL_SECRET = os.environ.get("ADMIN_PANEL_SECRET", "change-me")

# ----------------------------
# OPENAI CLIENT
# ----------------------------

_openai_client = None

def get_openai_client():
    global _openai_client
    if _openai_client is None:
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set")
        _openai_client = OpenAI(api_key=key)
    return _openai_client


# --- sessions ---
app.add_middleware(
    SessionMiddleware,
    secret_key=ADMIN_PANEL_SECRET,
    https_only=True,
    same_site="lax",
)

templates = Jinja2Templates(directory="templates")


# =========================
# ROOT
# =========================

@app.get("/", response_class=PlainTextResponse)
def root():
    return "OK"


@app.head("/")
def head_root():
    return


@app.head("/admin")
def head_admin():
    return


# =========================
# DATABASE
# =========================

def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)


def init_db():
    con = db()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        key TEXT PRIMARY KEY,
        hwid TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        note TEXT DEFAULT ''
    );
    """)

    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'custom';")
    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();")
    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();")
    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_check_at TIMESTAMPTZ;")
    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS check_count BIGINT DEFAULT 0;")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS admin_audit (
        id BIGSERIAL PRIMARY KEY,
        ts TIMESTAMPTZ DEFAULT NOW(),
        action TEXT,
        key TEXT,
        hwid TEXT,
        info TEXT DEFAULT ''
    );
    """)

    con.commit()
    cur.close()
    con.close()


@app.on_event("startup")
def startup():
    init_db()


def now():
    return datetime.now(timezone.utc)


def is_admin(request: Request):
    return request.session.get("is_admin")


# =========================
# CLIENT API (LICENSE CHECK)
# =========================

class CheckReq(BaseModel):
    key: str
    hwid: str


@app.post("/api/check")
def check(req: CheckReq):
    con = db()
    cur = con.cursor()
    cur.execute(
        "SELECT hwid, expires_at, revoked FROM licenses WHERE key=%s",
        (req.key,)
    )
    row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="key_not_found")

    hwid, expires_at, revoked = row

    cur.execute("""
        UPDATE licenses
        SET last_check_at=NOW(), check_count=check_count+1
        WHERE key=%s
    """, (req.key,))
    con.commit()

    cur.close()
    con.close()

    if revoked:
        raise HTTPException(status_code=403, detail="revoked")

    if hwid != req.hwid:
        raise HTTPException(status_code=403, detail="hwid_mismatch")

    if now() > expires_at:
        raise HTTPException(status_code=403, detail="expired")

    return {"ok": True, "expires_at": expires_at.isoformat()}


# =========================
# AI API
# =========================

class AIItem(BaseModel):
    id: str
    text: str

class AIScoreReq(BaseModel):
    prompt: str
    items: List[AIItem]
    min_score: int = 70
    lang: str = "ru"

@app.post("/api/ai/score")
def ai_score(req: AIScoreReq) -> Dict[str, Any]:

    client = get_openai_client()

    items = [{"id": it.id, "text": (it.text or "")[:1200]} for it in req.items]

    system_prompt = (
        "Ты анализируешь сообщения Telegram пользователей. "
        "Оцени соответствие текста заданному промту. "
        "Верни строго JSON без пояснений."
    )

    payload = {
        "prompt": req.prompt,
        "min_score": req.min_score,
        "items": items,
        "rules": [
            "score 0..100",
            "pass=true если score>=min_score и нет bot_like/spam_like/toxic",
            "flags возможные: bot_like, spam_like, toxic, low_quality",
            "reason коротко 5-12 слов"
        ],
        "output_format": {
            "results": [
                {"id": "string", "score": 0, "pass": True, "reason": "string", "flags": []}
            ]
        }
    }

    resp = client.responses.create(
        model="gpt-4.1-mini",
        input=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}
        ],
    )

    out_text = ""
    for o in resp.output:
        if o.type == "message":
            for c in o.content:
                if getattr(c, "type", None) == "output_text":
                    out_text += c.text

    data = json.loads(out_text)

    if "results" not in data:
        raise HTTPException(status_code=500, detail="bad_ai_response")

    return data
