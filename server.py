import os
import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

from fastapi import FastAPI, HTTPException, Request, Form, Header
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    StreamingResponse,
    PlainTextResponse,
    JSONResponse,
)
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr
from starlette.middleware.sessions import SessionMiddleware

import jwt
from passlib.context import CryptContext

from openai import OpenAI


app = FastAPI()

# =========================
# GLOBAL ERROR HANDLER
# =========================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": type(exc).__name__, "message": str(exc)}
    )


# =========================
# ENV
# =========================
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

# Админ-авторизация в панели (cookie session)
ADMIN_PANEL_SECRET = os.environ.get("ADMIN_PANEL_SECRET", "change-me").strip()

# Админ-токен для admin API (удобно для Postman, без браузерной сессии)
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "").strip()

# JWT
JWT_SECRET = os.environ.get("JWT_SECRET", "CHANGE_ME").strip()
JWT_TTL_DAYS = int(os.environ.get("JWT_TTL_DAYS", "30"))

# Цена AI: сколько центов списывать за 1 item (1 item = 1 пользователь/сообщение для скоринга)
AI_PRICE_PER_ITEM_CENTS = int(os.environ.get("AI_PRICE_PER_ITEM_CENTS", "1"))

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


# =========================
# OPENAI CLIENT
# =========================
_openai_client = None

def get_openai_client():
    global _openai_client
    if _openai_client is None:
        key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set in Render Environment")
        _openai_client = OpenAI(api_key=key)
    return _openai_client


# --- sessions ---
app.add_middleware(
    SessionMiddleware,
    secret_key=ADMIN_PANEL_SECRET,
    https_only=True,
    same_site="lax",
)


# =========================
# DB helpers
# =========================
def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)


def now_utc():
    return datetime.now(timezone.utc)


def init_db():
    con = db()
    cur = con.cursor()

    # ---- LICENSES (старое, оставляем для совместимости) ----
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

    # ---- USERS (новое: аккаунты) ----
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      subscription_expiry TIMESTAMPTZ,
      ai_balance_cents INTEGER NOT NULL DEFAULT 0,
      device_hwid TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """)

    # ---- Wallet ledger (чтобы всегда было видно списания/начисления) ----
    cur.execute("""
    CREATE TABLE IF NOT EXISTS wallet_ledger (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      delta_cents INTEGER NOT NULL,
      reason TEXT NOT NULL,
      meta JSONB
    );
    """)

    con.commit()
    cur.close()
    con.close()


@app.on_event("startup")
def startup():
    init_db()


# =========================
# ADMIN helpers
# =========================
templates = Jinja2Templates(directory="templates")


def is_admin_session(request: Request) -> bool:
    return bool(request.session.get("is_admin"))


def require_admin(request: Request, x_admin_token: Optional[str]):
    # можно зайти как админ через браузерную сессию
    if is_admin_session(request):
        return
    # либо через заголовок x-admin-token
    if ADMIN_TOKEN and x_admin_token and x_admin_token.strip() == ADMIN_TOKEN:
        return
    raise HTTPException(status_code=403, detail="admin_required")


# ========================
