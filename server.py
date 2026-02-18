import os
import csv
import io
import json
import re
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

from fastapi import FastAPI, HTTPException, Request, Form, BackgroundTasks, Header
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    StreamingResponse,
    PlainTextResponse,
    JSONResponse,
)
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

# =========================
# ÐÐžÐ’Ð«Ð• Ð˜ÐœÐŸÐžÐ Ð¢Ð« Ð”Ð›Ð¯ ÐŸÐžÐ§Ð¢Ð«
# =========================
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content

from openai import OpenAI

app = FastAPI()

# =========================
# Ð“Ð›ÐžÐ‘ÐÐ›Ð¬ÐÐ«Ð™ ÐžÐ‘Ð ÐÐ‘ÐžÐ¢Ð§Ð˜Ðš
# =========================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": type(exc).__name__, "message": str(exc)}
    )

# =========================
# ÐÐÐ¡Ð¢Ð ÐžÐ™ÐšÐ˜
# =========================
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
ADMIN_PANEL_SECRET = os.environ.get("ADMIN_PANEL_SECRET", "change-me")

# =========================
# ÐÐÐ¡Ð¢Ð ÐžÐ™ÐšÐ˜ SENDGRID (ÐÐžÐ’Ð«Ð•)
# =========================
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
FROM_EMAIL = "noreply@tgparsersender.me"  # Ð­Ñ‚Ð¾Ñ‚ email Ñ‚Ñ‹ Ð¿Ð¾Ð´Ñ‚Ð²ÐµÑ€Ð´Ð¸Ð» Ð² SendGrid
FROM_NAME = "TG Parser Sender"

# =========================
# OPENAI
# =========================
_openai_client = None

def get_openai_client():
    global _openai_client
    if _openai_client is None:
        key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set")
        _openai_client = OpenAI(api_key=key)
    return _openai_client

# =========================
# Ð¡Ð•Ð¡Ð¡Ð˜Ð˜
# =========================
app.add_middleware(
    SessionMiddleware,
    secret_key=ADMIN_PANEL_SECRET,
    https_only=True,
    same_site="lax",
)

templates = Jinja2Templates(directory="templates")

# =========================
# Ð’Ð¡ÐŸÐžÐœÐžÐ“ÐÐ¢Ð•Ð›Ð¬ÐÐ«Ð• Ð¤Ð£ÐÐšÐ¦Ð˜Ð˜
# =========================
def now():
    return datetime.now(timezone.utc)

def is_admin(request: Request):
    return request.session.get("is_admin")

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    return salt + ':' + hashlib.sha256((salt + password).encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt, hash_val = password_hash.split(':')
        return hash_val == hashlib.sha256((salt + password).encode()).hexdigest()
    except:
        return False

def generate_token() -> str:
    return secrets.token_urlsafe(32)

# =========================
# Ð‘ÐÐ—Ð Ð”ÐÐÐÐ«Ð¥
# =========================
def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)

def init_db():
    """Ð¡Ð¾Ð·Ð´Ð°Ð½Ð¸Ðµ Ð²ÑÐµÑ… Ñ‚Ð°Ð±Ð»Ð¸Ñ†"""
    print("ðŸš€ Ð¡Ð¾Ð·Ð´Ð°ÑŽ Ñ‚Ð°Ð±Ð»Ð¸Ñ†Ñ‹...")
    con = db()
    cur = con.cursor()
    
    try:
        # Ð¢Ð°Ð±Ð»Ð¸Ñ†Ð° Ð»Ð¸Ñ†ÐµÐ½Ð·Ð¸Ð¹
        cur.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            hwid TEXT,
            expires_at TIMESTAMPTZ NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT FALSE,
            note TEXT DEFAULT '',
            plan TEXT DEFAULT 'custom',
            max_devices INTEGER DEFAULT 1,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            last_check_at TIMESTAMPTZ,
            check_count BIGINT DEFAULT 0
        );
        """)
        print("âœ“ licenses")
        
        # Ð¢Ð°Ð±Ð»Ð¸Ñ†Ð° Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»ÐµÐ¹
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            license_key TEXT REFERENCES licenses(key) ON DELETE CASCADE,
            balance DECIMAL(10,2) DEFAULT 0.00,
            currency TEXT DEFAULT 'USD',
            email_confirmed BOOLEAN DEFAULT FALSE,
            email_confirmed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_login TIMESTAMPTZ,
            is_active BOOLEAN DEFAULT TRUE,
            total_spent DECIMAL(10,2) DEFAULT 0.00
        );
        """)
        print("âœ“ users")
        
        # Ð¢Ð°Ð±Ð»Ð¸Ñ†Ð° ÑƒÑÑ‚Ñ€Ð¾Ð¹ÑÑ‚Ð²
        cur.execute("""
        CREATE TABLE IF NOT EXISTS user_devices (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
            device_fingerprint TEXT NOT NULL,
            device_name TEXT,
            last_ip INET,
            last_login TIMESTAMPTZ DEFAULT NOW(),
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(user_id, device_fingerprint)
        );
        """)
        print("âœ“ user_devices")
        
        # Ð¢Ð°Ð±Ð»Ð¸Ñ†Ð° ÑÐµÑÑÐ¸Ð¹
        cur.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
            session_token TEXT UNIQUE NOT NULL,
            device_id BIGINT REFERENCES user_devices(id),
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_active TIMESTAMPTZ DEFAULT NOW()
        );
        """)
        print("âœ“ user_sessions")
        
        # Ð¢Ð°Ð±Ð»Ð¸Ñ†Ð° Ð¿Ð¾Ð´Ñ‚Ð²ÐµÑ€Ð¶Ð´ÐµÐ½Ð¸Ñ email
        cur.execute("""
        CREATE TABLE IF NOT EXISTS email_confirmations (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            confirmed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        """)
        print("âœ“ email_confirmations")
        
        # Ð¢Ð°Ð±Ð»Ð¸Ñ†Ð° ÑÐ±Ñ€Ð¾ÑÐ° Ð¿Ð°Ñ€Ð¾Ð»Ñ
        cur.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        """)
        print("âœ“ password_resets")
        
        # Ð¢Ð°Ð±Ð»Ð¸Ñ†Ð° Ñ‚Ñ€Ð°Ð½Ð·Ð°ÐºÑ†Ð¸Ð¹
        cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT REFERENCES users(id),
            license_key TEXT REFERENCES licenses(key),
            amount DECIMAL(10,2) NOT NULL,
            type TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            metadata JSONB DEFAULT '{}'
        );
        """)
        print("âœ“ transactions")
        
        # Ð¢Ð°Ñ€Ð¸Ñ„Ñ‹
        cur.execute("""
        CREATE TABLE IF NOT EXISTS pricing (
            id SERIAL PRIMARY KEY,
            operation_type TEXT UNIQUE NOT NULL,
            base_price DECIMAL(10,4) NOT NULL,
            final_price DECIMAL(10,4) NOT NULL,
            min_units INTEGER DEFAULT 1,
            description TEXT
        );
        """)
        
        cur.execute("""
        INSERT INTO pricing (operation_type, base_price, final_price, min_units, description)
        VALUES 
            ('parse', 0.0005, 0.0005, 100, 'ÐŸÐ°Ñ€ÑÐ¸Ð½Ð³ Ð¾Ð´Ð½Ð¾Ð³Ð¾ ÑÐ¾Ð¾Ð±Ñ‰ÐµÐ½Ð¸Ñ'),
            ('ai_parse', 0.005, 0.0075, 10, 'AI-Ð°Ð½Ð°Ð»Ð¸Ð· Ð¾Ð´Ð½Ð¾Ð³Ð¾ ÑÐ¾Ð¾Ð±Ñ‰ÐµÐ½Ð¸Ñ'),
            ('sender', 0.001, 0.001, 50, 'ÐžÑ‚Ð¿Ñ€Ð°Ð²ÐºÐ° Ð¾Ð´Ð½Ð¾Ð³Ð¾ ÑÐ¾Ð¾Ð±Ñ‰ÐµÐ½Ð¸Ñ'),
            ('invite', 0.002, 0.002, 20, 'ÐŸÑ€Ð¸Ð³Ð»Ð°ÑˆÐµÐ½Ð¸Ðµ Ð¾Ð´Ð½Ð¾Ð³Ð¾ Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»Ñ')
        ON CONFLICT (operation_type) DO UPDATE SET
            base_price = EXCLUDED.base_price,
            final_price = EXCLUDED.final_price,
            description = EXCLUDED.description;
        """)
        print("âœ“ pricing")
        
        # Ð›Ð¾Ð³Ð¸ Ð¸ÑÐ¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ð½Ð¸Ñ
        cur.execute("""
        CREATE TABLE IF NOT EXISTS usage_logs (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT REFERENCES users(id),
            license_key TEXT REFERENCES licenses(key),
            operation_type TEXT NOT NULL,
            units_used INTEGER NOT NULL,
            cost DECIMAL(10,2) NOT NULL,
            details JSONB DEFAULT '{}',
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        """)
        print("âœ“ usage_logs")
        
        # ÐŸÐ»Ð°Ñ‚ÐµÐ¶Ð½Ñ‹Ðµ Ð·Ð°Ð¿Ñ€Ð¾ÑÑ‹
        cur.execute("""
        CREATE TABLE IF NOT EXISTS payment_requests (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT REFERENCES users(id),
            license_key TEXT REFERENCES licenses(key),
            amount DECIMAL(10,2) NOT NULL,
            payment_id TEXT UNIQUE,
            status TEXT DEFAULT 'pending',
            payment_url TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            completed_at TIMESTAMPTZ
        );
        """)
        print("âœ“ payment_requests")
        
        # ÐÑƒÐ´Ð¸Ñ‚ Ð°Ð´Ð¼Ð¸Ð½Ð°
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
        print("âœ“ admin_audit")
        
        # ========== ÐœÐ˜Ð“Ð ÐÐ¦Ð˜Ð˜ ==========
        print("ðŸ”§ ÐŸÑ€Ð¸Ð¼ÐµÐ½ÑÑŽ Ð¼Ð¸Ð³Ñ€Ð°Ñ†Ð¸Ð¸...")
        
        # ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÐ¼ Ð½Ð°Ð»Ð¸Ñ‡Ð¸Ðµ ÐºÐ¾Ð»Ð¾Ð½ÐºÐ¸ last_login Ð² users
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='users' AND column_name='last_login';
        """)
        if not cur.fetchone():
            print("  â†’ Ð”Ð¾Ð±Ð°Ð²Ð»ÑÑŽ ÐºÐ¾Ð»Ð¾Ð½ÐºÑƒ last_login Ð² users...")
            cur.execute("""
                ALTER TABLE users 
                ADD COLUMN last_login TIMESTAMPTZ;
            """)
            print("  âœ“ ÐšÐ¾Ð»Ð¾Ð½ÐºÐ° last_login Ð´Ð¾Ð±Ð°Ð²Ð»ÐµÐ½Ð°")
        else:
            print("  âœ“ ÐšÐ¾Ð»Ð¾Ð½ÐºÐ° last_login ÑƒÐ¶Ðµ ÑÑƒÑ‰ÐµÑÑ‚Ð²ÑƒÐµÑ‚")
        
        # Migration: add telegram column to users if missing
        cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name='users' AND column_name='telegram';
        """)
        if not cur.fetchone():
            print("  -> Adding telegram column to users...")
            cur.execute("ALTER TABLE users ADD COLUMN telegram TEXT DEFAULT '';")
            print("  OK telegram added")
        else:
            print("  OK telegram exists")

        con.commit()
        print("âœ… Ð'Ð¡Ð• Ð¢ÐÐ'Ð›Ð˜Ð¦Ð« Ð¡ÐžÐ—Ð"ÐÐÐ«!")
    except Exception as e:
        print(f"âŒ ÐžÑˆÐ¸Ð±ÐºÐ°: {e}")
        con.rollback()
        raise
    finally:
        cur.close()
        con.close()

@app.on_event("startup")
def startup():
    init_db()

# =========================
# ÐŸÐ ÐžÐ’Ð•Ð ÐšÐ Ð›Ð˜Ð¦Ð•ÐÐ—Ð˜Ð˜
# =========================
class CheckReq(BaseModel):
    key: str
    hwid: str

@app.post("/api/check")
def check(req: CheckReq):
    """
    ÐŸÑ€Ð¾Ð²ÐµÑ€ÐºÐ° Ð»Ð¸Ñ†ÐµÐ½Ð·Ð¸Ð¸ Ð¿Ñ€Ð¸ Ð°ÐºÑ‚Ð¸Ð²Ð°Ñ†Ð¸Ð¸.
    Ð›ÐžÐ“Ð˜ÐšÐ:
    - ÐºÐ»ÑŽÑ‡ Ð´Ð¾Ð»Ð¶ÐµÐ½ ÑÑƒÑ‰ÐµÑÑ‚Ð²Ð¾Ð²Ð°Ñ‚ÑŒ, Ð±Ñ‹Ñ‚ÑŒ Ð½Ðµ revoked Ð¸ Ð½Ðµ expired
    - HWID "Ð¿Ñ€Ð¸Ð²ÑÐ·Ñ‹Ð²Ð°ÐµÑ‚ÑÑ" Ð¿Ñ€Ð¸ Ð¿ÐµÑ€Ð²Ð¾Ð¹ ÑƒÑÐ¿ÐµÑˆÐ½Ð¾Ð¹ Ð¿Ñ€Ð¾Ð²ÐµÑ€ÐºÐµ, ÐµÑÐ»Ð¸ Ð² Ð»Ð¸Ñ†ÐµÐ½Ð·Ð¸Ð¸ HWID Ð¿ÑƒÑÑ‚Ð¾Ð¹/temporary
    - Ð¿Ð¾ÑÐ»Ðµ Ð¿Ñ€Ð¸Ð²ÑÐ·ÐºÐ¸ HWID Ð´Ð¾Ð»Ð¶ÐµÐ½ ÑÐ¾Ð²Ð¿Ð°Ð´Ð°Ñ‚ÑŒ (Ð·Ð°Ñ‰Ð¸Ñ‚Ð° Ð¾Ñ‚ ÑˆÐ°Ñ€Ð¸Ð½Ð³Ð° ÐºÐ»ÑŽÑ‡ÐµÐ¹)
    """
    con = db()
    cur = con.cursor()
    try:
        cur.execute(
            "SELECT hwid, expires_at, revoked FROM licenses WHERE key=%s",
            (req.key,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="key_not_found")

        lic_hwid, expires_at, revoked = row

        # Ð£ÑÐ¿ÐµÑ…/Ð¾ÑˆÐ¸Ð±ÐºÐ¸ Ð¿Ð¾ ÑÑ€Ð¾ÐºÑƒ Ð¸ ÑÑ‚Ð°Ñ‚ÑƒÑÑƒ
        if revoked:
            raise HTTPException(status_code=403, detail="revoked")
        if now() > expires_at:
            raise HTTPException(status_code=403, detail="expired")

        # ÐÐ¾Ñ€Ð¼Ð°Ð»Ð¸Ð·ÑƒÐµÐ¼ HWID
        incoming_hwid = (req.hwid or "").strip().upper()
        stored_hwid = (lic_hwid or "").strip().upper()

        # Ð•ÑÐ»Ð¸ HWID ÐµÑ‰Ñ‘ Ð½Ðµ Ð¿Ñ€Ð¸Ð²ÑÐ·Ð°Ð½ â€” Ð¿Ñ€Ð¸Ð²ÑÐ·Ñ‹Ð²Ð°ÐµÐ¼ (Ñ€Ð°Ð·Ñ€ÐµÑˆÐ°ÐµÐ¼ Ð·Ð½Ð°Ñ‡ÐµÐ½Ð¸Ñ Ð²Ñ€Ð¾Ð´Ðµ "TEMP")
        if not stored_hwid or stored_hwid in {"TEMP", "NONE", "NULL", "-"}:
            if incoming_hwid:
                cur.execute(
                    "UPDATE licenses SET hwid=%s WHERE key=%s",
                    (incoming_hwid, req.key)
                )
                stored_hwid = incoming_hwid
        else:
            # Ð•ÑÐ»Ð¸ HWID ÑƒÐ¶Ðµ Ð¿Ñ€Ð¸Ð²ÑÐ·Ð°Ð½ â€” Ñ‚Ñ€ÐµÐ±ÑƒÐµÐ¼ ÑÐ¾Ð²Ð¿Ð°Ð´ÐµÐ½Ð¸Ðµ (ÐµÑÐ»Ð¸ ÐºÐ»Ð¸ÐµÐ½Ñ‚ Ð¿ÐµÑ€ÐµÐ´Ð°Ð» hwid)
            if incoming_hwid and incoming_hwid != stored_hwid:
                raise HTTPException(status_code=403, detail="hwid_mismatch")

        # ÐžÐ±Ð½Ð¾Ð²Ð»ÑÐµÐ¼ ÑÑ‡Ñ‘Ñ‚Ñ‡Ð¸Ðº Ð¿Ñ€Ð¾Ð²ÐµÑ€Ð¾Ðº
        cur.execute("""
            UPDATE licenses
            SET last_check_at=NOW(), check_count=check_count+1
            WHERE key=%s
        """, (req.key,))
        con.commit()

        return {"ok": True, "expires_at": expires_at.isoformat(), "hwid": stored_hwid}
    finally:
        cur.close()
        con.close()

# =========================
# Ð Ð•Ð“Ð˜Ð¡Ð¢Ð ÐÐ¦Ð˜Ð¯ (Ð¡ ÐŸÐžÐ”Ð ÐžÐ‘ÐÐ«ÐœÐ˜ Ð›ÐžÐ“ÐÐœÐ˜)
# =========================
class RegisterReq(BaseModel):
    email: str
    password: str
    license_key: str
    device_fingerprint: str
    device_name: str = "My Computer"
    telegram: str = ""

@app.post("/api/auth/register")
def register(req: RegisterReq, background_tasks: BackgroundTasks, request: Request):
    print(f"ðŸš€ REGISTER ATTEMPT: {req.email} with key {req.license_key}")
    print(f"ðŸ“± Device fingerprint: {req.device_fingerprint}")
    
    con = db()
    cur = con.cursor()
    
    try:
        # ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÐ¼ Ð»Ð¸Ñ†ÐµÐ½Ð·Ð¸ÑŽ
        print("ðŸ” Checking license...")
        cur.execute("""
            SELECT key, max_devices, expires_at, revoked 
            FROM licenses 
            WHERE key = %s
        """, (req.license_key,))
        
        license = cur.fetchone()
        if not license:
            print("âŒ License not found")
            raise HTTPException(status_code=404, detail="license_not_found")
        
        key, max_devices, expires_at, revoked = license
        print(f"âœ“ License found: {key}, expires: {expires_at}, revoked: {revoked}, max_devices: {max_devices}")
        
        if revoked:
            print("âŒ License revoked")
            raise HTTPException(status_code=403, detail="license_revoked")
        
        if now() > expires_at:
            print("âŒ License expired")
            raise HTTPException(status_code=403, detail="license_expired")
        
        # ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÐ¼ email
        print("ðŸ” Checking email...")
        cur.execute("SELECT id FROM users WHERE email = %s", (req.email,))
        if cur.fetchone():
            print("âŒ Email already registered")
            raise HTTPException(status_code=400, detail="email_already_registered")
        
        # Ð¡Ð¾Ð·Ð´Ð°ÐµÐ¼ Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»Ñ
        print("ðŸ” Creating user...")
        password_hash = hash_password(req.password)
        cur.execute("""
            INSERT INTO users (email, password_hash, license_key, telegram, balance, total_spent)
            VALUES (%s, %s, %s, %s, 0.00, 0.00)
            RETURNING id
        """, (req.email, password_hash, req.license_key, req.telegram))
        
        user_id = cur.fetchone()[0]
        print(f"âœ“ User created with ID: {user_id}")
        
        # Ð”Ð¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ ÑƒÑÑ‚Ñ€Ð¾Ð¹ÑÑ‚Ð²Ð¾
        print("ðŸ” Adding device...")
        client_ip = request.client.host if request.client else "0.0.0.0"
        cur.execute("""
            INSERT INTO user_devices (user_id, device_fingerprint, device_name, last_ip)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (user_id, req.device_fingerprint, req.device_name, client_ip))
        
        device_id = cur.fetchone()[0]
        print(f"âœ“ Device added with ID: {device_id}")
        
        # Ð¡Ð¾Ð·Ð´Ð°ÐµÐ¼ ÑÐµÑÑÐ¸ÑŽ
        print("ðŸ” Creating session...")
        session_token = generate_token()
        expires_at_session = now() + timedelta(days=30)
        
        cur.execute("""
            INSERT INTO user_sessions (user_id, session_token, device_id, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (user_id, session_token, device_id, expires_at_session))
        print(f"âœ“ Session created with token: {session_token[:10]}...")
        
        # Ð¡Ð¾Ð·Ð´Ð°ÐµÐ¼ Ð¿Ð¾Ð´Ñ‚Ð²ÐµÑ€Ð¶Ð´ÐµÐ½Ð¸Ðµ email
        print("ðŸ” Creating email confirmation...")
        confirm_token = generate_token()
        confirm_expires = now() + timedelta(hours=24)
        
        cur.execute("""
            INSERT INTO email_confirmations (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        """, (user_id, confirm_token, confirm_expires))
        print(f"âœ“ Email confirmation created with token: {confirm_token[:10]}...")
        
        con.commit()
        print("âœ… All changes committed!")
        
        # ÐžÑ‚Ð¿Ñ€Ð°Ð²Ð»ÑÐµÐ¼ Ð¿Ð¸ÑÑŒÐ¼Ð¾
        print("ðŸ“§ Sending confirmation email...")
        background_tasks.add_task(
            send_confirmation_email,
            req.email,
            confirm_token
        )
        print("ðŸ“§ Email task added")
        
        return {
            "success": True,
            "session_token": session_token,
            "user_id": user_id,
            "email": req.email,
            "need_confirmation": True
        }
        
    except HTTPException:
        print("âŒ HTTPException occurred")
        con.rollback()
        raise
    except Exception as e:
        print(f"âŒ UNEXPECTED ERROR: {str(e)}")
        print(f"âŒ Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()
        print("ðŸ”š Register function finished")

# =========================
# Ð’Ð¥ÐžÐ”
# =========================
class LoginReq(BaseModel):
    email: str
    password: str
    device_fingerprint: str
    device_name: str = "ÐœÐ¾Ð¹ ÐºÐ¾Ð¼Ð¿ÑŒÑŽÑ‚ÐµÑ€"

@app.post("/api/auth/login")
def login(req: LoginReq, request: Request):
    print(f"ðŸš€ LOGIN ATTEMPT: {req.email}")
    
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT u.*, l.max_devices 
            FROM users u
            JOIN licenses l ON u.license_key = l.key
            WHERE u.email = %s
        """, (req.email,))
        
        user = cur.fetchone()
        if not user:
            print("âŒ User not found")
            raise HTTPException(status_code=401, detail="invalid_credentials")
        
        print(f"âœ“ User found: {user['email']}")
        
        if not verify_password(req.password, user['password_hash']):
            print("âŒ Invalid password")
            raise HTTPException(status_code=401, detail="invalid_credentials")
        
        print("âœ“ Password correct")
        
        if not user['email_confirmed']:
            print("âŒ Email not confirmed")
            confirm_token = generate_token()
            confirm_expires = now() + timedelta(hours=24)
            
            cur.execute("""
                INSERT INTO email_confirmations (user_id, token, expires_at)
                VALUES (%s, %s, %s)
            """, (user['id'], confirm_token, confirm_expires))
            con.commit()
            
            raise HTTPException(
                status_code=403, 
                detail={
                    "error": "email_not_confirmed",
                    "email": user['email'],
                    "message": "ÐŸÐ¾Ð´Ñ‚Ð²ÐµÑ€Ð´Ð¸Ñ‚Ðµ email"
                }
            )
        
        print("ðŸ” Checking device...")
        cur.execute("""
            SELECT * FROM user_devices 
            WHERE user_id = %s AND device_fingerprint = %s
        """, (user['id'], req.device_fingerprint))
        
        device = cur.fetchone()
        client_ip = request.client.host if request.client else "0.0.0.0"
        
        if device:
            print(f"âœ“ Existing device found: {device['device_name']}")
            device_id = device['id']
            cur.execute("""
                UPDATE user_devices 
                SET last_login = NOW(), last_ip = %s
                WHERE id = %s
            """, (client_ip, device_id))
        else:
            print("ðŸ” New device, checking limit...")
            cur.execute("""
                SELECT COUNT(*) FROM user_devices 
                WHERE user_id = %s AND is_active = TRUE
            """, (user['id'],))
            device_count = cur.fetchone()['count']
            
            print(f"Active devices: {device_count}, max: {user['max_devices']}")
            
            if device_count >= user['max_devices']:
                print("âŒ Device limit exceeded")
                cur.execute("""
                    SELECT * FROM user_devices 
                    WHERE user_id = %s
                    ORDER BY last_login DESC
                """, (user['id'],))
                devices = cur.fetchall()
                
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "device_limit_exceeded",
                        "max_devices": user['max_devices'],
                        "current_devices": device_count,
                        "devices": [
                            {
                                "id": d['id'],
                                "name": d['device_name'],
                                "last_login": d['last_login'].isoformat() if d['last_login'] else None
                            }
                            for d in devices
                        ]
                    }
                )
            
            print("âœ“ Adding new device...")
            cur.execute("""
                INSERT INTO user_devices (user_id, device_fingerprint, device_name, last_ip)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (user['id'], req.device_fingerprint, req.device_name, client_ip))
            
            device_id = cur.fetchone()['id']
            print(f"âœ“ New device added with ID: {device_id}")
        
        print("ðŸ” Creating session...")
        session_token = generate_token()
        expires_at_session = now() + timedelta(days=30)
        
        cur.execute("""
            INSERT INTO user_sessions (user_id, session_token, device_id, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (user['id'], session_token, device_id, expires_at_session))
        
        cur.execute("""
            UPDATE users SET last_login = NOW() WHERE id = %s
        """, (user['id'],))
        
        con.commit()
        print(f"âœ“ Session created: {session_token[:10]}...")
        
        cur.execute("""
            SELECT * FROM user_devices 
            WHERE user_id = %s AND is_active = TRUE
            ORDER BY last_login DESC
        """, (user['id'],))
        devices = cur.fetchall()
        
        return {
            "success": True,
            "session_token": session_token,
            "user": {
                "id": user['id'],
                "email": user['email'],
                "license_key": user['license_key'],
                "balance": float(user['balance']),
                "email_confirmed": user['email_confirmed']
            },
            "devices": [
                {
                    "id": d['id'],
                    "name": d['device_name'],
                    "fingerprint": d['device_fingerprint'],
                    "last_login": d['last_login'].isoformat() if d['last_login'] else None,
                    "is_current": d['device_fingerprint'] == req.device_fingerprint
                }
                for d in devices
            ]
        }
        
    except HTTPException:
        con.rollback()
        raise
    except Exception as e:
        print(f"âŒ UNEXPECTED ERROR: {str(e)}")
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

# =========================
# Ð’Ð¥ÐžÐ” (Ð¡ ÐšÐ›Ð®Ð§ÐžÐœ) â€” ÐºÐ°Ðº Ð² Ð¿Ñ€Ð¾Ð´ÑƒÐºÑ‚Ðµ: ÐºÐ»ÑŽÑ‡ Ð²Ð²Ð¾Ð´Ð¸Ñ‚ÑÑ Ð²Ð¼ÐµÑÑ‚Ðµ Ñ Ð»Ð¾Ð³Ð¸Ð½Ð¾Ð¼
# =========================
class LoginWithKeyReq(BaseModel):
    email: str
    password: str
    license_key: str
    device_fingerprint: str
    device_name: str = "ÐœÐ¾Ð¹ ÐºÐ¾Ð¼Ð¿ÑŒÑŽÑ‚ÐµÑ€"

@app.post("/api/auth/login_with_key")
def login_with_key(req: LoginWithKeyReq, background_tasks: BackgroundTasks, request: Request):
    """
    Ð’Ñ…Ð¾Ð´ Ñ ÐºÐ»ÑŽÑ‡Ð¾Ð¼:
    - Ð¿Ñ€Ð¾Ð²ÐµÑ€ÑÐµÑ‚ Ð¿Ð°Ñ€Ð¾Ð»ÑŒ
    - Ð¿Ñ€Ð¾Ð²ÐµÑ€ÑÐµÑ‚/Ð¿Ñ€Ð¸Ð²ÑÐ·Ñ‹Ð²Ð°ÐµÑ‚ ÐºÐ»ÑŽÑ‡ Ðº Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»ÑŽ (1 ÐºÐ»ÑŽÑ‡ = 1 Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»ÑŒ)
    - Ñ€ÐµÐ³Ð¸ÑÑ‚Ñ€Ð¸Ñ€ÑƒÐµÑ‚ ÑƒÑÑ‚Ñ€Ð¾Ð¹ÑÑ‚Ð²Ð¾ Ñ Ð»Ð¸Ð¼Ð¸Ñ‚Ð¾Ð¼ max_devices (Ð¸Ð· licenses)
    - ÐµÑÐ»Ð¸ email Ð½Ðµ Ð¿Ð¾Ð´Ñ‚Ð²ÐµÑ€Ð¶Ð´ÐµÐ½: ÑÐ¾Ð·Ð´Ð°Ñ‘Ñ‚ Ñ‚Ð¾ÐºÐµÐ½ Ð¿Ð¾Ð´Ñ‚Ð²ÐµÑ€Ð¶Ð´ÐµÐ½Ð¸Ñ, Ð¾Ñ‚Ð¿Ñ€Ð°Ð²Ð»ÑÐµÑ‚ Ð¿Ð¸ÑÑŒÐ¼Ð¾, ÐÐž Ð²ÑÑ‘ Ñ€Ð°Ð²Ð½Ð¾ Ð²Ð¾Ð·Ð²Ñ€Ð°Ñ‰Ð°ÐµÑ‚ session_token
    """
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    try:
        # 1) ÐÐ°Ð¹Ð´Ñ‘Ð¼ Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»Ñ
        cur.execute("SELECT * FROM users WHERE email=%s", (req.email,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="invalid_credentials")

        if not verify_password(req.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="invalid_credentials")

        # 2) ÐŸÑ€Ð¾Ð²ÐµÑ€Ð¸Ð¼ Ð»Ð¸Ñ†ÐµÐ½Ð·Ð¸ÑŽ Ð¿Ð¾ ÐºÐ»ÑŽÑ‡Ñƒ
        cur.execute("SELECT key, expires_at, revoked, max_devices FROM licenses WHERE key=%s", (req.license_key,))
        lic = cur.fetchone()
        if not lic:
            raise HTTPException(status_code=404, detail="license_not_found")
        if lic["revoked"]:
            raise HTTPException(status_code=403, detail="license_revoked")
        if now() > lic["expires_at"]:
            raise HTTPException(status_code=403, detail="license_expired")

        # 3) ÐŸÑ€Ð¸Ð²ÑÐ·ÐºÐ° ÐºÐ»ÑŽÑ‡Ð° Ðº Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»ÑŽ (ÐµÑÐ»Ð¸ ÑƒÐ¶Ðµ Ð¿Ñ€Ð¸Ð²ÑÐ·Ð°Ð½ â€” Ð´Ð¾Ð»Ð¶ÐµÐ½ ÑÐ¾Ð²Ð¿Ð°Ð´Ð°Ñ‚ÑŒ)
        current_key = (user.get("license_key") or "").strip()
        incoming_key = (req.license_key or "").strip()
        if current_key and current_key != incoming_key:
            raise HTTPException(status_code=403, detail="license_key_mismatch")

        if not current_key:
            # ÑƒÐ±ÐµÐ´Ð¸Ð¼ÑÑ, Ñ‡Ñ‚Ð¾ ÐºÐ»ÑŽÑ‡ Ð½Ðµ Ð·Ð°Ð½ÑÑ‚ Ð´Ñ€ÑƒÐ³Ð¸Ð¼ Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»ÐµÐ¼
            cur.execute("SELECT id FROM users WHERE license_key=%s AND id<>%s", (incoming_key, user["id"]))
            if cur.fetchone():
                raise HTTPException(status_code=403, detail="license_key_already_used")

            cur.execute("UPDATE users SET license_key=%s WHERE id=%s", (incoming_key, user["id"]))
            user["license_key"] = incoming_key

        # 4) Ð Ð°Ð±Ð¾Ñ‚Ð° Ñ ÑƒÑÑ‚Ñ€Ð¾Ð¹ÑÑ‚Ð²Ð¾Ð¼ (Ð»Ð¸Ð¼Ð¸Ñ‚)
        client_ip = request.client.host if request.client else "0.0.0.0"
        max_devices = int(lic["max_devices"] or 1)

        cur.execute("""
            SELECT * FROM user_devices
            WHERE user_id=%s AND device_fingerprint=%s
        """, (user["id"], req.device_fingerprint))
        device = cur.fetchone()

        if device:
            device_id = device["id"]
            cur.execute("""
                UPDATE user_devices
                SET last_login=NOW(), last_ip=%s, device_name=%s, is_active=TRUE
                WHERE id=%s
            """, (client_ip, req.device_name, device_id))
        else:
            cur.execute("""
                SELECT COUNT(*) AS cnt FROM user_devices
                WHERE user_id=%s AND is_active=TRUE
            """, (user["id"],))
            cnt = int(cur.fetchone()["cnt"] or 0)
            if cnt >= max_devices:
                raise HTTPException(status_code=403, detail={"error": "device_limit_exceeded", "max_devices": max_devices, "current_devices": cnt})

            cur.execute("""
                INSERT INTO user_devices (user_id, device_fingerprint, device_name, last_ip, last_login)
                VALUES (%s, %s, %s, %s, NOW())
                RETURNING id
            """, (user["id"], req.device_fingerprint, req.device_name, client_ip))
            device_id = cur.fetchone()["id"]

        # 5) Ð¡ÐµÑÑÐ¸Ñ
        session_token = generate_token()
        expires_at_session = now() + timedelta(days=30)

        cur.execute("""
            INSERT INTO user_sessions (user_id, session_token, device_id, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (user["id"], session_token, device_id, expires_at_session))
        cur.execute("UPDATE users SET last_login=NOW() WHERE id=%s", (user["id"],))

        # 6) Ð•ÑÐ»Ð¸ Ð¿Ð¾Ñ‡Ñ‚Ð° Ð½Ðµ Ð¿Ð¾Ð´Ñ‚Ð²ÐµÑ€Ð¶Ð´ÐµÐ½Ð° â€” ÑÐ¾Ð·Ð´Ð°Ð´Ð¸Ð¼/Ð¾Ð±Ð½Ð¾Ð²Ð¸Ð¼ Ñ‚Ð¾ÐºÐµÐ½ Ð¸ Ð¾Ñ‚Ð¿Ñ€Ð°Ð²Ð¸Ð¼ Ð¿Ð¸ÑÑŒÐ¼Ð¾
        need_confirmation = not bool(user.get("email_confirmed"))
        if need_confirmation:
            confirm_token = generate_token()
            confirm_expires = now() + timedelta(hours=24)
            cur.execute("""
                INSERT INTO email_confirmations (user_id, token, expires_at)
                VALUES (%s, %s, %s)
            """, (user["id"], confirm_token, confirm_expires))
            # Ð¾Ñ‚Ð¿Ñ€Ð°Ð²ÐºÐ° Ð¿Ð¸ÑÑŒÐ¼Ð° Ð°ÑÐ¸Ð½Ñ…Ñ€Ð¾Ð½Ð½Ð¾
            background_tasks.add_task(send_confirmation_email, user["email"], confirm_token)

        con.commit()

        return {
            "success": True,
            "session_token": session_token,
            "need_confirmation": need_confirmation,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "license_key": user.get("license_key"),
                "balance": float(user.get("balance") or 0),
                "email_confirmed": bool(user.get("email_confirmed")),
            }
        }

    except HTTPException:
        con.rollback()
        raise
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()


# =========================
# ME â€” ÑÑ‚Ð°Ñ‚ÑƒÑ ÑÐµÑÑÐ¸Ð¸/Ð¿Ð¾Ñ‡Ñ‚Ñ‹/ÐºÐ»ÑŽÑ‡Ð° (Ð´Ð»Ñ Ð¾ÐºÐ½Ð° "Ð¯ Ð¿Ð¾Ð´Ñ‚Ð²ÐµÑ€Ð´Ð¸Ð»")
# =========================
def _get_session_user(cur, session_token: str):
    cur.execute("""
        SELECT s.user_id, s.expires_at, u.email, u.license_key, u.balance, u.currency, u.email_confirmed, u.total_spent
        FROM user_sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_token=%s
    """, (session_token,))
    return cur.fetchone()

@app.get("/api/auth/me")
def auth_me(authorization: str = Header(None)):
    """
    Authorization: Bearer <token>
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing_token")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing_token")

    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    try:
        row = _get_session_user(cur, token)
        if not row:
            raise HTTPException(status_code=401, detail="invalid_session")
        if now() > row["expires_at"]:
            raise HTTPException(status_code=401, detail="session_expired")

        # Ð¿Ð¾Ð´Ñ‚ÑÐ³Ð¸Ð²Ð°ÐµÐ¼ Ð»Ð¸Ñ†ÐµÐ½Ð·Ð¸ÑŽ
        lic = None
        if row.get("license_key"):
            cur.execute("SELECT key, expires_at, revoked, max_devices, plan FROM licenses WHERE key=%s", (row["license_key"],))
            lic = cur.fetchone()

        return {
            "success": True,
            "user": {
                "id": row["user_id"],
                "email": row["email"],
                "license_key": row.get("license_key"),
                "balance": float(row.get("balance") or 0),
                "currency": row.get("currency") or "USD",
                "email_confirmed": bool(row.get("email_confirmed")),
                "total_spent": float(row.get("total_spent") or 0),
            },
            "license": {
                "key": lic.get("key") if lic else None,
                "expires_at": lic.get("expires_at").isoformat() if lic and lic.get("expires_at") else None,
                "revoked": bool(lic.get("revoked")) if lic else None,
                "max_devices": int(lic.get("max_devices") or 1) if lic else None,
                "plan": lic.get("plan") if lic else None,
            } if lic else None
        }

    finally:
        cur.close()
        con.close()


# =========================
# ÐŸÐµÑ€ÐµÐ¾Ñ‚Ð¿Ñ€Ð°Ð²Ð¸Ñ‚ÑŒ Ð¿Ð¸ÑÑŒÐ¼Ð¾ Ð¿Ð¾Ð´Ñ‚Ð²ÐµÑ€Ð¶Ð´ÐµÐ½Ð¸Ñ
# =========================
class ResendConfirmReq(BaseModel):
    email: str

@app.post("/api/auth/resend-confirmation")
def resend_confirmation(req: ResendConfirmReq, background_tasks: BackgroundTasks):
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT id, email, email_confirmed FROM users WHERE email=%s", (req.email,))
        u = cur.fetchone()
        if not u:
            # Ð½Ðµ Ð¿Ð°Ð»Ð¸Ð¼ ÑÑƒÑ‰ÐµÑÑ‚Ð²Ð¾Ð²Ð°Ð½Ð¸Ðµ email
            return {"success": True}
        if u["email_confirmed"]:
            return {"success": True}

        confirm_token = generate_token()
        confirm_expires = now() + timedelta(hours=24)
        cur.execute("""
            INSERT INTO email_confirmations (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        """, (u["id"], confirm_token, confirm_expires))
        con.commit()

        background_tasks.add_task(send_confirmation_email, u["email"], confirm_token)
        return {"success": True}
    finally:
        cur.close()
        con.close()

@app.post("/api/auth/logout")
def logout(session_token: str = Form(...)):
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("DELETE FROM user_sessions WHERE session_token = %s", (session_token,))
        con.commit()
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

@app.get("/api/auth/confirm")
def confirm_email(token: str):
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("""
            SELECT user_id, expires_at 
            FROM email_confirmations 
            WHERE token = %s AND confirmed_at IS NULL
        """, (token,))
        
        row = cur.fetchone()
        if not row:
            return HTMLResponse("""
                <html>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h2>âŒ Ð¡ÑÑ‹Ð»ÐºÐ° Ð½ÐµÐ´ÐµÐ¹ÑÑ‚Ð²Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ð°</h2>
                    <p>Ð’Ð¾Ð·Ð¼Ð¾Ð¶Ð½Ð¾, Ð¾Ð½Ð° ÑƒÐ¶Ðµ Ð¸ÑÐ¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ð½Ð° Ð¸Ð»Ð¸ Ð¸ÑÑ‚ÐµÐºÐ»Ð°.</p>
                </body>
                </html>
            """)
        
        user_id, expires_at = row
        
        if now() > expires_at:
            return HTMLResponse("""
                <html>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h2>â° Ð¡ÑÑ‹Ð»ÐºÐ° Ð¸ÑÑ‚ÐµÐºÐ»Ð°</h2>
                    <p>Ð—Ð°Ð¿Ñ€Ð¾ÑÐ¸Ñ‚Ðµ Ð½Ð¾Ð²Ð¾Ðµ Ð¿Ð¸ÑÑŒÐ¼Ð¾ Ð² Ð¿Ñ€Ð¾Ð³Ñ€Ð°Ð¼Ð¼Ðµ.</p>
                </body>
                </html>
            """)
        
        cur.execute("""
            UPDATE users 
            SET email_confirmed = TRUE, email_confirmed_at = NOW()
            WHERE id = %s
        """, (user_id,))
        
        cur.execute("""
            UPDATE email_confirmations 
            SET confirmed_at = NOW()
            WHERE token = %s
        """, (token,))
        
        con.commit()
        
        return HTMLResponse("""
            <html>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h2>âœ… Email Ð¿Ð¾Ð´Ñ‚Ð²ÐµÑ€Ð¶Ð´Ñ‘Ð½!</h2>
                <p>Ð¢ÐµÐ¿ÐµÑ€ÑŒ Ð²Ñ‹ Ð¼Ð¾Ð¶ÐµÑ‚Ðµ Ð²Ð¾Ð¹Ñ‚Ð¸ Ð² Ð¿Ñ€Ð¾Ð³Ñ€Ð°Ð¼Ð¼Ñƒ.</p>
                <p>Ð’ÐµÑ€Ð½Ð¸Ñ‚ÐµÑÑŒ Ð² Ð¿Ñ€Ð¸Ð»Ð¾Ð¶ÐµÐ½Ð¸Ðµ Ð¸ Ð½Ð°Ð¶Ð¼Ð¸Ñ‚Ðµ "Ð’Ð¾Ð¹Ñ‚Ð¸".</p>
            </body>
            </html>
        """)
        
    except Exception as e:
        return HTMLResponse(f"""
            <html>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h2>âŒ ÐžÑˆÐ¸Ð±ÐºÐ°</h2>
                <p>{str(e)}</p>
            </body>
            </html>
        """)
    finally:
        cur.close()
        con.close()

# =========================
# ÐšÐ ÐÐ¡Ð˜Ð’Ð«Ð• ÐŸÐ˜Ð¡Ð¬ÐœÐ (ÐÐžÐ’Ð«Ð•)
# =========================
def send_confirmation_email(email: str, token: str):
    """ÐžÑ‚Ð¿Ñ€Ð°Ð²ÐºÐ° ÐºÑ€Ð°ÑÐ¸Ð²Ð¾Ð³Ð¾ Ð¿Ð¸ÑÑŒÐ¼Ð° Ñ Ð¿Ð¾Ð´Ñ‚Ð²ÐµÑ€Ð¶Ð´ÐµÐ½Ð¸ÐµÐ¼"""
    confirm_url = f"https://license-check-server-xatc.onrender.com/api/auth/confirm?token={token}"
    
    # Ð•ÑÐ»Ð¸ Ð½ÐµÑ‚ API ÐºÐ»ÑŽÑ‡Ð° - Ð¿ÐµÑ‡Ð°Ñ‚Ð°ÐµÐ¼ Ð² ÐºÐ¾Ð½ÑÐ¾Ð»ÑŒ (Ð´Ð»Ñ Ð¾Ñ‚Ð»Ð°Ð´ÐºÐ¸)
    if not SENDGRID_API_KEY:
        print(f"ðŸ“§ [Ð¢Ð•Ð¡Ð¢] ÐŸÐ¸ÑÑŒÐ¼Ð¾ Ð´Ð»Ñ {email}: {confirm_url}")
        return
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ÐŸÐ¾Ð´Ñ‚Ð²ÐµÑ€Ð¶Ð´ÐµÐ½Ð¸Ðµ email</title>
    </head>
    <body style="margin:0; padding:0; font-family: 'Segoe UI', Arial, sans-serif; background:#f5f7fa;">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px; margin:0 auto; background:white; border-radius:16px; margin-top:40px; box-shadow:0 4px 12px rgba(0,0,0,0.05);">
            <!-- Ð¨Ð°Ð¿ÐºÐ° -->
            <tr>
                <td style="padding:40px 40px 20px 40px; text-align:center; background:linear-gradient(135deg, #3b82f6, #8b5cf6); border-radius:16px 16px 0 0;">
                    <h1 style="color:white; margin:0; font-size:28px; font-weight:600;">TG Parser Sender</h1>
                    <p style="color:rgba(255,255,255,0.9); margin:10px 0 0 0; font-size:16px;">ÐŸÑ€Ð¾Ñ„ÐµÑÑÐ¸Ð¾Ð½Ð°Ð»ÑŒÐ½Ñ‹Ð¹ Ð¿Ð°Ñ€ÑÐ¸Ð½Ð³ Telegram</p>
                </td>
            </tr>
            
            <!-- ÐžÑÐ½Ð¾Ð²Ð½Ð¾Ð¹ ÐºÐ¾Ð½Ñ‚ÐµÐ½Ñ‚ -->
            <tr>
                <td style="padding:40px;">
                    <h2 style="color:#1e293b; margin:0 0 20px 0; font-size:24px;">ÐŸÐ¾Ð´Ñ‚Ð²ÐµÑ€Ð¶Ð´ÐµÐ½Ð¸Ðµ email</h2>
                    <p style="color:#475569; line-height:1.6; margin:0 0 30px 0; font-size:16px;">
                        Ð—Ð´Ñ€Ð°Ð²ÑÑ‚Ð²ÑƒÐ¹Ñ‚Ðµ!<br><br>
                        Ð”Ð»Ñ Ð·Ð°Ð²ÐµÑ€ÑˆÐµÐ½Ð¸Ñ Ñ€ÐµÐ³Ð¸ÑÑ‚Ñ€Ð°Ñ†Ð¸Ð¸ Ð² <strong>TG Parser Sender</strong> Ð¿Ð¾Ð´Ñ‚Ð²ÐµÑ€Ð´Ð¸Ñ‚Ðµ Ð²Ð°Ñˆ email Ð°Ð´Ñ€ÐµÑ.
                    </p>
                    
                    <!-- ÐšÐ½Ð¾Ð¿ÐºÐ° -->
                    <table cellpadding="0" cellspacing="0" style="margin:30px auto;">
                        <tr>
                            <td style="background:#4CAF50; border-radius:40px; padding:14px 40px;">
                                <a href="{confirm_url}" style="color:white; text-decoration:none; font-size:16px; font-weight:600; letter-spacing:0.5px;">âœ… ÐŸÐžÐ”Ð¢Ð’Ð•Ð Ð”Ð˜Ð¢Ð¬ EMAIL</a>
                            </td>
                        </tr>
                    </table>
                    
                    <!-- ÐÐ»ÑŒÑ‚ÐµÑ€Ð½Ð°Ñ‚Ð¸Ð²Ð½Ð°Ñ ÑÑÑ‹Ð»ÐºÐ° -->
                    <p style="color:#64748b; font-size:14px; margin:30px 0 0 0; text-align:center;">
                        Ð˜Ð»Ð¸ Ð¿ÐµÑ€ÐµÐ¹Ð´Ð¸Ñ‚Ðµ Ð¿Ð¾ ÑÑÑ‹Ð»ÐºÐµ:<br>
                        <a href="{confirm_url}" style="color:#3b82f6; word-break:break-all;">{confirm_url}</a>
                    </p>
                    
                    <!-- Ð¡Ñ€Ð¾Ðº Ð´ÐµÐ¹ÑÑ‚Ð²Ð¸Ñ -->
                    <p style="color:#94a3b8; font-size:13px; margin:30px 0 0 0; text-align:center; border-top:1px solid #e2e8f0; padding-top:30px;">
                        Ð¡ÑÑ‹Ð»ÐºÐ° Ð´ÐµÐ¹ÑÑ‚Ð²Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ð° 24 Ñ‡Ð°ÑÐ°.<br>
                        Ð•ÑÐ»Ð¸ Ð²Ñ‹ Ð½Ðµ Ñ€ÐµÐ³Ð¸ÑÑ‚Ñ€Ð¸Ñ€Ð¾Ð²Ð°Ð»Ð¸ÑÑŒ, Ð¿Ñ€Ð¾ÑÑ‚Ð¾ Ð¿Ñ€Ð¾Ð¸Ð³Ð½Ð¾Ñ€Ð¸Ñ€ÑƒÐ¹Ñ‚Ðµ ÑÑ‚Ð¾ Ð¿Ð¸ÑÑŒÐ¼Ð¾.
                    </p>
                </td>
            </tr>
            
            <!-- ÐŸÐ¾Ð´Ð²Ð°Ð» -->
            <tr>
                <td style="padding:30px 40px; background:#f8fafc; border-radius:0 0 16px 16px;">
                    <table width="100%">
                        <tr>
                            <td style="text-align:center;">
                                <p style="color:#64748b; margin:0 0 10px 0; font-size:14px;">
                                    Ð¡ ÑƒÐ²Ð°Ð¶ÐµÐ½Ð¸ÐµÐ¼, ÐºÐ¾Ð¼Ð°Ð½Ð´Ð° TG Parser Sender
                                </p>
                                <p style="color:#94a3b8; margin:0; font-size:13px;">
                                    ðŸ“§ support@tgparsersender.me | ðŸ“± @Ben_bell97
                                </p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    message = Mail(
        from_email=Email(FROM_EMAIL, FROM_NAME),
        to_emails=To(email),
        subject="ÐŸÐ¾Ð´Ñ‚Ð²ÐµÑ€Ð¶Ð´ÐµÐ½Ð¸Ðµ email Â· TG Parser Sender",
        html_content=Content("text/html", html_content)
    )
    
    try:
        sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"ðŸ“§ ÐšÑ€Ð°ÑÐ¸Ð²Ð¾Ðµ Ð¿Ð¸ÑÑŒÐ¼Ð¾ Ð¾Ñ‚Ð¿Ñ€Ð°Ð²Ð»ÐµÐ½Ð¾ Ð½Ð° {email}, ÑÑ‚Ð°Ñ‚ÑƒÑ: {response.status_code}")
    except Exception as e:
        print(f"âŒ ÐžÑˆÐ¸Ð±ÐºÐ° Ð¾Ñ‚Ð¿Ñ€Ð°Ð²ÐºÐ¸ Ð¿Ð¸ÑÑŒÐ¼Ð°: {e}")

def send_password_reset_email(email: str, token: str):
    """ÐžÑ‚Ð¿Ñ€Ð°Ð²ÐºÐ° ÐºÑ€Ð°ÑÐ¸Ð²Ð¾Ð³Ð¾ Ð¿Ð¸ÑÑŒÐ¼Ð° Ð´Ð»Ñ ÑÐ±Ñ€Ð¾ÑÐ° Ð¿Ð°Ñ€Ð¾Ð»Ñ"""
    reset_url = f"https://license-check-server-xatc.onrender.com/reset-password?token={token}"
    
    if not SENDGRID_API_KEY:
        print(f"ðŸ“§ [Ð¢Ð•Ð¡Ð¢] ÐŸÐ¸ÑÑŒÐ¼Ð¾ Ð´Ð»Ñ ÑÐ±Ñ€Ð¾ÑÐ° Ð¿Ð°Ñ€Ð¾Ð»Ñ {email}: {reset_url}")
        return
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Ð¡Ð±Ñ€Ð¾Ñ Ð¿Ð°Ñ€Ð¾Ð»Ñ</title>
    </head>
    <body style="margin:0; padding:0; font-family: 'Segoe UI', Arial, sans-serif; background:#f5f7fa;">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px; margin:0 auto; background:white; border-radius:16px; margin-top:40px; box-shadow:0 4px 12px rgba(0,0,0,0.05);">
            <!-- Ð¨Ð°Ð¿ÐºÐ° -->
            <tr>
                <td style="padding:40px 40px 20px 40px; text-align:center; background:linear-gradient(135deg, #ef4444, #f97316); border-radius:16px 16px 0 0;">
                    <h1 style="color:white; margin:0; font-size:28px; font-weight:600;">TG Parser Sender</h1>
                    <p style="color:rgba(255,255,255,0.9); margin:10px 0 0 0; font-size:16px;">Ð’Ð¾ÑÑÑ‚Ð°Ð½Ð¾Ð²Ð»ÐµÐ½Ð¸Ðµ Ð´Ð¾ÑÑ‚ÑƒÐ¿Ð°</p>
                </td>
            </tr>
            
            <!-- ÐžÑÐ½Ð¾Ð²Ð½Ð¾Ð¹ ÐºÐ¾Ð½Ñ‚ÐµÐ½Ñ‚ -->
            <tr>
                <td style="padding:40px;">
                    <h2 style="color:#1e293b; margin:0 0 20px 0; font-size:24px;">Ð¡Ð±Ñ€Ð¾Ñ Ð¿Ð°Ñ€Ð¾Ð»Ñ</h2>
                    <p style="color:#475569; line-height:1.6; margin:0 0 30px 0; font-size:16px;">
                        ÐœÑ‹ Ð¿Ð¾Ð»ÑƒÑ‡Ð¸Ð»Ð¸ Ð·Ð°Ð¿Ñ€Ð¾Ñ Ð½Ð° ÑÐ±Ñ€Ð¾Ñ Ð¿Ð°Ñ€Ð¾Ð»Ñ Ð´Ð»Ñ Ð²Ð°ÑˆÐµÐ³Ð¾ Ð°ÐºÐºÐ°ÑƒÐ½Ñ‚Ð°.
                    </p>
                    
                    <!-- ÐšÐ½Ð¾Ð¿ÐºÐ° -->
                    <table cellpadding="0" cellspacing="0" style="margin:30px auto;">
                        <tr>
                            <td style="background:#3b82f6; border-radius:40px; padding:14px 40px;">
                                <a href="{reset_url}" style="color:white; text-decoration:none; font-size:16px; font-weight:600; letter-spacing:0.5px;">ðŸ”„ Ð¡Ð‘Ð ÐžÐ¡Ð˜Ð¢Ð¬ ÐŸÐÐ ÐžÐ›Ð¬</a>
                            </td>
                        </tr>
                    </table>
                    
                    <!-- ÐÐ»ÑŒÑ‚ÐµÑ€Ð½Ð°Ñ‚Ð¸Ð²Ð½Ð°Ñ ÑÑÑ‹Ð»ÐºÐ° -->
                    <p style="color:#64748b; font-size:14px; margin:30px 0 0 0; text-align:center;">
                        Ð˜Ð»Ð¸ Ð¿ÐµÑ€ÐµÐ¹Ð´Ð¸Ñ‚Ðµ Ð¿Ð¾ ÑÑÑ‹Ð»ÐºÐµ:<br>
                        <a href="{reset_url}" style="color:#3b82f6; word-break:break-all;">{reset_url}</a>
                    </p>
                    
                    <!-- ÐŸÑ€ÐµÐ´ÑƒÐ¿Ñ€ÐµÐ¶Ð´ÐµÐ½Ð¸Ðµ -->
                    <p style="color:#94a3b8; font-size:13px; margin:30px 0 0 0; text-align:center; border-top:1px solid #e2e8f0; padding-top:30px;">
                        Ð¡ÑÑ‹Ð»ÐºÐ° Ð´ÐµÐ¹ÑÑ‚Ð²Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ð° 1 Ñ‡Ð°Ñ.<br>
                        Ð•ÑÐ»Ð¸ Ð²Ñ‹ Ð½Ðµ Ð·Ð°Ð¿Ñ€Ð°ÑˆÐ¸Ð²Ð°Ð»Ð¸ ÑÐ±Ñ€Ð¾Ñ Ð¿Ð°Ñ€Ð¾Ð»Ñ, Ð¿Ñ€Ð¾Ð¸Ð³Ð½Ð¾Ñ€Ð¸Ñ€ÑƒÐ¹Ñ‚Ðµ ÑÑ‚Ð¾ Ð¿Ð¸ÑÑŒÐ¼Ð¾.
                    </p>
                </td>
            </tr>
            
            <!-- ÐŸÐ¾Ð´Ð²Ð°Ð» -->
            <tr>
                <td style="padding:30px 40px; background:#f8fafc; border-radius:0 0 16px 16px;">
                    <table width="100%">
                        <tr>
                            <td style="text-align:center;">
                                <p style="color:#64748b; margin:0 0 10px 0; font-size:14px;">
                                    Ð¡ ÑƒÐ²Ð°Ð¶ÐµÐ½Ð¸ÐµÐ¼, ÐºÐ¾Ð¼Ð°Ð½Ð´Ð° TG Parser Sender
                                </p>
                                <p style="color:#94a3b8; margin:0; font-size:13px;">
                                    ðŸ“§ support@tgparsersender.me | ðŸ“± @Ben_bell97
                                </p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    message = Mail(
        from_email=Email(FROM_EMAIL, FROM_NAME),
        to_emails=To(email),
        subject="Ð¡Ð±Ñ€Ð¾Ñ Ð¿Ð°Ñ€Ð¾Ð»Ñ Â· TG Parser Sender",
        html_content=Content("text/html", html_content)
    )
    
    try:
        sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"ðŸ“§ ÐšÑ€Ð°ÑÐ¸Ð²Ð¾Ðµ Ð¿Ð¸ÑÑŒÐ¼Ð¾ Ð´Ð»Ñ ÑÐ±Ñ€Ð¾ÑÐ° Ð¿Ð°Ñ€Ð¾Ð»Ñ Ð¾Ñ‚Ð¿Ñ€Ð°Ð²Ð»ÐµÐ½Ð¾ Ð½Ð° {email}, ÑÑ‚Ð°Ñ‚ÑƒÑ: {response.status_code}")
    except Exception as e:
        print(f"âŒ ÐžÑˆÐ¸Ð±ÐºÐ° Ð¾Ñ‚Ð¿Ñ€Ð°Ð²ÐºÐ¸ Ð¿Ð¸ÑÑŒÐ¼Ð°: {e}")

# =========================
# ÐÐ”ÐœÐ˜Ð ÐŸÐÐÐ•Ð›Ð¬ - Ð”ÐÐ¨Ð‘ÐžÐ Ð”
# =========================
@app.get("/admin/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": ""})

@app.post("/admin/login")
def login(request: Request, token: str = Form(...)):
    if token != ADMIN_TOKEN:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "ÐÐµÐ²ÐµÑ€Ð½Ñ‹Ð¹ Ñ‚Ð¾ÐºÐµÐ½"}
        )
    
    request.session["is_admin"] = True
    return RedirectResponse("/admin", status_code=303)

@app.post("/admin/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("SELECT * FROM licenses ORDER BY updated_at DESC LIMIT 500")
        rows = cur.fetchall()
        
        now_ts = now()
        active = 0
        expired = 0
        revoked = 0
        
        for row in rows:
            if row['revoked']:
                revoked += 1
            elif row['expires_at'] > now_ts:
                active += 1
            else:
                expired += 1
        
        try:
            cur.execute("SELECT COUNT(*) as count FROM users")
            total_users = cur.fetchone()['count'] or 0
        except:
            total_users = 0
            
        try:
            cur.execute("SELECT COUNT(*) as count FROM users WHERE email_confirmed = TRUE")
            confirmed_users = cur.fetchone()['count'] or 0
        except:
            confirmed_users = 0
            
        try:
            cur.execute("SELECT COALESCE(SUM(balance), 0) as total FROM users")
            total_balance = float(cur.fetchone()['total'] or 0)
        except:
            total_balance = 0
            
        try:
            cur.execute("SELECT COALESCE(SUM(total_spent), 0) as total FROM users")
            total_revenue = float(cur.fetchone()['total'] or 0)
        except:
            total_revenue = 0
            
        try:
            cur.execute("SELECT COUNT(*) as count FROM user_devices WHERE is_active = TRUE")
            total_devices = cur.fetchone()['count'] or 0
        except:
            total_devices = 0
            
        try:
            cur.execute("SELECT COUNT(DISTINCT user_id) as count FROM user_devices WHERE is_active = TRUE")
            users_with_devices = cur.fetchone()['count'] or 0
        except:
            users_with_devices = 0
        
        stats = {
            "total": len(rows),
            "active": active,
            "expired": expired,
            "revoked": revoked,
            "total_users": total_users,
            "confirmed_users": confirmed_users,
            "total_balance": total_balance,
            "total_revenue": total_revenue,
            "total_devices": total_devices,
            "users_with_devices": users_with_devices
        }
        
    except Exception as e:
        print(f"ÐžÑˆÐ¸Ð±ÐºÐ° Ð² Ð°Ð´Ð¼Ð¸Ð½ÐºÐµ: {e}")
        rows = []
        stats = {
            "total": 0, "active": 0, "expired": 0, "revoked": 0,
            "total_users": 0, "confirmed_users": 0,
            "total_balance": 0, "total_revenue": 0,
            "total_devices": 0, "users_with_devices": 0
        }
        
    finally:
        cur.close()
        con.close()
    
    return templates.TemplateResponse(
        "admin_dashboard.html",
        {
            "request": request,
            "rows": rows,
            "stats": stats,
            "now": now_ts,
            "active_tab": "dashboard"
        }
    )

# =========================
# ÐÐžÐ’Ð«Ð• API Ð”Ð›Ð¯ ÐÐ”ÐœÐ˜ÐÐšÐ˜
# =========================

class DepositRequest(BaseModel):
    user_id: int
    amount: float
    method: str
    note: str = ""

@app.post("/admin/api/deposit")
def admin_deposit(request: Request, data: DepositRequest):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("BEGIN")
        
        cur.execute("SELECT license_key FROM users WHERE id = %s", (data.user_id,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        license_key = user[0]
        
        cur.execute("""
            UPDATE users 
            SET balance = balance + %s 
            WHERE id = %s
            RETURNING balance
        """, (data.amount, data.user_id))
        
        new_balance = cur.fetchone()[0]
        
        cur.execute("""
            INSERT INTO transactions 
            (user_id, license_key, amount, type, description, metadata)
            VALUES (%s, %s, %s, 'deposit', %s, %s)
        """, (
            data.user_id, 
            license_key, 
            data.amount, 
            f"Ð ÑƒÑ‡Ð½Ð¾Ðµ Ð¿Ð¾Ð¿Ð¾Ð»Ð½ÐµÐ½Ð¸Ðµ: {data.note}" if data.note else "Ð ÑƒÑ‡Ð½Ð¾Ðµ Ð¿Ð¾Ð¿Ð¾Ð»Ð½ÐµÐ½Ð¸Ðµ",
            json.dumps({"method": data.method, "admin": True})
        ))
        
        con.commit()
        
        return {"success": True, "new_balance": float(new_balance)}
        
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

class ResetPasswordRequest(BaseModel):
    user_id: int
    email: str

@app.post("/admin/api/reset-password")
def admin_reset_password(request: Request, data: ResetPasswordRequest):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    reset_token = generate_token()
    expires_at = now() + timedelta(hours=24)
    
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("""
            INSERT INTO password_resets (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        """, (data.user_id, reset_token, expires_at))
        con.commit()
        
        send_password_reset_email(data.email, reset_token)
        
        return {"success": True}
        
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

class UnlinkDevicesRequest(BaseModel):
    user_id: int

@app.post("/admin/api/unlink-devices")
def admin_unlink_devices(request: Request, data: UnlinkDevicesRequest):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("""
            SELECT id FROM user_devices 
            WHERE user_id = %s AND is_active = TRUE
        """, (data.user_id,))
        devices = cur.fetchall()
        
        count = len(devices)
        
        cur.execute("""
            UPDATE user_devices 
            SET is_active = FALSE 
            WHERE user_id = %s
        """, (data.user_id,))
        
        cur.execute("""
            DELETE FROM user_sessions 
            WHERE user_id = %s
        """, (data.user_id,))
        
        con.commit()
        
        return {"success": True, "count": count}
        
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

class UnlinkSingleDeviceRequest(BaseModel):
    device_id: int

@app.post("/admin/api/unlink-device")
def admin_unlink_device(request: Request, data: UnlinkSingleDeviceRequest):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("""
            UPDATE user_devices 
            SET is_active = FALSE 
            WHERE id = %s
        """, (data.device_id,))
        
        cur.execute("""
            DELETE FROM user_sessions 
            WHERE device_id = %s
        """, (data.device_id,))
        
        con.commit()
        
        return {"success": True}
        
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

class UpdateLimitRequest(BaseModel):
    key: str
    max_devices: int

@app.post("/admin/api/update-limit")
def admin_update_limit(request: Request, data: UpdateLimitRequest):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("""
            UPDATE licenses 
            SET max_devices = %s 
            WHERE key = %s
        """, (data.max_devices, data.key))
        con.commit()
        
        return {"success": True}
        
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

# =========================
# Ð¡Ð¢Ð ÐÐÐ˜Ð¦Ð Ð›Ð˜Ð¦Ð•ÐÐ—Ð˜Ð™
# =========================
@app.get("/admin/licenses", response_class=HTMLResponse)
def admin_licenses(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("SELECT * FROM licenses ORDER BY updated_at DESC LIMIT 500")
        rows = cur.fetchall()
    except:
        rows = []
    finally:
        cur.close()
        con.close()
    
    return templates.TemplateResponse(
        "admin_licenses.html",
        {
            "request": request,
            "rows": rows,
            "now": now(),
            "active_tab": "licenses"
        }
    )

# =========================
# Ð¡Ð¢Ð ÐÐÐ˜Ð¦Ð ÐŸÐžÐ›Ð¬Ð—ÐžÐ’ÐÐ¢Ð•Ð›Ð•Ð™
# =========================
@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT u.*, l.plan, l.expires_at as license_expires 
            FROM users u
            LEFT JOIN licenses l ON u.license_key = l.key
            ORDER BY u.created_at DESC
            LIMIT 500
        """)
        users = cur.fetchall()
    except:
        users = []
    finally:
        cur.close()
        con.close()
    
    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "users": users,
            "active_tab": "users"
        }
    )

# =========================
# Ð¡Ð¢Ð ÐÐÐ˜Ð¦Ð Ð£Ð¡Ð¢Ð ÐžÐ™Ð¡Ð¢Ð’
# =========================
@app.get("/admin/devices", response_class=HTMLResponse)
def admin_devices(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT d.*, u.email, u.license_key
            FROM user_devices d
            JOIN users u ON d.user_id = u.id
            WHERE d.is_active = TRUE
            ORDER BY d.last_login DESC
            LIMIT 500
        """)
        devices = cur.fetchall()
    except:
        devices = []
    finally:
        cur.close()
        con.close()
    
    return templates.TemplateResponse(
        "admin_devices.html",
        {
            "request": request,
            "devices": devices,
            "active_tab": "devices"
        }
    )

# =========================
# Ð¡Ð¢Ð ÐÐÐ˜Ð¦Ð Ð¢Ð ÐÐÐ—ÐÐšÐ¦Ð˜Ð™
# =========================
@app.get("/admin/transactions", response_class=HTMLResponse)
def admin_transactions(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT t.*, u.email
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            ORDER BY t.created_at DESC
            LIMIT 500
        """)
        transactions = cur.fetchall()
    except:
        transactions = []
    finally:
        cur.close()
        con.close()
    
    return templates.TemplateResponse(
        "admin_transactions.html",
        {
            "request": request,
            "transactions": transactions,
            "active_tab": "transactions"
        }
    )

# =========================
# Ð¡Ð¢Ð ÐÐÐ˜Ð¦Ð ÐÐÐ¡Ð¢Ð ÐžÐ•Ðš
# =========================
@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    
    return templates.TemplateResponse(
        "admin_settings.html",
        {
            "request": request,
            "active_tab": "settings"
        }
    )

# =========================
# API Ð£Ð¡Ð¢Ð ÐžÐ™Ð¡Ð¢Ð’
# =========================
class DeviceReq(BaseModel):
    session_token: str
    device_fingerprint: str

@app.post("/api/devices/list")
def list_devices(req: DeviceReq):
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT d.* 
            FROM user_devices d
            JOIN user_sessions s ON d.user_id = s.user_id
            WHERE s.session_token = %s AND d.is_active = TRUE
            ORDER BY d.last_login DESC
        """, (req.session_token,))
        
        devices = cur.fetchall()
        
        return {
            "devices": [
                {
                    "id": d['id'],
                    "name": d['device_name'],
                    "fingerprint": d['device_fingerprint'],
                    "last_login": d['last_login'].isoformat() if d['last_login'] else None,
                    "is_current": d['device_fingerprint'] == req.device_fingerprint
                }
                for d in devices
            ]
        }
        
    finally:
        cur.close()
        con.close()

@app.post("/api/devices/rename")
def rename_device(device_id: int, new_name: str, session_token: str):
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("""
            UPDATE user_devices 
            SET device_name = %s
            WHERE id = %s AND user_id = (
                SELECT user_id FROM user_sessions WHERE session_token = %s
            )
        """, (new_name, device_id, session_token))
        
        con.commit()
        return {"success": True}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

@app.post("/api/devices/remove")
def remove_device(device_id: int, session_token: str):
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("""
            SELECT d.id 
            FROM user_devices d
            JOIN user_sessions s ON d.user_id = s.user_id
            WHERE s.session_token = %s AND d.id = %s AND d.device_fingerprint != (
                SELECT device_fingerprint FROM user_devices WHERE id = (
                    SELECT device_id FROM user_sessions WHERE session_token = %s
                )
            )
        """, (session_token, device_id, session_token))
        
        if not cur.fetchone():
            raise HTTPException(status_code=403, detail="cannot_remove_current_device")
        
        cur.execute("""
            UPDATE user_devices 
            SET is_active = FALSE
            WHERE id = %s
        """, (device_id,))
        
        cur.execute("""
            DELETE FROM user_sessions 
            WHERE device_id = %s
        """, (device_id,))
        
        con.commit()
        return {"success": True}
        
    except HTTPException:
        con.rollback()
        raise
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

# =========================
# API Ð‘ÐÐ›ÐÐÐ¡Ð
# =========================
class BalanceReq(BaseModel):
    session_token: str

@app.post("/api/balance/get")
def get_balance(req: BalanceReq):
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT u.balance, u.total_spent, u.currency
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_token = %s
        """, (req.session_token,))
        
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="invalid_session")
        
        return {
            "balance": float(user['balance']),
            "total_spent": float(user['total_spent']),
            "currency": user['currency']
        }
        
    finally:
        cur.close()
        con.close()

class EstimateReq(BaseModel):
    session_token: str
    operation: str
    units: int

@app.post("/api/balance/estimate")
def estimate_cost(req: EstimateReq):
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("""
            SELECT final_price, min_units 
            FROM pricing 
            WHERE operation_type = %s
        """, (req.operation,))
        
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="operation_not_found")
        
        final_price, min_units = row
        units = max(req.units, min_units)
        total_cost = final_price * units
        
        cur.execute("""
            SELECT u.balance 
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_token = %s
        """, (req.session_token,))
        
        balance = cur.fetchone()[0]
        
        return {
            "total_cost": float(total_cost),
            "current_balance": float(balance),
            "sufficient": balance >= total_cost
        }
        
    finally:
        cur.close()
        con.close()

class ChargeReq(BaseModel):
    session_token: str
    operation: str
    units: int
    description: str = ""

@app.post("/api/balance/charge")
def charge(req: ChargeReq):
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("BEGIN")
        
        cur.execute("""
            SELECT final_price, min_units 
            FROM pricing 
            WHERE operation_type = %s
        """, (req.operation,))
        
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="operation_not_found")
        
        final_price, min_units = row
        units = max(req.units, min_units)
        total_cost = final_price * units
        
        cur.execute("""
            SELECT u.id, u.balance, u.license_key
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_token = %s
            FOR UPDATE
        """, (req.session_token,))
        
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="invalid_session")
        
        user_id, balance, license_key = user
        
        if balance < total_cost:
            raise HTTPException(status_code=403, detail="insufficient_funds")
        
        cur.execute("""
            UPDATE users 
            SET balance = balance - %s, total_spent = total_spent + %s
            WHERE id = %s
            RETURNING balance
        """, (total_cost, total_cost, user_id))
        
        new_balance = cur.fetchone()[0]
        
        cur.execute("""
            INSERT INTO usage_logs 
            (user_id, license_key, operation_type, units_used, cost, details)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, license_key, req.operation, units, total_cost, 
              json.dumps({"description": req.description})))
        
        cur.execute("COMMIT")
        
        return {
            "success": True,
            "charged": float(total_cost),
            "new_balance": float(new_balance)
        }
        
    except HTTPException:
        cur.execute("ROLLBACK")
        raise
    except Exception as e:
        cur.execute("ROLLBACK")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

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

def _extract_json(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    m = re.search(r"\{.*\}", text, flags=re.S)
    if not m:
        raise ValueError("No JSON object found")
    return json.loads(m.group(0))

@app.post("/api/ai/score")
def ai_score(req: AIScoreReq) -> Dict[str, Any]:
    try:
        client = get_openai_client()
        items = [{"id": it.id, "text": (it.text or "")[:1200]} for it in req.items]
        
        system_prompt = (
            "Ð¢Ñ‹ Ð°Ð½Ð°Ð»Ð¸Ð·Ð¸Ñ€ÑƒÐµÑˆÑŒ ÑÐ¾Ð¾Ð±Ñ‰ÐµÐ½Ð¸Ñ Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»ÐµÐ¹ Telegram Ð½Ð° Ñ€ÑƒÑÑÐºÐ¾Ð¼ ÑÐ·Ñ‹ÐºÐµ.\n"
            "Ð¯ Ð´Ð°Ð¼ Ð¿Ñ€Ð¾Ð¼Ñ‚ (ÐºÐ¾Ð³Ð¾ Ð¸Ñ‰ÐµÐ¼) Ð¸ Ñ‚ÐµÐºÑÑ‚Ñ‹ ÑÐ¾Ð¾Ð±Ñ‰ÐµÐ½Ð¸Ð¹ Ð»ÑŽÐ´ÐµÐ¹.\n"
            "Ð’ÐµÑ€Ð½Ð¸ Ð¡Ð¢Ð ÐžÐ“Ðž Ð²Ð°Ð»Ð¸Ð´Ð½Ñ‹Ð¹ JSON (Ð±ÐµÐ· markdown, Ð±ÐµÐ· Ð¿Ð¾ÑÑÐ½ÐµÐ½Ð¸Ð¹) ÑÑ‚Ñ€Ð¾Ð³Ð¾ Ð² Ñ„Ð¾Ñ€Ð¼Ð°Ñ‚Ðµ:\n"
            "{ \"results\": [ {\"id\":\"...\",\"score\":0-100,\"pass\":true/false,\"reason\":\"ÐºÐ¾Ñ€Ð¾Ñ‚ÐºÐ¾ 5-12 ÑÐ»Ð¾Ð²\",\"flags\":[\"bot_like|spam_like|toxic|low_quality\"...]}, ... ] }\n"
            "ÐŸÑ€Ð°Ð²Ð¸Ð»Ð¾ pass: true ÐµÑÐ»Ð¸ score >= min_score Ð¸ Ð½ÐµÑ‚ flags bot_like/spam_like/toxic.\n"
            "Reason Ð½Ð° Ñ€ÑƒÑÑÐºÐ¾Ð¼."
        )
        
        payload = {
            "prompt": req.prompt,
            "min_score": req.min_score,
            "items": items
        }
        
        resp = client.responses.create(
            model="gpt-4.1-mini",
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}
            ],
        )
        
        out_text = getattr(resp, "output_text", None)
        if not out_text:
            out_text = ""
            for o in getattr(resp, "output", []) or []:
                if getattr(o, "type", None) == "message":
                    for c in getattr(o, "content", []) or []:
                        if getattr(c, "type", None) == "output_text":
                            out_text += getattr(c, "text", "")
        
        data = _extract_json(out_text)
        
        if not isinstance(data, dict) or "results" not in data:
            raise ValueError(f"bad_ai_response: {out_text[:200]}")
        
        return data
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI error: {type(e).__name__}: {e}")

# =========================
# CRUD Ð”Ð›Ð¯ Ð›Ð˜Ð¦Ð•ÐÐ—Ð˜Ð™
# =========================
@app.post("/admin/upsert")
def upsert_license(
    request: Request,
    key: str = Form(...),
    hwid: str = Form(""),
    days: int = Form(...),
    note: str = Form("")
):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    expires = now() + timedelta(days=int(days))

    con = db()
    cur = con.cursor()
    
    hwid_value = hwid.strip() if hwid.strip() else "temp"
    
    cur.execute("""
        INSERT INTO licenses(key, hwid, expires_at, revoked, note, updated_at)
        VALUES (%s,%s,%s,FALSE,%s,NOW())
        ON CONFLICT (key) DO UPDATE SET
            hwid=EXCLUDED.hwid,
            expires_at=EXCLUDED.expires_at,
            revoked=FALSE,
            note=EXCLUDED.note,
            updated_at=NOW()
    """, (key.strip(), hwid_value, expires, note.strip()))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse("/admin", status_code=303)

@app.post("/admin/add_days")
def add_days(request: Request, key: str = Form(...), add: int = Form(...)):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    con = db()
    cur = con.cursor()
    cur.execute("""
        UPDATE licenses
        SET expires_at = expires_at + (%s || ' days')::interval,
            revoked = FALSE,
            updated_at = NOW()
        WHERE key=%s
    """, (add, key))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse("/admin", status_code=303)

@app.post("/admin/revoke")
def revoke(request: Request, key: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=TRUE WHERE key=%s", (key,))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse("/admin", status_code=303)

@app.post("/admin/unrevoke")
def unrevoke(request: Request, key: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=FALSE WHERE key=%s", (key,))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse("/admin", status_code=303)

@app.post("/admin/delete")
def delete(request: Request, key: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    con = db()
    cur = con.cursor()
    cur.execute("DELETE FROM licenses WHERE key=%s", (key,))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse("/admin", status_code=303)

@app.get("/admin/export")
def export_csv(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM licenses ORDER BY updated_at DESC")
    rows = cur.fetchall()
    cur.close()
    con.close()

    output = io.StringIO()
    writer = csv.writer(output)
    if rows:
        writer.writerow(rows[0].keys())
        for row in rows:
            writer.writerow(row.values())

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=licenses.csv"}
    )

@app.post("/admin/generate_key")
def generate_key(request: Request, prefix: str = Form("")):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    
    import random
    import string
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    key = f"{prefix}-{suffix}" if prefix else suffix
    
    return templates.TemplateResponse(
        "admin_licenses.html",
        {"request": request, "generated_key": key}
    )

# =========================
# Ð—ÐÐŸÐ£Ð¡Ðš
# =========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
