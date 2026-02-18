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
# ---
# =========================
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content

from openai import OpenAI

app = FastAPI()

# =========================
# ---
# =========================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": type(exc).__name__, "message": str(exc)}
    )

# =========================
# ---
# =========================
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
ADMIN_PANEL_SECRET = os.environ.get("ADMIN_PANEL_SECRET", "change-me")

# =========================
# ---
# =========================
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
FROM_EMAIL = "noreply@tgparsersender.me"  # ???????? email ???? ???????????????????? ?? SendGrid
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
# ---
# =========================
app.add_middleware(
    SessionMiddleware,
    secret_key=ADMIN_PANEL_SECRET,
    https_only=True,
    same_site="lax",
)

templates = Jinja2Templates(directory="templates")

# =========================
# ---
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
# ---
# =========================
def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)

def init_db():
    """???????????????? ???????? ????????????"""
    pass  # log
    con = db()
    cur = con.cursor()
    
    try:
        # ---
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
        pass  # log
        
        # ---
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
        pass  # log
        
        # ---
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
        pass  # log
        
        # ---
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
        pass  # log
        
        # ---
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
        pass  # log
        
        # ---
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
        pass  # log
        
        # ---
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
        pass  # log
        
        # ---
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
            ('parse',    0.0005, 0.0005, 100, 'Parsing one message'),
            ('ai_parse', 0.0002, 0.0004,   1, 'AI analysis per person (x2 markup)'),
            ('sender',   0.001,  0.001,   50, 'Sending one message'),
            ('invite',   0.002,  0.002,   20, 'Inviting one user')
        ON CONFLICT (operation_type) DO UPDATE SET
            base_price  = EXCLUDED.base_price,
            final_price = EXCLUDED.final_price,
            min_units   = EXCLUDED.min_units,
            description = EXCLUDED.description;
        
        -- Force update ai_parse pricing to correct values regardless of what was in DB
        UPDATE pricing SET
            base_price  = 0.0002,
            final_price = 0.0004,
            min_units   = 1,
            description = 'AI analysis per person (x2 markup)'
        WHERE operation_type = 'ai_parse';
        """)
        pass  # log
        
        # ---
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
        pass  # log
        
        # ---
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
        pass  # log
        
        # ---
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
        pass  # log
        
        # ---
        pass  # log
        
        # ---
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='users' AND column_name='last_login';
        """)
        if not cur.fetchone():
            pass  # log
            cur.execute("""
                ALTER TABLE users 
                ADD COLUMN last_login TIMESTAMPTZ;
            """)
            pass  # log
        else:
            pass  # log
        
                # Migration: add telegram column to users
        cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name='users' AND column_name='telegram';
        """)
        if not cur.fetchone():
            cur.execute("ALTER TABLE users ADD COLUMN telegram TEXT DEFAULT '';")
            print('telegram column added')

        con.commit()
        pass  # log
        
    except Exception as e:
        print(f"[INFO] e={e}")
        con.rollback()
        raise
    finally:
        cur.close()
        con.close()

@app.on_event("startup")
def startup():
    init_db()

# =========================
# ---
# =========================
class CheckReq(BaseModel):
    key: str
    hwid: str

@app.post("/api/check")
def check(req: CheckReq):
    """
    ???????????????? ???????????????? ?????? ??????????????????.
    ????????????:
    - ???????? ???????????? ????????????????????????, ???????? ???? revoked ?? ???? expired
    - HWID "??????????????????????????" ?????? ???????????? ???????????????? ????????????????, ???????? ?? ???????????????? HWID ????????????/temporary
    - ?????????? ???????????????? HWID ???????????? ?????????????????? (???????????? ???? ?????????????? ????????????)
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

        # ---
        if revoked:
            raise HTTPException(status_code=403, detail="revoked")
        if now() > expires_at:
            raise HTTPException(status_code=403, detail="expired")

        # ---
        incoming_hwid = (req.hwid or "").strip().upper()
        stored_hwid = (lic_hwid or "").strip().upper()

        # ---
        if not stored_hwid or stored_hwid in {"TEMP", "NONE", "NULL", "-"}:
            if incoming_hwid:
                cur.execute(
                    "UPDATE licenses SET hwid=%s WHERE key=%s",
                    (incoming_hwid, req.key)
                )
                stored_hwid = incoming_hwid
        else:
            # ---
            if incoming_hwid and incoming_hwid != stored_hwid:
                raise HTTPException(status_code=403, detail="hwid_mismatch")

        # ---
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
# ---
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
    pass  # log
    pass  # log
    
    con = db()
    cur = con.cursor()
    
    try:
        # ---
        pass  # log
        cur.execute("""
            SELECT key, max_devices, expires_at, revoked 
            FROM licenses 
            WHERE key = %s
        """, (req.license_key,))
        
        license = cur.fetchone()
        if not license:
            pass  # log
            raise HTTPException(status_code=404, detail="license_not_found")
        
        key, max_devices, expires_at, revoked = license
        print(f"[INFO] key={key} expires_at={expires_at} revoked={revoked} max_devices={max_devices}")
        
        if revoked:
            pass  # log
            raise HTTPException(status_code=403, detail="license_revoked")
        
        if now() > expires_at:
            pass  # log
            raise HTTPException(status_code=403, detail="license_expired")
        
        # ---
        pass  # log
        cur.execute("SELECT id FROM users WHERE email = %s", (req.email,))
        if cur.fetchone():
            pass  # log
            raise HTTPException(status_code=400, detail="email_already_registered")
        
        # ---
        pass  # log
        password_hash = hash_password(req.password)
        cur.execute("""
            INSERT INTO users (email, password_hash, license_key, telegram, balance, total_spent)
            VALUES (%s, %s, %s, %s, 0.00, 0.00)
            RETURNING id
        """, (req.email, password_hash, req.license_key, req.telegram))
        
        user_id = cur.fetchone()[0]
        print(f"[INFO] user_id={user_id}")
        
        # ---
        pass  # log
        client_ip = request.client.host if request.client else "0.0.0.0"
        cur.execute("""
            INSERT INTO user_devices (user_id, device_fingerprint, device_name, last_ip)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (user_id, req.device_fingerprint, req.device_name, client_ip))
        
        device_id = cur.fetchone()[0]
        print(f"[INFO] device_id={device_id}")
        
        # ---
        pass  # log
        session_token = generate_token()
        expires_at_session = now() + timedelta(days=30)
        
        cur.execute("""
            INSERT INTO user_sessions (user_id, session_token, device_id, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (user_id, session_token, device_id, expires_at_session))
        pass  # log
        
        # ---
        pass  # log
        confirm_token = generate_token()
        confirm_expires = now() + timedelta(hours=24)
        
        cur.execute("""
            INSERT INTO email_confirmations (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        """, (user_id, confirm_token, confirm_expires))
        pass  # log
        
        con.commit()
        pass  # log
        
        # ---
        pass  # log
        background_tasks.add_task(
            send_confirmation_email,
            req.email,
            confirm_token
        )
        pass  # log
        
        return {
            "success": True,
            "session_token": session_token,
            "user_id": user_id,
            "email": req.email,
            "need_confirmation": True
        }
        
    except HTTPException:
        pass  # log
        con.rollback()
        raise
    except Exception as e:
        pass  # log
        pass  # log
        import traceback
        traceback.print_exc()
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()
        pass  # log

# =========================
# ---
# =========================
class LoginReq(BaseModel):
    email: str
    password: str
    device_fingerprint: str
    device_name: str = "?????? ??????????????????"

@app.post("/api/auth/login")
def login(req: LoginReq, request: Request):
    pass  # log
    
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
            pass  # log
            raise HTTPException(status_code=401, detail="invalid_credentials")
        
        pass  # log
        
        if not verify_password(req.password, user['password_hash']):
            pass  # log
            raise HTTPException(status_code=401, detail="invalid_credentials")
        
        pass  # log
        
        if not user['email_confirmed']:
            pass  # log
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
                    "message": "?????????????????????? email"
                }
            )
        
        pass  # log
        cur.execute("""
            SELECT * FROM user_devices 
            WHERE user_id = %s AND device_fingerprint = %s
        """, (user['id'], req.device_fingerprint))
        
        device = cur.fetchone()
        client_ip = request.client.host if request.client else "0.0.0.0"
        
        if device:
            pass  # log
            device_id = device['id']
            cur.execute("""
                UPDATE user_devices 
                SET last_login = NOW(), last_ip = %s
                WHERE id = %s
            """, (client_ip, device_id))
        else:
            pass  # log
            cur.execute("""
                SELECT COUNT(*) FROM user_devices 
                WHERE user_id = %s AND is_active = TRUE
            """, (user['id'],))
            device_count = cur.fetchone()['count']
            
            print(f"Active devices: {device_count}, max: {user['max_devices']}")
            
            if device_count >= user['max_devices']:
                pass  # log
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
            
            pass  # log
            cur.execute("""
                INSERT INTO user_devices (user_id, device_fingerprint, device_name, last_ip)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (user['id'], req.device_fingerprint, req.device_name, client_ip))
            
            device_id = cur.fetchone()['id']
            print(f"[INFO] device_id={device_id}")
        
        pass  # log
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
        pass  # log
        
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
        pass  # log
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

# =========================
# ---
# =========================
class LoginWithKeyReq(BaseModel):
    email: str
    password: str
    license_key: str
    device_fingerprint: str
    device_name: str = "?????? ??????????????????"

@app.post("/api/auth/login_with_key")
def login_with_key(req: LoginWithKeyReq, background_tasks: BackgroundTasks, request: Request):
    """
    ???????? ?? ????????????:
    - ?????????????????? ????????????
    - ??????????????????/?????????????????????? ???????? ?? ???????????????????????? (1 ???????? = 1 ????????????????????????)
    - ???????????????????????? ???????????????????? ?? ?????????????? max_devices (???? licenses)
    - ???????? email ???? ??????????????????????: ?????????????? ?????????? ??????????????????????????, ???????????????????? ????????????, ???? ?????? ?????????? ???????????????????? session_token
    """
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    try:
        # ---
        cur.execute("SELECT * FROM users WHERE email=%s", (req.email,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="invalid_credentials")

        if not verify_password(req.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="invalid_credentials")

        # ---
        cur.execute("SELECT key, expires_at, revoked, max_devices FROM licenses WHERE key=%s", (req.license_key,))
        lic = cur.fetchone()
        if not lic:
            raise HTTPException(status_code=404, detail="license_not_found")
        if lic["revoked"]:
            raise HTTPException(status_code=403, detail="license_revoked")
        if now() > lic["expires_at"]:
            raise HTTPException(status_code=403, detail="license_expired")

        # ---
        current_key = (user.get("license_key") or "").strip()
        incoming_key = (req.license_key or "").strip()
        if current_key and current_key != incoming_key:
            raise HTTPException(status_code=403, detail="license_key_mismatch")

        if not current_key:
            # ---
            cur.execute("SELECT id FROM users WHERE license_key=%s AND id<>%s", (incoming_key, user["id"]))
            if cur.fetchone():
                raise HTTPException(status_code=403, detail="license_key_already_used")

            cur.execute("UPDATE users SET license_key=%s WHERE id=%s", (incoming_key, user["id"]))
            user["license_key"] = incoming_key

        # ---
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

        # ---
        session_token = generate_token()
        expires_at_session = now() + timedelta(days=30)

        cur.execute("""
            INSERT INTO user_sessions (user_id, session_token, device_id, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (user["id"], session_token, device_id, expires_at_session))
        cur.execute("UPDATE users SET last_login=NOW() WHERE id=%s", (user["id"],))

        # ---
        need_confirmation = not bool(user.get("email_confirmed"))
        if need_confirmation:
            confirm_token = generate_token()
            confirm_expires = now() + timedelta(hours=24)
            cur.execute("""
                INSERT INTO email_confirmations (user_id, token, expires_at)
                VALUES (%s, %s, %s)
            """, (user["id"], confirm_token, confirm_expires))
            # ---
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
# ---
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

        # ---
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
# ---
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
            # ---
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
                    <h2>??? ???????????? ??????????????????????????????</h2>
                    <p>????????????????, ?????? ?????? ???????????????????????? ?????? ??????????????.</p>
                </body>
                </html>
            """)
        
        user_id, expires_at = row
        
        if now() > expires_at:
            return HTMLResponse("""
                <html>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h2>??? ???????????? ??????????????</h2>
                    <p>?????????????????? ?????????? ???????????? ?? ??????????????????.</p>
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
                <h2>??? Email ??????????????????????!</h2>
                <p>???????????? ???? ???????????? ?????????? ?? ??????????????????.</p>
                <p>?????????????????? ?? ???????????????????? ?? ?????????????? "??????????".</p>
            </body>
            </html>
        """)
        
    except Exception as e:
        return HTMLResponse(f"""
            <html>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h2>??? ????????????</h2>
                <p>{str(e)}</p>
            </body>
            </html>
        """)
    finally:
        cur.close()
        con.close()

# =========================
# ---
# =========================
def send_confirmation_email(email: str, token: str):
    """???????????????? ?????????????????? ???????????? ?? ????????????????????????????"""
    confirm_url = f"https://license-check-server-xatc.onrender.com/api/auth/confirm?token={token}"
    
    # ---
    if not SENDGRID_API_KEY:
        print(f"[INFO] email={email} confirm_url={confirm_url}")
        return
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>?????????????????????????? email</title>
    </head>
    <body style="margin:0; padding:0; font-family: 'Segoe UI', Arial, sans-serif; background:#f5f7fa;">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px; margin:0 auto; background:white; border-radius:16px; margin-top:40px; box-shadow:0 4px 12px rgba(0,0,0,0.05);">
            <!-- ?????????? -->
            <tr>
                <td style="padding:40px 40px 20px 40px; text-align:center; background:linear-gradient(135deg, #3b82f6, #8b5cf6); border-radius:16px 16px 0 0;">
                    <h1 style="color:white; margin:0; font-size:28px; font-weight:600;">TG Parser Sender</h1>
                    <p style="color:rgba(255,255,255,0.9); margin:10px 0 0 0; font-size:16px;">???????????????????????????????? ?????????????? Telegram</p>
                </td>
            </tr>
            
            <!-- ???????????????? ?????????????? -->
            <tr>
                <td style="padding:40px;">
                    <h2 style="color:#1e293b; margin:0 0 20px 0; font-size:24px;">?????????????????????????? email</h2>
                    <p style="color:#475569; line-height:1.6; margin:0 0 30px 0; font-size:16px;">
                        ????????????????????????!<br><br>
                        ?????? ???????????????????? ?????????????????????? ?? <strong>TG Parser Sender</strong> ?????????????????????? ?????? email ??????????.
                    </p>
                    
                    <!-- ???????????? -->
                    <table cellpadding="0" cellspacing="0" style="margin:30px auto;">
                        <tr>
                            <td style="background:#4CAF50; border-radius:40px; padding:14px 40px;">
                                <a href="{confirm_url}" style="color:white; text-decoration:none; font-size:16px; font-weight:600; letter-spacing:0.5px;">??? ?????????????????????? EMAIL</a>
                            </td>
                        </tr>
                    </table>
                    
                    <!-- ???????????????????????????? ???????????? -->
                    <p style="color:#64748b; font-size:14px; margin:30px 0 0 0; text-align:center;">
                        ?????? ?????????????????? ???? ????????????:<br>
                        <a href="{confirm_url}" style="color:#3b82f6; word-break:break-all;">{confirm_url}</a>
                    </p>
                    
                    <!-- ???????? ???????????????? -->
                    <p style="color:#94a3b8; font-size:13px; margin:30px 0 0 0; text-align:center; border-top:1px solid #e2e8f0; padding-top:30px;">
                        ???????????? ?????????????????????????? 24 ????????.<br>
                        ???????? ???? ???? ????????????????????????????????, ???????????? ???????????????????????????? ?????? ????????????.
                    </p>
                </td>
            </tr>
            
            <!-- ???????????? -->
            <tr>
                <td style="padding:30px 40px; background:#f8fafc; border-radius:0 0 16px 16px;">
                    <table width="100%">
                        <tr>
                            <td style="text-align:center;">
                                <p style="color:#64748b; margin:0 0 10px 0; font-size:14px;">
                                    ?? ??????????????????, ?????????????? TG Parser Sender
                                </p>
                                <p style="color:#94a3b8; margin:0; font-size:13px;">
                                    ???? support@tgparsersender.me | ???? @Ben_bell97
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
        subject="?????????????????????????? email ?? TG Parser Sender",
        html_content=Content("text/html", html_content)
    )
    
    try:
        sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"[INFO] email={email}")
    except Exception as e:
        print(f"[INFO] e={e}")

def send_password_reset_email(email: str, token: str):
    """???????????????? ?????????????????? ???????????? ?????? ???????????? ????????????"""
    reset_url = f"https://license-check-server-xatc.onrender.com/reset-password?token={token}"
    
    if not SENDGRID_API_KEY:
        print(f"[INFO] email={email} reset_url={reset_url}")
        return
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>?????????? ????????????</title>
    </head>
    <body style="margin:0; padding:0; font-family: 'Segoe UI', Arial, sans-serif; background:#f5f7fa;">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px; margin:0 auto; background:white; border-radius:16px; margin-top:40px; box-shadow:0 4px 12px rgba(0,0,0,0.05);">
            <!-- ?????????? -->
            <tr>
                <td style="padding:40px 40px 20px 40px; text-align:center; background:linear-gradient(135deg, #ef4444, #f97316); border-radius:16px 16px 0 0;">
                    <h1 style="color:white; margin:0; font-size:28px; font-weight:600;">TG Parser Sender</h1>
                    <p style="color:rgba(255,255,255,0.9); margin:10px 0 0 0; font-size:16px;">???????????????????????????? ??????????????</p>
                </td>
            </tr>
            
            <!-- ???????????????? ?????????????? -->
            <tr>
                <td style="padding:40px;">
                    <h2 style="color:#1e293b; margin:0 0 20px 0; font-size:24px;">?????????? ????????????</h2>
                    <p style="color:#475569; line-height:1.6; margin:0 0 30px 0; font-size:16px;">
                        ???? ???????????????? ???????????? ???? ?????????? ???????????? ?????? ???????????? ????????????????.
                    </p>
                    
                    <!-- ???????????? -->
                    <table cellpadding="0" cellspacing="0" style="margin:30px auto;">
                        <tr>
                            <td style="background:#3b82f6; border-radius:40px; padding:14px 40px;">
                                <a href="{reset_url}" style="color:white; text-decoration:none; font-size:16px; font-weight:600; letter-spacing:0.5px;">???? ???????????????? ????????????</a>
                            </td>
                        </tr>
                    </table>
                    
                    <!-- ???????????????????????????? ???????????? -->
                    <p style="color:#64748b; font-size:14px; margin:30px 0 0 0; text-align:center;">
                        ?????? ?????????????????? ???? ????????????:<br>
                        <a href="{reset_url}" style="color:#3b82f6; word-break:break-all;">{reset_url}</a>
                    </p>
                    
                    <!-- ???????????????????????????? -->
                    <p style="color:#94a3b8; font-size:13px; margin:30px 0 0 0; text-align:center; border-top:1px solid #e2e8f0; padding-top:30px;">
                        ???????????? ?????????????????????????? 1 ??????.<br>
                        ???????? ???? ???? ?????????????????????? ?????????? ????????????, ???????????????????????????? ?????? ????????????.
                    </p>
                </td>
            </tr>
            
            <!-- ???????????? -->
            <tr>
                <td style="padding:30px 40px; background:#f8fafc; border-radius:0 0 16px 16px;">
                    <table width="100%">
                        <tr>
                            <td style="text-align:center;">
                                <p style="color:#64748b; margin:0 0 10px 0; font-size:14px;">
                                    ?? ??????????????????, ?????????????? TG Parser Sender
                                </p>
                                <p style="color:#94a3b8; margin:0; font-size:13px;">
                                    ???? support@tgparsersender.me | ???? @Ben_bell97
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
        subject="?????????? ???????????? ?? TG Parser Sender",
        html_content=Content("text/html", html_content)
    )
    
    try:
        sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"[INFO] email={email}")
    except Exception as e:
        print(f"[INFO] e={e}")

# =========================
# ---
# =========================
@app.get("/admin/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": ""})

@app.post("/admin/login")
def login(request: Request, token: str = Form(...)):
    if token != ADMIN_TOKEN:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "???????????????? ??????????"}
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
        print(f"[INFO] e={e}")
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
# ---
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
            f"???????????? ????????????????????: {data.note}" if data.note else "???????????? ????????????????????",
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
# ---
# =========================




# --- delete user ---
class DeleteUserReq(BaseModel):
    user_id: int

@app.post("/admin/api/delete-user")
def admin_delete_user(request: Request, data: DeleteUserReq):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        # Manually nullify FK in tables without CASCADE to avoid constraint errors
        cur.execute("UPDATE transactions SET user_id = NULL WHERE user_id = %s", (data.user_id,))
        cur.execute("UPDATE usage_logs SET user_id = NULL WHERE user_id = %s", (data.user_id,))
        cur.execute("UPDATE payment_requests SET user_id = NULL WHERE user_id = %s", (data.user_id,))
        # DELETE user - cascades to user_devices, user_sessions, email_confirmations, password_resets
        cur.execute("DELETE FROM users WHERE id = %s RETURNING email", (data.user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        con.commit()
        return {"success": True, "deleted_email": row[0]}
    except HTTPException:
        con.rollback()
        raise
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()

# =========================
# USER DETAIL PAGE
# =========================
@app.get("/admin/users/{user_id}", response_class=HTMLResponse)
def admin_user_detail(user_id: int, request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("""
            SELECT u.*,
                   l.expires_at AS license_expires,
                   l.revoked    AS license_revoked,
                   l.plan       AS license_plan,
                   l.max_devices
            FROM users u
            LEFT JOIN licenses l ON u.license_key = l.key
            WHERE u.id = %s
        """, (user_id,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        cur.execute("""
            SELECT * FROM user_devices WHERE user_id = %s ORDER BY last_login DESC
        """, (user_id,))
        devices = cur.fetchall()

        cur.execute("""
            SELECT * FROM transactions WHERE user_id = %s ORDER BY created_at DESC LIMIT 50
        """, (user_id,))
        transactions = cur.fetchall()
    finally:
        cur.close()
        con.close()

    return templates.TemplateResponse("admin_user_detail.html", {
        "request": request,
        "user": user,
        "devices": devices,
        "transactions": transactions,
        "now": now(),
        "active_tab": "users",
    })


# --- update email ---
class UpdateEmailReq(BaseModel):
    user_id: int
    email: str

@app.post("/admin/api/update-email")
def admin_update_email(request: Request, data: UpdateEmailReq):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute("UPDATE users SET email = %s WHERE id = %s", (data.email, data.user_id))
        con.commit()
        return {"success": True}
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()


# --- update telegram ---
class UpdateTelegramReq(BaseModel):
    user_id: int
    telegram: str

@app.post("/admin/api/update-telegram")
def admin_update_telegram(request: Request, data: UpdateTelegramReq):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute("UPDATE users SET telegram = %s WHERE id = %s", (data.telegram, data.user_id))
        con.commit()
        return {"success": True}
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()


# --- confirm email ---
class ConfirmEmailReq(BaseModel):
    user_id: int

@app.post("/admin/api/confirm-email")
def admin_confirm_email(request: Request, data: ConfirmEmailReq):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute("""
            UPDATE users SET email_confirmed = TRUE, email_confirmed_at = %s WHERE id = %s
        """, (now(), data.user_id))
        con.commit()
        return {"success": True}
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()


# --- extend license ---
class ExtendLicenseReq(BaseModel):
    user_id: int
    days: int

@app.post("/admin/api/extend-license")
def admin_extend_license(request: Request, data: ExtendLicenseReq):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute("SELECT license_key FROM users WHERE id = %s", (data.user_id,))
        row = cur.fetchone()
        if not row or not row[0]:
            raise HTTPException(status_code=404, detail="License not found")
        key = row[0]
        cur.execute("""
            UPDATE licenses
            SET expires_at = GREATEST(expires_at, NOW()) + INTERVAL '%s days'
            WHERE key = %s
        """, (data.days, key))
        con.commit()
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()


# --- revoke/unrevoke license ---
class RevokeLicenseReq(BaseModel):
    user_id: int
    revoked: bool

@app.post("/admin/api/revoke-license")
def admin_revoke_license(request: Request, data: RevokeLicenseReq):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute("SELECT license_key FROM users WHERE id = %s", (data.user_id,))
        row = cur.fetchone()
        if not row or not row[0]:
            raise HTTPException(status_code=404, detail="License not found")
        key = row[0]
        cur.execute("UPDATE licenses SET revoked = %s WHERE key = %s", (data.revoked, key))
        con.commit()
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()


# --- add transaction (generic) ---
class AddTransactionReq(BaseModel):
    user_id: int
    amount: float
    type: str
    description: str = ""

@app.post("/admin/api/add-transaction")
def admin_add_transaction(request: Request, data: AddTransactionReq):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute("SELECT license_key FROM users WHERE id = %s", (data.user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        key = row[0]
        cur.execute("""
            UPDATE users SET balance = balance + %s WHERE id = %s RETURNING balance
        """, (data.amount, data.user_id))
        new_balance = float(cur.fetchone()[0])
        cur.execute("""
            INSERT INTO transactions (user_id, license_key, amount, type, description)
            VALUES (%s, %s, %s, %s, %s)
        """, (data.user_id, key, data.amount, data.type, data.description or data.type))
        con.commit()
        return {"success": True, "new_balance": new_balance}
    except HTTPException:
        raise
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()

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
# ---
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
            "now": now(),
            "active_tab": "users"
        }
    )

@app.get("/admin/users/{user_id}", response_class=HTMLResponse)
def admin_user_detail(user_id: int, request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    try:
        # User + license info
        cur.execute("""
            SELECT u.*, l.plan, l.expires_at as license_expires, l.revoked as license_revoked,
                   l.max_devices, l.check_count
            FROM users u
            LEFT JOIN licenses l ON u.license_key = l.key
            WHERE u.id = %s
        """, (user_id,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Devices
        cur.execute("""
            SELECT * FROM user_devices WHERE user_id = %s ORDER BY last_login DESC
        """, (user_id,))
        devices = cur.fetchall()

        # Transactions
        cur.execute("""
            SELECT * FROM transactions WHERE user_id = %s ORDER BY created_at DESC LIMIT 100
        """, (user_id,))
        transactions = cur.fetchall()

        # Days left on license
        days = None
        if user.get("license_expires"):
            delta = user["license_expires"] - now()
            days = max(0, delta.days)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

    return templates.TemplateResponse(
        "admin_user_detail.html",
        {
            "request": request,
            "user": user,
            "devices": devices,
            "transactions": transactions,
            "days": days,
            "now": now(),
            "active_tab": "users"
        }
    )

# =========================
# ---
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
            "now": now(),
            "active_tab": "devices"
        }
    )

# =========================
# ---
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
            "now": now(),
            "active_tab": "transactions"
        }
    )

# =========================
# ---
# =========================
@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    
    return templates.TemplateResponse(
        "admin_settings.html",
        {
            "request": request,
            "now": now(),
            "active_tab": "settings"
        }
    )

# =========================
# ---
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
# ---
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
              AND s.expires_at > NOW()
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
    session_token: str
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
        # Require active session to use AI endpoint (prevents free OpenAI usage without balance)
        con = db()
        cur = con.cursor()
        try:
            cur.execute(
                "SELECT 1 FROM user_sessions WHERE session_token = %s AND expires_at > NOW()",
                (req.session_token,)
            )
            if not cur.fetchone():
                raise HTTPException(status_code=401, detail="invalid_session")
        finally:
            try:
                cur.close()
                con.close()
            except Exception:
                pass

        client = get_openai_client()
        items = [{"id": str(it.id), "text": (it.text or "")[:1200]} for it in req.items]

        system_prompt = (
            "You analyze Telegram user profiles to find matches for a search query.\n"
            "I will give you a prompt (who we are looking for) and a list of user data objects.\n"
            "Return ONLY valid JSON, no markdown, no explanation, strictly in this format:\n"
            '{ "results": [ {"id":"...","score":0-100,"pass":true/false,"reason":"short reason in Russian 5-12 words","flags":["bot_like|spam_like|toxic|low_quality"...]}, ... ] }\n'
            "Rule: pass=true only if score >= min_score AND no bot_like/spam_like/toxic flags.\n"
            "Reason field must be in Russian."
        )

        payload = {
            "prompt": req.prompt,
            "min_score": req.min_score,
            "items": items
        }

        resp = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
        )

        out_text = resp.choices[0].message.content or ""
        data = _extract_json(out_text)

        if not isinstance(data, dict) or "results" not in data:
            raise ValueError(f"bad_ai_response: {out_text[:200]}")

        return data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI error: {type(e).__name__}: {e}")

# =========================
# ---
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

    return RedirectResponse("/admin/licenses", status_code=303)

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

    return RedirectResponse("/admin/licenses", status_code=303)

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

    return RedirectResponse("/admin/licenses", status_code=303)

@app.post("/admin/delete")
def delete(request: Request, key: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    con = db()
    cur = con.cursor()
    try:
        # Delete dependent rows first to avoid FK violations
        cur.execute("DELETE FROM transactions WHERE license_key=%s", (key,))
        cur.execute("DELETE FROM usage_logs WHERE license_key=%s", (key,))
        cur.execute("DELETE FROM payment_requests WHERE license_key=%s", (key,))
        cur.execute("UPDATE users SET license_key=NULL WHERE license_key=%s", (key,))
        cur.execute("DELETE FROM licenses WHERE key=%s", (key,))
        con.commit()
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

    return RedirectResponse("/admin/licenses", status_code=303)

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
# ADMIN USER DETAIL APIs
# =========================

class UpdateEmailRequest(BaseModel):
    user_id: int
    email: str

@app.post("/admin/api/update-email")
def admin_update_email(request: Request, data: UpdateEmailRequest):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute("UPDATE users SET email=%s WHERE id=%s", (data.email, data.user_id))
        con.commit()
        return {"success": True}
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()

class UpdateTelegramRequest(BaseModel):
    user_id: int
    telegram: str

@app.post("/admin/api/update-telegram")
def admin_update_telegram(request: Request, data: UpdateTelegramRequest):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute("UPDATE users SET telegram=%s WHERE id=%s", (data.telegram, data.user_id))
        con.commit()
        return {"success": True}
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()

class ConfirmEmailRequest(BaseModel):
    user_id: int

@app.post("/admin/api/confirm-email")
def admin_confirm_email(request: Request, data: ConfirmEmailRequest):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute(
            "UPDATE users SET email_confirmed=TRUE, email_confirmed_at=%s WHERE id=%s",
            (now(), data.user_id)
        )
        con.commit()
        return {"success": True}
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()

class ExtendLicenseRequest(BaseModel):
    user_id: int
    days: int

@app.post("/admin/api/extend-license")
def admin_extend_license(request: Request, data: ExtendLicenseRequest):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute("SELECT license_key FROM users WHERE id=%s", (data.user_id,))
        row = cur.fetchone()
        if not row or not row[0]:
            raise HTTPException(status_code=404, detail="No license found for user")
        key = row[0]
        cur.execute(
            "UPDATE licenses SET expires_at = expires_at + (%s || ' days')::interval, revoked=FALSE, updated_at=NOW() WHERE key=%s",
            (data.days, key)
        )
        con.commit()
        return {"success": True, "key": key}
    except HTTPException:
        raise
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()

class RevokeLicenseRequest(BaseModel):
    user_id: int
    revoked: bool

@app.post("/admin/api/revoke-license")
def admin_revoke_license(request: Request, data: RevokeLicenseRequest):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute("SELECT license_key FROM users WHERE id=%s", (data.user_id,))
        row = cur.fetchone()
        if not row or not row[0]:
            raise HTTPException(status_code=404, detail="No license found for user")
        key = row[0]
        cur.execute("UPDATE licenses SET revoked=%s, updated_at=NOW() WHERE key=%s", (data.revoked, key))
        con.commit()
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()

class AddTransactionRequest(BaseModel):
    user_id: int
    amount: float
    type: str = "deposit"
    description: str = ""

@app.post("/admin/api/add-transaction")
def admin_add_transaction(request: Request, data: AddTransactionRequest):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Unauthorized")
    con = db()
    cur = con.cursor()
    try:
        cur.execute("SELECT license_key FROM users WHERE id=%s", (data.user_id,))
        row = cur.fetchone()
        license_key = row[0] if row else None

        cur.execute(
            "UPDATE users SET balance = balance + %s WHERE id=%s RETURNING balance",
            (data.amount, data.user_id)
        )
        new_balance = cur.fetchone()[0]

        cur.execute(
            "INSERT INTO transactions (user_id, license_key, amount, type, description, metadata) VALUES (%s,%s,%s,%s,%s,%s)",
            (data.user_id, license_key, data.amount, data.type, data.description, json.dumps({"admin": True}))
        )
        con.commit()
        return {"success": True, "new_balance": float(new_balance)}
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); con.close()

# =========================
# ---
# =========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
