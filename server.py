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
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email

from openai import OpenAI

app = FastAPI()

# =========================
# ---
# =========================


def _send_mail(message: Mail):
    if not SENDGRID_API_KEY:
        raise RuntimeError("SENDGRID_API_KEY is missing")

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        resp = sg.send(message)
        # Minimal log for Render
        print(f"[mail] status={resp.status_code}")
        return resp
    except Exception as e:
        print(f"[mail] error: {e}")
        raise


def _email_html_base(title: str, preheader: str, heading: str, body_html: str, button_text: str, button_url: str) -> str:
    # Bulletproof email HTML (better contrast / Gmail safe link colors / Outlook-friendly button)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title}</title>
  <style>
    body,table,td,a{{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;}}
    table,td{{mso-table-lspace:0pt;mso-table-rspace:0pt;}}
    img{{-ms-interpolation-mode:bicubic;border:0;outline:none;text-decoration:none;}}
    table{{border-collapse:collapse !important;}}
    body{{margin:0;padding:0;width:100% !important;background:#f4f6fb;font-family:Arial,Helvetica,sans-serif;}}
    .container{{max-width:600px;margin:0 auto;}}
    .card{{background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 8px 24px rgba(15,23,42,0.08);}}
    .header{{background:linear-gradient(135deg,#4f46e5 0%,#7c3aed 100%);padding:28px 28px 22px 28px;color:#ffffff;}}
    .brand{{font-size:20px;font-weight:700;letter-spacing:-0.2px;}}
    .subbrand{{opacity:.9;font-size:13px;margin-top:6px;}}
    .content{{padding:28px; color:#0f172a;}}
    h1{{margin:0 0 10px 0;font-size:22px;line-height:1.25;}}
    p{{margin:0 0 14px 0;font-size:14px;line-height:1.6;color:#334155;}}
    .small{{font-size:12px;color:#64748b;}}
    .footer{{padding:18px 28px;color:#94a3b8;font-size:12px;text-align:center;}}
    .mono{{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;}}
    .preheader{{display:none !important;visibility:hidden;opacity:0;color:transparent;height:0;width:0;}}
    /* Force safe link color inside buttons and elsewhere */
    a{{color:#2563eb;}}
    .btn-link{{color:#ffffff !important;text-decoration:none !important;}}
  </style>
</head>
<body>
  <div class="preheader">{preheader}</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
    <tr>
      <td style="padding:28px 12px;">
        <div class="container">
          <div class="card">
            <div class="header">
              <div class="brand">TG Leads AI</div>
              <div class="subbrand">Telegram leads & outreach platform</div>
            </div>
            <div class="content">
              <h1>{heading}</h1>
              {body_html}

              <!-- Bulletproof button -->
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:10px 0 10px 0;">
                <tr>
                  <td bgcolor="#4f46e5" style="border-radius:12px;">
                    <a href="{button_url}" target="_blank" rel="noopener"
                       class="btn-link"
                       style="display:inline-block;padding:12px 18px;font-weight:700;font-size:14px;line-height:14px;border-radius:12px;background:#4f46e5;color:#ffffff !important;text-decoration:none !important;">
                      {button_text}
                    </a>
                  </td>
                </tr>
              </table>

              <p class="small">If the button doesn’t work, open this link:</p>
              <p class="small mono"><a href="{button_url}" target="_blank" rel="noopener" style="color:#2563eb;">{button_url}</a></p>
              <p class="small">If you didn’t request this, you can safely ignore this email.</p>
            </div>
            <div class="footer">
              © {datetime.utcnow().year} TG Leads AI
            </div>
          </div>
        </div>
      </td>
    </tr>
  </table>
</body>
</html>"""



def send_password_reset_email(email: str, token: str):
    reset_url = f"{BASE_URL}/reset-password?token={token}"

    html = _email_html_base(
        title="Reset your password — TG Leads AI",
        preheader="Your password reset link for TG Leads AI",
        heading="Reset your password",
        body_html="""
          <p>We received a request to reset your password. Click the button below to set a new password.</p>
          <p class="small">If you didn’t request this, just ignore this email — your password won’t change.</p>
        """,
        button_text="🔒 Reset password",
        button_url=reset_url
    )

    message = Mail(
        from_email=Email(FROM_EMAIL, FROM_NAME),
        to_emails=email,
        subject="Reset your password — TG Leads AI",
        html_content=html,
        plain_text_content=f"Reset password link: {reset_url}"
    )
    _send_mail(message)




def send_confirmation_email(email: str, token: str):
    confirm_url = f"{BASE_URL}/confirm-email?token={token}"

    html = _email_html_base(
        title="Confirm your email — TG Leads AI",
        preheader="Confirm your email address for TG Leads AI",
        heading="Confirm your email",
        body_html="""
          <p>Thanks for signing up for <b>TG Leads AI</b>!</p>
          <p>Please confirm your email address by clicking the button below.</p>
          <p class="small">If you didn’t create an account, you can safely ignore this email.</p>
        """,
        button_text="✅ Confirm email",
        button_url=confirm_url
    )

    message = Mail(
        from_email=Email(FROM_EMAIL, FROM_NAME),
        to_emails=email,
        subject="Confirm your email — TG Leads AI",
        html_content=html,
        plain_text_content=f"Confirm email link: {confirm_url}"
    )
    _send_mail(message)

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
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "").strip()
BASE_URL = os.environ.get("BASE_URL", "https://license-check-server-xatc.onrender.com").rstrip("/")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@tgparsersender.me").strip()
FROM_NAME = os.environ.get("FROM_NAME", "TG Parser Sender").strip() or "TG Parser Sender"

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

# GPT-4.1-mini pricing (USD per token) x2 markup
_GPT_INPUT_PRICE  = 0.40 / 1_000_000 * 2   # $0.0000008 per input token
_GPT_OUTPUT_PRICE = 1.60 / 1_000_000 * 2   # $0.0000032 per output token

def _calc_ai_cost(prompt_tokens: int, completion_tokens: int) -> float:
    cost = prompt_tokens * _GPT_INPUT_PRICE + completion_tokens * _GPT_OUTPUT_PRICE
    return max(round(cost, 8), 0.00004)  # minimum $0.00004 per call

def _charge_ai_transaction(session_token: str, cost: float, description: str, metadata: dict) -> dict:
    """Deduct cost from balance and write to transactions. Returns success/error dict."""
    con = db()
    cur = con.cursor()
    try:
        cur.execute("BEGIN")
        cur.execute("""
            SELECT u.id, u.balance, u.license_key
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_token = %s AND s.expires_at > NOW()
            FOR UPDATE
        """, (session_token,))
        user = cur.fetchone()
        if not user:
            cur.execute("ROLLBACK")
            return {"success": False, "error": "invalid_session"}
        user_id, balance, license_key = user
        if float(balance) < cost:
            cur.execute("ROLLBACK")
            return {"success": False, "error": "insufficient_funds"}
        cur.execute("""
            UPDATE users SET balance = balance - %s, total_spent = COALESCE(total_spent,0) + %s
            WHERE id = %s RETURNING balance
        """, (cost, cost, user_id))
        new_balance = float(cur.fetchone()[0])
        cur.execute("""
            INSERT INTO transactions (user_id, license_key, amount, type, description, metadata)
            VALUES (%s, %s, %s, 'charge', %s, %s)
        """, (user_id, license_key, -cost, description, json.dumps(metadata)))
        cur.execute("COMMIT")
        return {"success": True, "charged": cost, "new_balance": new_balance}
    except Exception as e:
        try: cur.execute("ROLLBACK")
        except Exception: pass
        return {"success": False, "error": str(e)}
    finally:
        try: cur.close(); con.close()
        except Exception: pass

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
            total_spent DECIMAL(14,8) DEFAULT 0.00000000
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
            amount DECIMAL(14,8) NOT NULL,
            type TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            metadata JSONB DEFAULT '{}'
        );
        """)
        pass  # log

        # Migrate existing columns to higher precision (idempotent)
        for _col_mig in [
            "ALTER TABLE transactions ALTER COLUMN amount TYPE DECIMAL(14,8) USING amount::DECIMAL(14,8)",
            "ALTER TABLE users ALTER COLUMN total_spent TYPE DECIMAL(14,8) USING total_spent::DECIMAL(14,8)",
            "ALTER TABLE users ALTER COLUMN balance TYPE DECIMAL(14,8) USING balance::DECIMAL(14,8)",
        ]:
            try:
                cur.execute(_col_mig)
            except Exception:
                pass  # already correct type or table doesn't exist yet

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
            amount DECIMAL(14,8) NOT NULL,
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


class ChangePasswordReq(BaseModel):
    session_token: str
    old_password: str
    new_password: str

@app.post("/api/auth/change-password")
def change_password(req: ChangePasswordReq):
    # Validate
    if not req.new_password or len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="weak_password")

    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    try:
        # Load user by session
        cur.execute("""
            SELECT u.id, u.password_hash
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_token = %s
        """, (req.session_token,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="invalid_session")

        if not verify_password(req.old_password, user["password_hash"] or ""):
            raise HTTPException(status_code=400, detail="wrong_password")

        new_hash = hash_password(req.new_password)

        cur.execute("""
            UPDATE users
            SET password_hash = %s
            WHERE id = %s
        """, (new_hash, user["id"]))

        # Optional: invalidate all password reset tokens for this user (safety)
        try:
            cur.execute("UPDATE password_resets SET used = TRUE WHERE user_id = %s AND used = FALSE", (user["id"],))
        except Exception:
            pass

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

@app.get("/api/auth/confirm", response_class=HTMLResponse)
def confirm_email(request: Request, token: str):
    con = db()
    cur = con.cursor()

    status = "error"
    message = "Something went wrong. Please try again later."

    try:
        cur.execute("""
            SELECT user_id, expires_at
            FROM email_confirmations
            WHERE token = %s AND confirmed_at IS NULL
        """, (token,))

        row = cur.fetchone()
        if not row:
            status = "invalid"
            message = "This confirmation link is invalid or has already been used."
            return templates.TemplateResponse("confirm_email.html", {"request": request, "status": status, "message": message})

        user_id, expires_at = row

        if now() > expires_at:
            status = "expired"
            message = "This confirmation link has expired. Please request a new confirmation email."
            return templates.TemplateResponse("confirm_email.html", {"request": request, "status": status, "message": message})

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

        status = "ok"
        message = "Email confirmed! You can now return to the app and sign in."

        return templates.TemplateResponse("confirm_email.html", {"request": request, "status": status, "message": message})

    except Exception as e:
        # Keep user-facing message generic, but include a short detail for debugging if needed
        status = "error"
        message = "Confirmation failed. Please try again later."
        return templates.TemplateResponse("confirm_email.html", {"request": request, "status": status, "message": message})

    finally:
        try:
            cur.close()
            con.close()
        except Exception:
            pass




@app.get("/confirm-email", response_class=HTMLResponse)
def confirm_email_alias(request: Request, token: str):
    # Friendly public URL for email confirmation
    return confirm_email(request=request, token=token)


@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request, "sent": False, "error": ""})

@app.post("/forgot-password", response_class=HTMLResponse)
def forgot_password_submit(request: Request, email: str = Form(...), background_tasks: BackgroundTasks = None):
    # ВАЖНО: всегда отвечаем одинаково (не раскрываем, зарегистрирован ли email)
    email_norm = (email or "").strip().lower()
    if not email_norm:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "sent": False, "error": "Введите email."})

    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT id, email FROM users WHERE email=%s", (email_norm,))
        u = cur.fetchone()
        if u:
            token = generate_token()
            expires_at = now() + timedelta(hours=24)
            cur.execute(
                "INSERT INTO password_resets (user_id, token, expires_at) VALUES (%s,%s,%s)",
                (u["id"], token, expires_at)
            )
            con.commit()

            if background_tasks is not None:
                background_tasks.add_task(send_password_reset_email, u["email"], token)
            else:
                send_password_reset_email(u["email"], token)
    except Exception:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "sent": False, "error": "Не удалось отправить письмо. Попробуйте позже."})
    finally:
        cur.close()
        con.close()

    return templates.TemplateResponse("forgot_password.html", {"request": request, "sent": True, "error": ""})

@app.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, token: str):
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token, "error": ""})

class ResetPasswordPublicReq(BaseModel):
    token: str
    new_password: str

@app.post("/api/auth/reset-password")
def reset_password_public(data: ResetPasswordPublicReq):
    token = (data.token or "").strip()
    new_password = (data.new_password or "").strip()
    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="password_too_short")

    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            "SELECT user_id, expires_at FROM password_resets WHERE token=%s AND used = FALSE",
            (token,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="invalid_or_used_token")
        if now() > row["expires_at"]:
            raise HTTPException(status_code=400, detail="token_expired")

        user_id = row["user_id"]
        cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (hash_password(new_password), user_id))
        cur.execute("UPDATE password_resets SET used=TRUE WHERE token=%s", (token,))
        cur.execute("DELETE FROM user_sessions WHERE user_id=%s", (user_id,))
        con.commit()
        return {"success": True}
    finally:
        cur.close()
        con.close()

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
            f"💳 Пополнение баланса: {data.note}" if data.note else "💳 Пополнение баланса (администратор)",
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

        # Transactions (deposits + AI charges)
        cur.execute("""
            SELECT * FROM transactions WHERE user_id = %s ORDER BY created_at DESC LIMIT 200
        """, (user_id,))
        transactions = cur.fetchall()

        # AI usage stats from usage_logs
        cur.execute("""
            SELECT
                COUNT(*) as total_ops,
                COALESCE(SUM(cost), 0) as total_ai_cost
            FROM usage_logs WHERE user_id = %s
        """, (user_id,))
        ai_stats_row = cur.fetchone()
        ai_stats = {
            "total_ops": int(ai_stats_row["total_ops"]) if ai_stats_row else 0,
            "total_ai_cost": float(ai_stats_row["total_ai_cost"]) if ai_stats_row else 0.0,
        }

        # AI spend from transactions (type=charge)
        cur.execute("""
            SELECT COALESCE(SUM(ABS(amount)), 0) as total_charged
            FROM transactions WHERE user_id = %s AND type = 'charge'
        """, (user_id,))
        ai_charged_row = cur.fetchone()
        total_ai_charged = float(ai_charged_row["total_charged"]) if ai_charged_row else 0.0

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
            "ai_stats": ai_stats,
            "total_ai_charged": total_ai_charged,
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
# BALANCE TRANSACTIONS API
# =========================
class TransactionsReq(BaseModel):
    session_token: str
    limit: int = 50

@app.post("/api/balance/transactions")
def get_balance_transactions(req: TransactionsReq) -> Dict[str, Any]:
    """Return transaction history (deposits + AI charges) for the authenticated user."""
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("""
            SELECT u.id FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_token = %s AND s.expires_at > NOW()
        """, (req.session_token,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="invalid_session")
        user_id = row["id"]
        limit = max(1, min(int(req.limit), 200))
        cur.execute("""
            SELECT id, amount, type, description, metadata, created_at
            FROM transactions
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s
        """, (user_id, limit))
        rows = cur.fetchall()
        result = []
        for r in rows:
            meta = r["metadata"] or {}
            if isinstance(meta, str):
                try: meta = json.loads(meta)
                except Exception: meta = {}
            result.append({
                "id": r["id"],
                "amount": float(r["amount"]),
                "type": r["type"],
                "description": r["description"] or "",
                "metadata": meta,
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            })
        return {"transactions": result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try: cur.close(); con.close()
        except Exception: pass

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

        # ── Billing: charge based on actual token usage ──
        usage = resp.usage
        prompt_tokens     = int(usage.prompt_tokens)     if usage else 300
        completion_tokens = int(usage.completion_tokens) if usage else 100
        cost = _calc_ai_cost(prompt_tokens, completion_tokens)
        n_items = len(items)
        description = f"🤖 TG Leads AI анализ | {n_items} лид(ов) | {prompt_tokens}вх+{completion_tokens}вых ток."
        _charge_ai_transaction(
            req.session_token, cost, description,
            {
                "type": "ai_score",
                "model": "gpt-4.1-mini",
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "items_count": n_items,
            }
        )

        return data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI error: {type(e).__name__}: {e}")

# =========================
# AI CHAT — conversational AI for TG Leads full-AI mode
# =========================
class AIChatMessage(BaseModel):
    role: str   # "user" | "assistant"
    text: str

class AIChatReq(BaseModel):
    session_token: str
    goal: str = ""
    system_context: str = ""
    history: List[AIChatMessage] = []
    message: str
    ai_score_threshold: int = 60
    username: str = ""       # TG username for transaction description
    project_name: str = ""   # project name for context

@app.post("/api/ai/chat")
def ai_chat(req: AIChatReq) -> Dict[str, Any]:
    """
    Conversational AI endpoint for TG Leads full-AI mode.
    Takes conversation history + new message, returns AI reply + intent/score.
    Response: {"reply": str, "intent": "hot|cold|neutral", "score": 0-100,
               "goal_achieved": bool}
    """
    try:
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

        # Build system prompt
        system_parts = [
            "Ты профессиональный менеджер по продажам в Telegram.",
            f"Цель: {req.goal}" if req.goal else "Цель: продать продукт или услугу.",
        ]
        if req.system_context:
            system_parts.append(f"Контекст: {req.system_context}")
        system_parts += [
            "",
            "Правила:",
            "1. Веди живой, естественный диалог на русском языке.",
            "2. Отвечай кратко и по делу — не пиши длинных монологов.",
            "3. Выявляй потребности и двигай лида к цели.",
            "4. Когда цель достигнута (договорились о сделке/встрече/демо/покупке) — установи goal_achieved=true и intent=hot.",
            "5. Если лид явно заинтересован но цель ещё не достигнута — intent=hot, goal_achieved=false.",
            "6. Если лид явно отказывается и не идёт на контакт — intent=cold, score < 30.",
            "7. Если диалог продолжается — intent=neutral.",
            "8. Ты ОБЯЗАН в итоге принять решение: не оставляй лида в подвешенном состоянии.",
            "",
            "ВАЖНО: Отвечай ТОЛЬКО валидным JSON (без markdown-блоков), строго в формате:",
            '{"reply": "<текст ответа лиду>", "intent": "hot|cold|neutral", '
            '"score": <0-100>, "goal_achieved": <true|false>}',
            "intent hot = лид очень заинтересован / готов к сделке",
            "intent cold = лид отказывается, не заинтересован",
            "intent neutral = диалог продолжается",
            "goal_achieved = true только когда цель ПОЛНОСТЬЮ достигнута (договорились конкретно)",
            "score = 0-100, где 100 = максимальный интерес",
        ]
        system_prompt = "\n".join(system_parts)

        # Build messages list: history + new message
        messages = [{"role": "system", "content": system_prompt}]
        for h in (req.history or []):
            role = "user" if h.role == "user" else "assistant"
            messages.append({"role": role, "content": (h.text or "")[:1000]})
        messages.append({"role": "user", "content": (req.message or "")[:1000]})

        resp = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=messages,
            response_format={"type": "json_object"},
            temperature=0.7,
            max_tokens=500,
        )

        out_text = resp.choices[0].message.content or ""
        try:
            data = _extract_json(out_text)
        except Exception:
            data = {}

        # ── Billing: charge based on actual token usage ──
        usage = resp.usage
        prompt_tokens     = int(usage.prompt_tokens)     if usage else 200
        completion_tokens = int(usage.completion_tokens) if usage else 80
        cost = _calc_ai_cost(prompt_tokens, completion_tokens)

        uname = (req.username or "").strip().lstrip("@")
        proj  = (req.project_name or "").strip()
        desc_parts = ["🤖 TG Leads AI чат"]
        if uname:
            desc_parts.append(f"@{uname}")
        if proj:
            desc_parts.append(f"[{proj}]")
        desc_parts.append(f"{prompt_tokens}вх+{completion_tokens}вых ток.")
        description = " | ".join(desc_parts)

        charge_result = _charge_ai_transaction(
            req.session_token, cost, description,
            {
                "type": "ai_chat",
                "model": "gpt-4.1-mini",
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "username": uname,
                "project": proj,
            }
        )
        charged = charge_result.get("charged", 0.0) if charge_result.get("success") else 0.0

        return {
            "reply": str(data.get("reply") or ""),
            "intent": str(data.get("intent") or "neutral").lower(),
            "score": int(data.get("score") or 50),
            "goal_achieved": bool(data.get("goal_achieved", False)),
            "charged": charged,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI chat error: {type(e).__name__}: {e}")

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
