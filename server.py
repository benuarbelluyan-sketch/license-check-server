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

from fastapi import FastAPI, HTTPException, Request, Form, BackgroundTasks
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

from openai import OpenAI

app = FastAPI()

# =========================
# ГЛОБАЛЬНЫЙ ОБРАБОТЧИК
# =========================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": type(exc).__name__, "message": str(exc)}
    )

# =========================
# НАСТРОЙКИ
# =========================
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
ADMIN_PANEL_SECRET = os.environ.get("ADMIN_PANEL_SECRET", "change-me")

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
# СЕССИИ
# =========================
app.add_middleware(
    SessionMiddleware,
    secret_key=ADMIN_PANEL_SECRET,
    https_only=True,
    same_site="lax",
)

templates = Jinja2Templates(directory="templates")

# =========================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
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
# БАЗА ДАННЫХ
# =========================
def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)

# =========================
# API ПРОВЕРКИ ЛИЦЕНЗИИ
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
# API РЕГИСТРАЦИИ И ВХОДА
# =========================
class RegisterReq(BaseModel):
    email: str
    password: str
    license_key: str
    device_fingerprint: str
    device_name: str = "Мой компьютер"

@app.post("/api/auth/register")
def register(req: RegisterReq, background_tasks: BackgroundTasks, request: Request):
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("""
            SELECT key, max_devices, expires_at, revoked 
            FROM licenses 
            WHERE key = %s
        """, (req.license_key,))
        
        license = cur.fetchone()
        if not license:
            raise HTTPException(status_code=404, detail="license_not_found")
        
        key, max_devices, expires_at, revoked = license
        
        if revoked:
            raise HTTPException(status_code=403, detail="license_revoked")
        
        if now() > expires_at:
            raise HTTPException(status_code=403, detail="license_expired")
        
        cur.execute("SELECT id FROM users WHERE email = %s", (req.email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="email_already_registered")
        
        password_hash = hash_password(req.password)
        cur.execute("""
            INSERT INTO users (email, password_hash, license_key)
            VALUES (%s, %s, %s)
            RETURNING id
        """, (req.email, password_hash, req.license_key))
        
        user_id = cur.fetchone()[0]
        
        client_ip = request.client.host if request.client else "0.0.0.0"
        cur.execute("""
            INSERT INTO user_devices (user_id, device_fingerprint, device_name, last_ip)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (user_id, req.device_fingerprint, req.device_name, client_ip))
        
        device_id = cur.fetchone()[0]
        
        session_token = generate_token()
        expires_at_session = now() + timedelta(days=30)
        
        cur.execute("""
            INSERT INTO user_sessions (user_id, session_token, device_id, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (user_id, session_token, device_id, expires_at_session))
        
        confirm_token = generate_token()
        confirm_expires = now() + timedelta(hours=24)
        
        cur.execute("""
            INSERT INTO email_confirmations (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        """, (user_id, confirm_token, confirm_expires))
        
        con.commit()
        
        background_tasks.add_task(
            send_confirmation_email,
            req.email,
            confirm_token
        )
        
        return {
            "success": True,
            "session_token": session_token,
            "user_id": user_id,
            "email": req.email,
            "need_confirmation": True
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

class LoginReq(BaseModel):
    email: str
    password: str
    device_fingerprint: str
    device_name: str = "Мой компьютер"

@app.post("/api/auth/login")
def login(req: LoginReq, request: Request):
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
            raise HTTPException(status_code=401, detail="invalid_credentials")
        
        if not verify_password(req.password, user['password_hash']):
            raise HTTPException(status_code=401, detail="invalid_credentials")
        
        if not user['email_confirmed']:
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
                    "message": "Подтвердите email"
                }
            )
        
        cur.execute("""
            SELECT * FROM user_devices 
            WHERE user_id = %s AND device_fingerprint = %s
        """, (user['id'], req.device_fingerprint))
        
        device = cur.fetchone()
        client_ip = request.client.host if request.client else "0.0.0.0"
        
        if device:
            device_id = device['id']
            cur.execute("""
                UPDATE user_devices 
                SET last_login = NOW(), last_ip = %s
                WHERE id = %s
            """, (client_ip, device_id))
        else:
            cur.execute("""
                SELECT COUNT(*) FROM user_devices 
                WHERE user_id = %s AND is_active = TRUE
            """, (user['id'],))
            device_count = cur.fetchone()['count']
            
            if device_count >= user['max_devices']:
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
            
            cur.execute("""
                INSERT INTO user_devices (user_id, device_fingerprint, device_name, last_ip)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (user['id'], req.device_fingerprint, req.device_name, client_ip))
            
            device_id = cur.fetchone()['id']
        
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
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
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
                    <h2>❌ Ссылка недействительна</h2>
                    <p>Возможно, она уже использована или истекла.</p>
                </body>
                </html>
            """)
        
        user_id, expires_at = row
        
        if now() > expires_at:
            return HTMLResponse("""
                <html>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h2>⏰ Ссылка истекла</h2>
                    <p>Запросите новое письмо в программе.</p>
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
                <h2>✅ Email подтверждён!</h2>
                <p>Теперь вы можете войти в программу.</p>
                <p>Вернитесь в приложение и нажмите "Войти".</p>
            </body>
            </html>
        """)
        
    except Exception as e:
        return HTMLResponse(f"""
            <html>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h2>❌ Ошибка</h2>
                <p>{str(e)}</p>
            </body>
            </html>
        """)
    finally:
        cur.close()
        con.close()

# =========================
# АДМИН ПАНЕЛЬ (С НОВОЙ СТАТИСТИКОЙ)
# =========================
@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Получаем лицензии
        cur.execute("SELECT * FROM licenses ORDER BY updated_at DESC LIMIT 500")
        rows = cur.fetchall()
        
        # Статистика по лицензиям
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
        
        # Пробуем получить статистику пользователей
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
        print(f"Ошибка в админке: {e}")
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
        "admin.html",
        {
            "request": request,
            "rows": rows,
            "stats": stats,
        }
    )
    
# =========================
# API УСТРОЙСТВ
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

# =========================
# API БАЛАНСА
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

# =========================
# ФУНКЦИИ ОТПРАВКИ ПИСЕМ
# =========================
def send_confirmation_email(email: str, token: str):
    confirm_url = f"https://license-check-server-xatc.onrender.com/api/auth/confirm?token={token}"
    print(f"📧 Письмо для {email}: {confirm_url}")

def send_password_reset_email(email: str, token: str):
    reset_url = f"https://license-check-server-xatc.onrender.com/reset-password?token={token}"
    print(f"📧 Письмо для сброса пароля {email}: {reset_url}")

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
            "Ты анализируешь сообщения пользователей Telegram на русском языке.\n"
            "Я дам промт (кого ищем) и тексты сообщений людей.\n"
            "Верни СТРОГО валидный JSON (без markdown, без пояснений) строго в формате:\n"
            "{ \"results\": [ {\"id\":\"...\",\"score\":0-100,\"pass\":true/false,\"reason\":\"коротко 5-12 слов\",\"flags\":[\"bot_like|spam_like|toxic|low_quality\"...]}, ... ] }\n"
            "Правило pass: true если score >= min_score и нет flags bot_like/spam_like/toxic.\n"
            "Reason на русском."
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
# ЗАПУСК
# =========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))


