import os
import csv
import io
import json
import re
import secrets
import hashlib
import hmac
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

from fastapi import FastAPI, HTTPException, Request, Form, Cookie, Response, BackgroundTasks
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
# НАСТРОЙКИ
# =========================
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
ADMIN_PANEL_SECRET = os.environ.get("ADMIN_PANEL_SECRET", "change-me")

# Для отправки писем (пока заглушка, потом подключим SendGrid)
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@tgparsersender.me")

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
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =========================
def now():
    return datetime.now(timezone.utc)

def is_admin(request: Request):
    return request.session.get("is_admin")

def hash_password(password: str) -> str:
    """Хеширование пароля"""
    salt = secrets.token_hex(16)
    return salt + ':' + hashlib.sha256((salt + password).encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    """Проверка пароля"""
    try:
        salt, hash_val = password_hash.split(':')
        return hash_val == hashlib.sha256((salt + password).encode()).hexdigest()
    except:
        return False

def generate_token() -> str:
    """Генерация случайного токена"""
    return secrets.token_urlsafe(32)

# =========================
# БАЗА ДАННЫХ
# =========================
def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)

def init_db():
    """Создание всех таблиц"""
    print("🚀 Создаю таблицы...")
    con = db()
    cur = con.cursor()
    
    try:
        # Таблица лицензий
        cur.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            hwid TEXT NOT NULL,
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
        print("✓ licenses")
        
        # Таблица пользователей
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
        print("✓ users")
        
        # Таблица устройств (fingerprint)
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
        print("✓ user_devices")
        
        # Таблица сессий (для входа)
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
        print("✓ user_sessions")
        
        # Таблица подтверждения email
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
        print("✓ email_confirmations")
        
        # Таблица сброса пароля
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
        print("✓ password_resets")
        
        # Таблица транзакций
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
        print("✓ transactions")
        
        # Тарифы
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
        
        # Заполняем тарифы
        cur.execute("""
        INSERT INTO pricing (operation_type, base_price, final_price, min_units, description)
        VALUES 
            ('parse', 0.0005, 0.0005, 100, 'Парсинг одного сообщения'),
            ('ai_parse', 0.005, 0.0075, 10, 'AI-анализ одного сообщения'),
            ('sender', 0.001, 0.001, 50, 'Отправка одного сообщения'),
            ('invite', 0.002, 0.002, 20, 'Приглашение одного пользователя')
        ON CONFLICT (operation_type) DO UPDATE SET
            base_price = EXCLUDED.base_price,
            final_price = EXCLUDED.final_price,
            description = EXCLUDED.description;
        """)
        print("✓ pricing")
        
        # Логи использования
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
        print("✓ usage_logs")
        
        # Платежные запросы
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
        print("✓ payment_requests")
        
        # Аудит админа
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
        print("✓ admin_audit")
        
        con.commit()
        print("✅ ВСЕ ТАБЛИЦЫ СОЗДАНЫ!")
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        con.rollback()
        raise
    finally:
        cur.close()
        con.close()

@app.on_event("startup")
def startup():
    init_db()

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
def register(req: RegisterReq, background_tasks: BackgroundTasks):
    """Регистрация нового пользователя"""
    con = db()
    cur = con.cursor()
    
    try:
        # Проверяем лицензию
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
        
        # Проверяем email
        cur.execute("SELECT id FROM users WHERE email = %s", (req.email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="email_already_registered")
        
        # Создаем пользователя
        password_hash = hash_password(req.password)
        cur.execute("""
            INSERT INTO users (email, password_hash, license_key)
            VALUES (%s, %s, %s)
            RETURNING id
        """, (req.email, password_hash, req.license_key))
        
        user_id = cur.fetchone()[0]
        
        # Добавляем устройство
        cur.execute("""
            INSERT INTO user_devices (user_id, device_fingerprint, device_name, last_ip)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (user_id, req.device_fingerprint, req.device_name, req.client.host))
        
        device_id = cur.fetchone()[0]
        
        # Создаем сессию
        session_token = generate_token()
        expires_at_session = now() + timedelta(days=30)
        
        cur.execute("""
            INSERT INTO user_sessions (user_id, session_token, device_id, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (user_id, session_token, device_id, expires_at_session))
        
        # Создаем токен подтверждения email
        confirm_token = generate_token()
        confirm_expires = now() + timedelta(hours=24)
        
        cur.execute("""
            INSERT INTO email_confirmations (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        """, (user_id, confirm_token, confirm_expires))
        
        con.commit()
        
        # Отправляем письмо (фоново)
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
    """Вход в аккаунт"""
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Ищем пользователя
        cur.execute("""
            SELECT u.*, l.max_devices 
            FROM users u
            JOIN licenses l ON u.license_key = l.key
            WHERE u.email = %s
        """, (req.email,))
        
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="invalid_credentials")
        
        # Проверяем пароль
        if not verify_password(req.password, user['password_hash']):
            raise HTTPException(status_code=401, detail="invalid_credentials")
        
        # Проверяем подтверждение email
        if not user['email_confirmed']:
            # Создаем новый токен подтверждения
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
        
        # Проверяем устройство
        cur.execute("""
            SELECT * FROM user_devices 
            WHERE user_id = %s AND device_fingerprint = %s
        """, (user['id'], req.device_fingerprint))
        
        device = cur.fetchone()
        
        if device:
            # Устройство уже есть - обновляем
            device_id = device['id']
            cur.execute("""
                UPDATE user_devices 
                SET last_login = NOW(), last_ip = %s
                WHERE id = %s
            """, (request.client.host, device_id))
        else:
            # Новое устройство - проверяем лимит
            cur.execute("""
                SELECT COUNT(*) FROM user_devices 
                WHERE user_id = %s AND is_active = TRUE
            """, (user['id'],))
            device_count = cur.fetchone()['count']
            
            if device_count >= user['max_devices']:
                # Лимит превышен - возвращаем список устройств
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
            
            # Добавляем новое устройство
            cur.execute("""
                INSERT INTO user_devices (user_id, device_fingerprint, device_name, last_ip)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (user['id'], req.device_fingerprint, req.device_name, request.client.host))
            
            device_id = cur.fetchone()['id']
        
        # Создаем сессию
        session_token = generate_token()
        expires_at_session = now() + timedelta(days=30)
        
        cur.execute("""
            INSERT INTO user_sessions (user_id, session_token, device_id, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (user['id'], session_token, device_id, expires_at_session))
        
        # Обновляем last_login
        cur.execute("""
            UPDATE users SET last_login = NOW() WHERE id = %s
        """, (user['id'],))
        
        con.commit()
        
        # Получаем все устройства пользователя
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
    """Выход из аккаунта"""
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
    """Подтверждение email"""
    con = db()
    cur = con.cursor()
    
    try:
        # Ищем токен
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
        
        # Подтверждаем email
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

@app.post("/api/auth/resend-confirmation")
def resend_confirmation(email: str, background_tasks: BackgroundTasks):
    """Переотправить письмо подтверждения"""
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="user_not_found")
        
        user_id = user[0]
        
        # Создаем новый токен
        confirm_token = generate_token()
        confirm_expires = now() + timedelta(hours=24)
        
        cur.execute("""
            INSERT INTO email_confirmations (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        """, (user_id, confirm_token, confirm_expires))
        
        con.commit()
        
        # Отправляем письмо
        background_tasks.add_task(
            send_confirmation_email,
            email,
            confirm_token
        )
        
        return {"success": True}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

@app.post("/api/auth/forgot-password")
def forgot_password(email: str, background_tasks: BackgroundTasks):
    """Запрос на сброс пароля"""
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if not user:
            # Не говорим, что пользователь не найден (безопасность)
            return {"success": True}
        
        user_id = user[0]
        
        # Создаем токен сброса
        reset_token = generate_token()
        reset_expires = now() + timedelta(hours=1)
        
        cur.execute("""
            INSERT INTO password_resets (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        """, (user_id, reset_token, reset_expires))
        
        con.commit()
        
        # Отправляем письмо
        background_tasks.add_task(
            send_password_reset_email,
            email,
            reset_token
        )
        
        return {"success": True}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

@app.post("/api/auth/reset-password")
def reset_password(token: str, new_password: str):
    """Сброс пароля"""
    con = db()
    cur = con.cursor()
    
    try:
        # Ищем токен
        cur.execute("""
            SELECT user_id, expires_at 
            FROM password_resets 
            WHERE token = %s AND used = FALSE
        """, (token,))
        
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="invalid_token")
        
        user_id, expires_at = row
        
        if now() > expires_at:
            raise HTTPException(status_code=403, detail="token_expired")
        
        # Меняем пароль
        password_hash = hash_password(new_password)
        cur.execute("""
            UPDATE users 
            SET password_hash = %s
            WHERE id = %s
        """, (password_hash, user_id))
        
        # Помечаем токен как использованный
        cur.execute("""
            UPDATE password_resets 
            SET used = TRUE
            WHERE token = %s
        """, (token,))
        
        con.commit()
        
        return {"success": True}
        
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

@app.post("/api/auth/sessions")
def get_sessions(session_token: str):
    """Получить все активные сессии пользователя"""
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT s.*, d.device_name, d.device_fingerprint
            FROM user_sessions s
            JOIN user_devices d ON s.device_id = d.id
            WHERE s.user_id = (
                SELECT user_id FROM user_sessions WHERE session_token = %s
            ) AND s.expires_at > NOW()
            ORDER BY s.last_active DESC
        """, (session_token,))
        
        sessions = cur.fetchall()
        
        return {
            "sessions": [
                {
                    "id": s['id'],
                    "device_name": s['device_name'],
                    "last_active": s['last_active'].isoformat() if s['last_active'] else None,
                    "is_current": s['session_token'] == session_token
                }
                for s in sessions
            ]
        }
        
    finally:
        cur.close()
        con.close()

@app.post("/api/auth/terminate-session")
def terminate_session(session_id: int, session_token: str):
    """Завершить сессию"""
    con = db()
    cur = con.cursor()
    
    try:
        # Проверяем, что это сессия текущего пользователя
        cur.execute("""
            DELETE FROM user_sessions 
            WHERE id = %s AND user_id = (
                SELECT user_id FROM user_sessions WHERE session_token = %s
            )
        """, (session_id, session_token))
        
        con.commit()
        return {"success": True}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

# =========================
# API УСТРОЙСТВ
# =========================

class DeviceReq(BaseModel):
    session_token: str
    device_fingerprint: str

@app.post("/api/devices/list")
def list_devices(req: DeviceReq):
    """Список устройств пользователя"""
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
    """Переименовать устройство"""
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
    """Отвязать устройство"""
    con = db()
    cur = con.cursor()
    
    try:
        # Нельзя удалить текущее устройство
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
        
        # Удаляем сессии этого устройства
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
# ФУНКЦИИ ОТПРАВКИ ПИСЕМ
# =========================

def send_confirmation_email(email: str, token: str):
    """Отправка письма с подтверждением"""
    confirm_url = f"https://license-check-server-xatc.onrender.com/api/auth/confirm?token={token}"
    
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333;">TG Parser Sender</h2>
        <p>Здравствуйте!</p>
        <p>Для подтверждения email нажмите на кнопку:</p>
        <a href="{confirm_url}" style="display: inline-block; background: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 20px 0;">Подтвердить email</a>
        <p>Или перейдите по ссылке: <a href="{confirm_url}">{confirm_url}</a></p>
        <p>Ссылка действительна 24 часа.</p>
        <p>С уважением,<br>Команда TG Parser Sender</p>
    </body>
    </html>
    """
    
    # Пока просто печатаем в консоль (потом подключим SendGrid)
    print(f"📧 Письмо для {email}: {confirm_url}")
    
    # Здесь будет код отправки через SendGrid/Mailgun

def send_password_reset_email(email: str, token: str):
    """Отправка письма для сброса пароля"""
    reset_url = f"https://license-check-server-xatc.onrender.com/reset-password?token={token}"
    
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333;">TG Parser Sender</h2>
        <p>Здравствуйте!</p>
        <p>Для сброса пароля нажмите на кнопку:</p>
        <a href="{reset_url}" style="display: inline-block; background: #2196F3; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 20px 0;">Сбросить пароль</a>
        <p>Или перейдите по ссылке: <a href="{reset_url}">{reset_url}</a></p>
        <p>Ссылка действительна 1 час.</p>
        <p>Если вы не запрашивали сброс пароля, проигнорируйте это письмо.</p>
        <p>С уважением,<br>Команда TG Parser Sender</p>
    </body>
    </html>
    """
    
    print(f"📧 Письмо для сброса пароля {email}: {reset_url}")

# =========================
# API БАЛАНСА
# =========================

class BalanceReq(BaseModel):
    session_token: str

@app.post("/api/balance/get")
def get_balance(req: BalanceReq):
    """Получить баланс"""
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
    """Оценить стоимость"""
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
    """Списать средства"""
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("BEGIN")
        
        # Получаем цену
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
        
        # Получаем пользователя
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
        
        # Списываем
        cur.execute("""
            UPDATE users 
            SET balance = balance - %s, total_spent = total_spent + %s
            WHERE id = %s
            RETURNING balance
        """, (total_cost, total_cost, user_id))
        
        new_balance = cur.fetchone()[0]
        
        # Логируем
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

class DepositReq(BaseModel):
    session_token: str
    amount: float
    method: str

@app.post("/api/balance/create_deposit")
def create_deposit(req: DepositReq):
    """Создать запрос на пополнение"""
    con = db()
    cur = con.cursor()
    
    try:
        if req.amount < 5:
            raise HTTPException(status_code=400, detail="minimum_amount_5")
        
        cur.execute("""
            SELECT u.id, u.license_key
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_token = %s
        """, (req.session_token,))
        
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="invalid_session")
        
        user_id, license_key = user
        
        payment_id = secrets.token_hex(16)
        
        if req.method == 'cryptobot':
            payment_url = f"https://t.me/CryptoBot?start={payment_id}"
        else:
            payment_url = f"/manual_payment/{payment_id}"
        
        cur.execute("""
            INSERT INTO payment_requests 
            (user_id, license_key, amount, payment_id, status, payment_url)
            VALUES (%s, %s, %s, %s, 'pending', %s)
        """, (user_id, license_key, req.amount, payment_id, payment_url))
        
        con.commit()
        
        return {
            "success": True,
            "payment_id": payment_id,
            "payment_url": payment_url,
            "amount": req.amount,
            "instructions": "Переведите точную сумму и отправьте скриншот @Ben_bell97"
        }
        
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

@app.post("/api/balance/confirm_payment")
def confirm_payment(payment_id: str, admin_token: str = Form(...)):
    """Подтверждение платежа админом"""
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="unauthorized")
    
    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("""
            SELECT user_id, license_key, amount, status 
            FROM payment_requests 
            WHERE payment_id = %s AND status = 'pending'
        """, (payment_id,))
        
        payment = cur.fetchone()
        if not payment:
            raise HTTPException(status_code=404, detail="payment_not_found")
        
        user_id, license_key, amount, status = payment
        
        cur.execute("""
            UPDATE users 
            SET balance = balance + %s 
            WHERE id = %s
        """, (amount, user_id))
        
        cur.execute("""
            UPDATE payment_requests 
            SET status = 'completed', completed_at = NOW()
            WHERE payment_id = %s
        """, (payment_id,))
        
        cur.execute("""
            INSERT INTO transactions 
            (user_id, license_key, amount, type, description)
            VALUES (%s, %s, %s, 'deposit', 'Пополнение баланса')
        """, (user_id, license_key, amount))
        
        con.commit()
        
        return {"success": True, "amount": amount}
        
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

# =========================
# АДМИН ПАНЕЛЬ
# =========================

@app.get("/admin/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": ""})

@app.post("/admin/login")
def login(request: Request, token: str = Form(...)):
    if token != ADMIN_TOKEN:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверный токен"}
        )
    
    request.session["is_admin"] = True
    return RedirectResponse("/admin", status_code=303)

@app.post("/admin/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)

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
        active_count = 0
        expired_count = 0
        revoked_count = 0
        
        for r in rows:
            if r["revoked"]:
                revoked_count += 1
            elif r["expires_at"] > now_ts:
                active_count += 1
            else:
                expired_count += 1
        
        # Статистика пользователей
        try:
            cur.execute("""
                SELECT 
                    COUNT(*) as total_users,
                    COUNT(CASE WHEN email_confirmed THEN 1 END) as confirmed_users,
                    COALESCE(SUM(balance), 0) as total_balance,
                    COALESCE(SUM(total_spent), 0) as total_revenue
                FROM users
            """)
            user_stats = cur.fetchone()
        except:
            user_stats = {"total_users": 0, "confirmed_users": 0, "total_balance": 0, "total_revenue": 0}
        
        # Статистика устройств
        try:
            cur.execute("""
                SELECT 
                    COUNT(*) as total_devices,
                    COUNT(DISTINCT user_id) as users_with_devices
                FROM user_devices
                WHERE is_active = TRUE
            """)
            device_stats = cur.fetchone()
        except:
            device_stats = {"total_devices": 0, "users_with_devices": 0}
        
        stats = {
            "total": len(rows),
            "active": active_count,
            "expired": expired_count,
            "revoked": revoked_count,
            "total_users": user_stats["total_users"] or 0,
            "confirmed_users": user_stats["confirmed_users"] or 0,
            "total_balance": float(user_stats["total_balance"] or 0),
            "total_revenue": float(user_stats["total_revenue"] or 0),
            "total_devices": device_stats["total_devices"] or 0,
            "users_with_devices": device_stats["users_with_devices"] or 0
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

