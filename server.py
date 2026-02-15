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

from fastapi import FastAPI, HTTPException, Request, Form, Cookie, Response
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

from openai import OpenAI

app = FastAPI()

# =========================
# ГЛОБАЛЬНЫЙ ОБРАБОТЧИК ОШИБОК
# =========================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": type(exc).__name__, "message": str(exc)}
    )

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
ADMIN_PANEL_SECRET = os.environ.get("ADMIN_PANEL_SECRET", "change-me")

# =========================
# НАЦЕНКА (ТВОЙ ЗАРАБОТОК)
# =========================
MARKUP_MULTIPLIER = 1.5  # Наценка 50% на всё

# ----------------------------
# OPENAI CLIENT
# ----------------------------
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

templates = Jinja2Templates(directory="templates")

# =========================
# ROOT (Render health)
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
# БАЗА ДАННЫХ
# =========================
def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)

def init_db():
    """Создаем все таблицы при запуске"""
    con = db()
    cur = con.cursor()

    # Таблица лицензий
    cur.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        key TEXT PRIMARY KEY,
        hwid TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        note TEXT DEFAULT '',
        plan TEXT DEFAULT 'custom',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        last_check_at TIMESTAMPTZ,
        check_count BIGINT DEFAULT 0
    );
    """)

    # ========== НОВЫЕ ТАБЛИЦЫ ==========
    
    # Таблица пользователей (регистрация по email)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        license_key TEXT REFERENCES licenses(key) ON DELETE CASCADE,
        balance DECIMAL(10,2) DEFAULT 0.00,
        currency TEXT DEFAULT 'USD',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_login TIMESTAMPTZ,
        is_active BOOLEAN DEFAULT TRUE,
        total_spent DECIMAL(10,2) DEFAULT 0.00
    );
    """)

    # Таблица сессий (чтобы пользователь оставался залогинен)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_sessions (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
        session_token TEXT UNIQUE NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        ip_address TEXT,
        user_agent TEXT
    );
    """)

    # Таблица транзакций
    cur.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT REFERENCES users(id),
        license_key TEXT REFERENCES licenses(key),
        amount DECIMAL(10,2) NOT NULL,
        type TEXT NOT NULL, -- 'deposit', 'spend', 'refund'
        description TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        metadata JSONB DEFAULT '{}'
    );
    """)

    # Таблица тарифов (с наценкой x1.5 для AI)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS pricing (
        id SERIAL PRIMARY KEY,
        operation_type TEXT UNIQUE NOT NULL,
        base_price DECIMAL(10,4) NOT NULL,  -- цена для тебя
        final_price DECIMAL(10,4) NOT NULL,  -- цена для клиента (с наценкой)
        min_units INTEGER DEFAULT 1,
        description TEXT
    );
    """)

    # Заполняем тарифы (base_price - твоя себестоимость, final_price - с наценкой x1.5)
    cur.execute("""
    INSERT INTO pricing (operation_type, base_price, final_price, min_units, description)
    VALUES 
        ('parse', 0.0005, 0.0005, 100, 'Парсинг одного сообщения (без наценки)'),
        ('ai_parse', 0.005, 0.0075, 10, 'AI-анализ одного сообщения (наценка 50%)'),
        ('sender', 0.001, 0.001, 50, 'Отправка одного сообщения'),
        ('invite', 0.002, 0.002, 20, 'Приглашение одного пользователя')
    ON CONFLICT (operation_type) DO UPDATE SET
        base_price = EXCLUDED.base_price,
        final_price = EXCLUDED.final_price,
        description = EXCLUDED.description;
    """)

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

    # Платежные запросы
    cur.execute("""
    CREATE TABLE IF NOT EXISTS payment_requests (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT REFERENCES users(id),
        license_key TEXT REFERENCES licenses(key),
        amount DECIMAL(10,2) NOT NULL,
        payment_id TEXT UNIQUE,
        status TEXT DEFAULT 'pending', -- 'pending', 'completed', 'failed'
        payment_url TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        completed_at TIMESTAMPTZ
    );
    """)

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
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =========================

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

def generate_session_token() -> str:
    """Генерация токена сессии"""
    return secrets.token_urlsafe(32)

# =========================
# API ДЛЯ РЕГИСТРАЦИИ И ВХОДА
# =========================

class RegisterReq(BaseModel):
    email: EmailStr
    password: str
    license_key: str

@app.post("/api/auth/register")
def register(req: RegisterReq):
    """Регистрация нового пользователя"""
    con = db()
    cur = con.cursor()
    
    try:
        # Проверяем, существует ли лицензия
        cur.execute("SELECT key FROM licenses WHERE key = %s", (req.license_key,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="license_not_found")
        
        # Проверяем, не занят ли email
        cur.execute("SELECT id FROM users WHERE email = %s", (req.email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="email_already_registered")
        
        # Создаем пользователя
        password_hash = hash_password(req.password)
        cur.execute("""
            INSERT INTO users (email, password_hash, license_key, balance)
            VALUES (%s, %s, %s, 0.00)
            RETURNING id
        """, (req.email, password_hash, req.license_key))
        
        user_id = cur.fetchone()[0]
        
        # Создаем сессию
        session_token = generate_session_token()
        expires_at = now() + timedelta(days=30)
        
        cur.execute("""
            INSERT INTO user_sessions (user_id, session_token, expires_at)
            VALUES (%s, %s, %s)
        """, (user_id, session_token, expires_at))
        
        con.commit()
        
        return {
            "success": True,
            "session_token": session_token,
            "user_id": user_id
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
    email: EmailStr
    password: str

@app.post("/api/auth/login")
def login(req: LoginReq):
    """Вход пользователя"""
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Ищем пользователя
        cur.execute("""
            SELECT id, email, password_hash, license_key, balance 
            FROM users 
            WHERE email = %s
        """, (req.email,))
        
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="invalid_credentials")
        
        # Проверяем пароль
        if not verify_password(req.password, user['password_hash']):
            raise HTTPException(status_code=401, detail="invalid_credentials")
        
        # Обновляем last_login
        cur.execute("""
            UPDATE users SET last_login = NOW() WHERE id = %s
        """, (user['id'],))
        
        # Создаем новую сессию
        session_token = generate_session_token()
        expires_at = now() + timedelta(days=30)
        
        cur.execute("""
            INSERT INTO user_sessions (user_id, session_token, expires_at)
            VALUES (%s, %s, %s)
        """, (user['id'], session_token, expires_at))
        
        con.commit()
        
        return {
            "success": True,
            "session_token": session_token,
            "user": {
                "id": user['id'],
                "email": user['email'],
                "license_key": user['license_key'],
                "balance": float(user['balance'])
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

@app.post("/api/auth/logout")
def logout(session_token: str = Form(...)):
    """Выход из системы"""
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

def get_current_user(session_token: str):
    """Получить текущего пользователя по токену сессии"""
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute("""
            SELECT u.* 
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_token = %s AND s.expires_at > NOW()
        """, (session_token,))
        
        user = cur.fetchone()
        return user
    finally:
        cur.close()
        con.close()

# =========================
# API ДЛЯ РАБОТЫ С БАЛАНСОМ
# =========================

class BalanceReq(BaseModel):
    session_token: str

@app.post("/api/balance/get")
def get_balance(req: BalanceReq):
    """Получить текущий баланс"""
    user = get_current_user(req.session_token)
    if not user:
        raise HTTPException(status_code=401, detail="invalid_session")
    
    return {
        "balance": float(user['balance']),
        "currency": "USD",
        "total_spent": float(user['total_spent']) if user['total_spent'] else 0
    }

class EstimateReq(BaseModel):
    session_token: str
    operation: str  # 'parse', 'ai_parse', 'sender', 'invite'
    units: int

@app.post("/api/balance/estimate")
def estimate_cost(req: EstimateReq):
    """Оценить стоимость операции (с учетом наценки)"""
    user = get_current_user(req.session_token)
    if not user:
        raise HTTPException(status_code=401, detail="invalid_session")
    
    con = db()
    cur = con.cursor()
    
    try:
        # Получаем цену из таблицы тарифов (final_price - уже с наценкой)
        cur.execute("""
            SELECT final_price, min_units 
            FROM pricing 
            WHERE operation_type = %s
        """, (req.operation,))
        
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="operation_not_found")
        
        final_price, min_units = row
        
        # Проверяем минимальное количество
        units = max(req.units, min_units)
        total_cost = final_price * units
        
        return {
            "operation": req.operation,
            "units": units,
            "price_per_unit": float(final_price),
            "total_cost": float(total_cost),
            "current_balance": float(user['balance']),
            "sufficient": float(user['balance']) >= total_cost
        }
        
    finally:
        cur.close()
        con.close()

class ChargeReq(BaseModel):
    session_token: str
    operation: str
    units: int
    description: Optional[str] = ""

@app.post("/api/balance/charge")
def charge_operation(req: ChargeReq):
    """Списать средства за операцию"""
    user = get_current_user(req.session_token)
    if not user:
        raise HTTPException(status_code=401, detail="invalid_session")
    
    con = db()
    cur = con.cursor()
    
    try:
        # Начинаем транзакцию
        cur.execute("BEGIN")
        
        # Получаем цену (final_price - уже с наценкой)
        cur.execute("""
            SELECT final_price, min_units 
            FROM pricing 
            WHERE operation_type = %s
        """, (req.operation,))
        
        price_row = cur.fetchone()
        if not price_row:
            raise HTTPException(status_code=404, detail="operation_not_found")
        
        final_price, min_units = price_row
        units = max(req.units, min_units)
        total_cost = final_price * units
        
        # Проверяем баланс и блокируем строку
        cur.execute("""
            SELECT balance, total_spent 
            FROM users 
            WHERE id = %s 
            FOR UPDATE
        """, (user['id'],))
        
        balance, total_spent = cur.fetchone()
        
        if balance < total_cost:
            raise HTTPException(status_code=403, detail="insufficient_funds")
        
        # Списываем средства
        cur.execute("""
            UPDATE users 
            SET balance = balance - %s,
                total_spent = total_spent + %s,
                last_login = NOW()
            WHERE id = %s
            RETURNING balance
        """, (total_cost, total_cost, user['id']))
        
        new_balance = cur.fetchone()[0]
        
        # Записываем транзакцию
        cur.execute("""
            INSERT INTO transactions 
            (user_id, license_key, amount, type, description, metadata)
            VALUES (%s, %s, %s, 'spend', %s, %s)
            RETURNING id
        """, (
            user['id'],
            user['license_key'],
            -total_cost,
            f"{req.operation}: {req.units} units",
            json.dumps({"operation": req.operation, "units": req.units})
        ))
        
        # Логируем использование
        cur.execute("""
            INSERT INTO usage_logs 
            (user_id, license_key, operation_type, units_used, cost, details)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            user['id'],
            user['license_key'],
            req.operation,
            units,
            total_cost,
            json.dumps({"description": req.description})
        ))
        
        cur.execute("COMMIT")
        
        return {
            "success": True,
            "charged": float(total_cost),
            "new_balance": float(new_balance),
            "units_charged": units
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
    method: str  # 'cryptobot', 'manual'

@app.post("/api/balance/create_deposit")
def create_deposit(req: DepositReq):
    """Создать запрос на пополнение"""
    user = get_current_user(req.session_token)
    if not user:
        raise HTTPException(status_code=401, detail="invalid_session")
    
    if req.amount < 5:
        raise HTTPException(status_code=400, detail="minimum_amount_5")
    
    con = db()
    cur = con.cursor()
    
    try:
        # Генерируем уникальный ID платежа
        payment_id = secrets.token_hex(16)
        
        # Для CryptoBot
        if req.method == 'cryptobot':
            payment_url = f"https://t.me/CryptoBot?start={payment_id}"
            # Здесь потом добавим реальную интеграцию с CryptoBot API
        else:
            # Ручной режим - просто показываем реквизиты
            payment_url = f"/manual_payment/{payment_id}"
        
        # Сохраняем запрос
        cur.execute("""
            INSERT INTO payment_requests 
            (user_id, license_key, amount, payment_id, status, payment_url)
            VALUES (%s, %s, %s, %s, 'pending', %s)
            RETURNING id
        """, (user['id'], user['license_key'], req.amount, payment_id, payment_url))
        
        con.commit()
        
        return {
            "success": True,
            "payment_id": payment_id,
            "payment_url": payment_url,
            "amount": req.amount,
            "instructions": "Переведите точную сумму и отправьте скриншот @Ben_bell97" if req.method == 'manual' else "Оплатите через CryptoBot"
        }
        
    except Exception as e:
        con.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        con.close()

@app.post("/api/balance/confirm_payment")
def confirm_payment(payment_id: str, admin_token: str = Form(...)):
    """Подтверждение платежа админом (ручной режим)"""
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="unauthorized")
    
    con = db()
    cur = con.cursor()
    
    try:
        # Находим платеж
        cur.execute("""
            SELECT user_id, license_key, amount, status 
            FROM payment_requests 
            WHERE payment_id = %s AND status = 'pending'
        """, (payment_id,))
        
        payment = cur.fetchone()
        if not payment:
            raise HTTPException(status_code=404, detail="payment_not_found")
        
        user_id, license_key, amount, status = payment
        
        # Начисляем баланс
        cur.execute("""
            UPDATE users 
            SET balance = balance + %s 
            WHERE id = %s
        """, (amount, user_id))
        
        # Обновляем статус платежа
        cur.execute("""
            UPDATE payment_requests 
            SET status = 'completed', completed_at = NOW()
            WHERE payment_id = %s
        """, (payment_id,))
        
        # Записываем транзакцию
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
# АДМИН ПАНЕЛЬ (ОБНОВЛЕННАЯ)
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
    
    # Статистика по лицензиям
    cur.execute("SELECT * FROM licenses ORDER BY updated_at DESC LIMIT 500")
    rows = cur.fetchall()
    
    # Статистика по пользователям
    cur.execute("""
        SELECT 
            COUNT(*) as total_users,
            SUM(balance) as total_balance,
            SUM(total_spent) as total_revenue
        FROM users
    """)
    user_stats = cur.fetchone()
    
    # Последние транзакции
    cur.execute("""
        SELECT t.*, u.email 
        FROM transactions t
        JOIN users u ON t.user_id = u.id
        ORDER BY t.created_at DESC
        LIMIT 50
    """)
    transactions = cur.fetchall()
    
    cur.close()
    con.close()
    
    stats = {
        "total": len(rows),
        "active": len([r for r in rows if not r["revoked"] and r["expires_at"] > now()]),
        "revoked": len([r for r in rows if r["revoked"]]),
        "expired": len([r for r in rows if not r["revoked"] and r["expires_at"] <= now()]),
        "total_users": user_stats['total_users'] or 0,
        "total_balance": float(user_stats['total_balance'] or 0),
        "total_revenue": float(user_stats['total_revenue'] or 0)
    }
    
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "rows": rows,
            "stats": stats,
            "transactions": transactions
        }
    )

# ... (остальные админские функции /admin/upsert, /admin/revoke и т.д. остаются без изменений)

# =========================
# AI API (без изменений)
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
        raise ValueError("No JSON object found in model output")
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
