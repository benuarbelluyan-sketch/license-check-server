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

from fastapi import FastAPI, HTTPException, Request, Form
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
# БАЗА ДАННЫХ
# =========================
def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)

def init_db():
    """Создаем все таблицы"""
    print("🚀 Начинаю создание таблиц...")
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
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            last_check_at TIMESTAMPTZ,
            check_count BIGINT DEFAULT 0
        );
        """)
        print("✓ licenses OK")

        # Таблица пользователей
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
        print("✓ users OK")

        # Сессии
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
        print("✓ sessions OK")

        # Транзакции
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
        print("✓ transactions OK")

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
            ('ai_parse', 0.005, 0.0075, 10, 'AI-анализ одного сообщения (наценка 50%)'),
            ('sender', 0.001, 0.001, 50, 'Отправка одного сообщения'),
            ('invite', 0.002, 0.002, 20, 'Приглашение одного пользователя')
        ON CONFLICT (operation_type) DO UPDATE SET
            base_price = EXCLUDED.base_price,
            final_price = EXCLUDED.final_price,
            description = EXCLUDED.description;
        """)
        print("✓ pricing OK")

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
        print("✓ usage_logs OK")

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
        print("✓ payment_requests OK")

        # Аудит
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
        print("✓ admin_audit OK")
        
        con.commit()
        print("✅ ВСЕ ТАБЛИЦЫ СОЗДАНЫ УСПЕШНО!")
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        con.rollback()
        raise
    finally:
        cur.close()
        con.close()

@app.on_event("startup")
def startup():
    print("🚀 Сервер запускается...")
    init_db()

def now():
    return datetime.now(timezone.utc)

def is_admin(request: Request):
    return request.session.get("is_admin")

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
    
    # Лицензии
    cur.execute("SELECT * FROM licenses ORDER BY updated_at DESC LIMIT 500")
    rows = cur.fetchall()
    
    # Статистика
    stats = {
        "total": len(rows),
        "active": len([r for r in rows if not r["revoked"] and r["expires_at"] > now()]),
        "revoked": len([r for r in rows if r["revoked"]]),
        "expired": len([r for r in rows if not r["revoked"] and r["expires_at"] <= now()]),
    }
    
    # Пробуем получить статистику пользователей
    try:
        cur.execute("SELECT COUNT(*) as count FROM users")
        user_count = cur.fetchone()['count']
        stats["total_users"] = user_count
    except:
        stats["total_users"] = 0
    
    try:
        cur.execute("SELECT COALESCE(SUM(balance), 0) as total FROM users")
        total_balance = cur.fetchone()['total']
        stats["total_balance"] = float(total_balance)
    except:
        stats["total_balance"] = 0
    
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
