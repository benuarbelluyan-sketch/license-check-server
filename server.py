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
    JSONResponse,
)
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from openai import OpenAI

app = FastAPI()

# =========================
# GLOBAL ERROR HANDLER (чтобы вместо "Internal Server Error" отдавал причину)
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
            # важно: так ты сразу увидишь причину в ответе
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
# DATABASE
# =========================

def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)


def init_db():
    con = db()
    cur = con.cursor()

    # базовая таблица
    cur.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        key TEXT PRIMARY KEY,
        hwid TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        note TEXT DEFAULT ''
    );
    """)

    # миграции
    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'custom';")
    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();")
    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();")
    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_check_at TIMESTAMPTZ;")
    cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS check_count BIGINT DEFAULT 0;")

    # аудит
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

    # статистика
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
# AI DIAGNOSTIC (проверка ключа и версии openai)
# =========================

@app.get("/api/ai/ping")
def ai_ping():
    key_ok = bool(os.environ.get("OPENAI_API_KEY", "").strip())
    try:
        import openai
        ver = getattr(openai, "__version__", "unknown")
    except Exception as e:
        ver = f"import_error: {e}"
    return {"ok": True, "openai_version": ver, "key_set": key_ok}


# =========================
# ADMIN LOGIN
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


# =========================
# ADMIN PANEL
# =========================

@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT * FROM licenses
        ORDER BY updated_at DESC
        LIMIT 500
    """)
    rows = cur.fetchall()
    cur.close()
    con.close()

    stats = {
        "total": len(rows),
        "active": len([r for r in rows if not r["revoked"] and r["expires_at"] > now()]),
        "revoked": len([r for r in rows if r["revoked"]]),
        "expired": len([r for r in rows if not r["revoked"] and r["expires_at"] <= now()])
    }

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "rows": rows,
            "stats": stats,
        }
    )


# =========================
# CREATE / UPDATE LICENSE
# =========================

@app.post("/admin/upsert")
def upsert_license(
    request: Request,
    key: str = Form(...),
    hwid: str = Form(...),
    days: int = Form(...),
    note: str = Form("")
):
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    expires = now() + timedelta(days=int(days))

    con = db()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO licenses(key, hwid, expires_at, revoked, note, updated_at)
        VALUES (%s,%s,%s,FALSE,%s,NOW())
        ON CONFLICT (key) DO UPDATE SET
            hwid=EXCLUDED.hwid,
            expires_at=EXCLUDED.expires_at,
            revoked=FALSE,
            note=EXCLUDED.note,
            updated_at=NOW()
    """, (key.strip(), hwid.strip(), expires, note.strip()))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse("/admin", status_code=303)


# =========================
# ADD DAYS
# =========================

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


# =========================
# REVOKE / UNREVOKE
# =========================

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


# =========================
# DELETE
# =========================

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


# =========================
# EXPORT CSV
# =========================

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
    writer.writerow(rows[0].keys() if rows else [])

    for row in rows:
        writer.writerow(row.values())

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=licenses.csv"}
    )


# =========================
# AI API (score)
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
        "Верни строго валидный JSON без пояснений и без markdown. "
        "Язык reason — русский."
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

    # Самый надёжный вариант в новом SDK
    out_text = getattr(resp, "output_text", None)
    if not out_text:
        out_text = ""
        for o in resp.output:
            if o.type == "message":
                for c in o.content:
                    if getattr(c, "type", None) == "output_text":
                        out_text += c.text

    data = json.loads(out_text)

    if not isinstance(data, dict) or "results" not in data:
        raise RuntimeError(f"bad_ai_response: {out_text[:200]}")

    return data
