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


# =========================
# HEALTH
# =========================
@app.get("/", response_class=PlainTextResponse)
def root():
    return "OK"


@app.head("/")
def root_head():
    return PlainTextResponse("OK")


@app.head("/admin")
def admin_head():
    return PlainTextResponse("OK")


# =========================
# CLIENT API (старое: LICENSE CHECK)
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
        cur.close()
        con.close()
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

    if expires_at < now_utc():
        raise HTTPException(status_code=403, detail="expired")

    return {"ok": True, "expires_at": expires_at.isoformat()}


# =========================
# AUTH (аккаунты)
# =========================
def hash_password(p: str) -> str:
    return pwd.hash(p)

def verify_password(p: str, h: str) -> bool:
    return pwd.verify(p, h)

def make_token(user_id: int, email: str) -> str:
    t0 = now_utc()
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": int(t0.timestamp()),
        "exp": int((t0 + timedelta(days=JWT_TTL_DAYS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


class RegisterReq(BaseModel):
    email: EmailStr
    password: str
    hwid: Optional[str] = None


class LoginReq(BaseModel):
    email: EmailStr
    password: str
    hwid: Optional[str] = None


def get_user_by_id(user_id: int) -> dict:
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT id, email, subscription_expiry, ai_balance_cents, device_hwid, created_at
        FROM users WHERE id=%s
    """, (user_id,))
    row = cur.fetchone()
    cur.close()
    con.close()
    if not row:
        raise HTTPException(status_code=401, detail="user_not_found")
    return dict(row)


def get_user_from_auth(authorization: Optional[str]) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing_authorization")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="bad_authorization")
    token = parts[1].strip()
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="bad_token")
    user_id = int(payload["sub"])
    return get_user_by_id(user_id)


@app.post("/api/auth/register")
def register(req: RegisterReq):
    pwd_raw = (req.password or "").strip()
    if len(pwd_raw) < 8:
        raise HTTPException(status_code=400, detail="password_too_short")

    email = req.email.lower().strip()
    hwid = (req.hwid or "").strip() or None

    con = db()
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO users(email, password_hash, device_hwid) VALUES(%s,%s,%s) RETURNING id",
            (email, hash_password(pwd_raw), hwid),
        )
        user_id = cur.fetchone()[0]
        con.commit()
    except Exception:
        con.rollback()
        cur.close()
        con.close()
        raise HTTPException(status_code=400, detail="email_already_used")

    cur.close()
    con.close()

    token = make_token(user_id, email)
    return {"access_token": token}


@app.post("/api/auth/login")
def login(req: LoginReq):
    email = req.email.lower().strip()
    incoming_hwid = (req.hwid or "").strip() or None

    con = db()
    cur = con.cursor()
    cur.execute("SELECT id, email, password_hash, device_hwid FROM users WHERE email=%s", (email,))
    row = cur.fetchone()
    if not row:
        cur.close()
        con.close()
        raise HTTPException(status_code=401, detail="bad_credentials")

    user_id, email_db, password_hash_db, device_hwid = row

    if not verify_password((req.password or "").strip(), password_hash_db):
        cur.close()
        con.close()
        raise HTTPException(status_code=401, detail="bad_credentials")

    # 1 устройство:
    # - если device_hwid пустой -> привязываем к incoming_hwid
    # - если не пустой и incoming_hwid != device_hwid -> отказ
    if device_hwid is None:
        if not incoming_hwid:
            cur.close()
            con.close()
            raise HTTPException(status_code=400, detail="hwid_required")
        cur.execute("UPDATE users SET device_hwid=%s WHERE id=%s", (incoming_hwid, user_id))
        con.commit()
    else:
        if incoming_hwid and incoming_hwid != device_hwid:
            cur.close()
            con.close()
            raise HTTPException(status_code=403, detail="device_mismatch")

    cur.close()
    con.close()

    token = make_token(user_id, email_db)
    return {"access_token": token}


@app.get("/api/me")
def me(authorization: Optional[str] = Header(default=None)):
    u = get_user_from_auth(authorization)
    return {
        "email": u["email"],
        "subscription_expiry": u["subscription_expiry"].isoformat() if u["subscription_expiry"] else None,
        "ai_balance_cents": int(u["ai_balance_cents"]),
        "device_hwid": u["device_hwid"],
    }


# =========================
# ADMIN PANEL (как было)
# =========================
@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    # если уже залогинен — перекинуть
    if is_admin_session(request):
        return RedirectResponse("/admin", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/admin/login")
def admin_login(request: Request, token: str = Form(...)):
    if token != ADMIN_PANEL_SECRET:
        raise HTTPException(status_code=401, detail="bad_admin_secret")
    request.session["is_admin"] = True
    return RedirectResponse("/admin", status_code=302)


@app.post("/admin/logout")
def admin_logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=302)


@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request):
    if not is_admin_session(request):
        return RedirectResponse("/admin/login", status_code=302)

    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT COUNT(*) AS c FROM licenses")
    total = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM licenses WHERE revoked=true")
    revoked = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM licenses WHERE expires_at < NOW() AND revoked=false")
    expired = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM licenses WHERE expires_at >= NOW() AND revoked=false")
    active = cur.fetchone()["c"]

    cur.execute("""
        SELECT key, hwid, expires_at, revoked, note, plan, created_at, updated_at, last_check_at, check_count
        FROM licenses
        ORDER BY updated_at DESC NULLS LAST
        LIMIT 500
    """)
    licenses = cur.fetchall()

    cur.close()
    con.close()

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "total": total,
            "active": active,
            "expired": expired,
            "revoked": revoked,
            "licenses": licenses,
        },
    )


@app.post("/admin/upsert")
def upsert_license(
    request: Request,
    key: str = Form(...),
    hwid: str = Form(...),
    days: int = Form(...),
    note: str = Form(""),
    plan: str = Form("custom"),
):
    if not is_admin_session(request):
        return RedirectResponse("/admin/login", status_code=302)

    expires_at = now_utc() + timedelta(days=max(0, int(days)))

    con = db()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO licenses(key, hwid, expires_at, revoked, note, plan, created_at, updated_at)
        VALUES(%s,%s,%s,false,%s,%s,NOW(),NOW())
        ON CONFLICT (key) DO UPDATE
        SET hwid=EXCLUDED.hwid,
            expires_at=EXCLUDED.expires_at,
            revoked=false,
            note=EXCLUDED.note,
            plan=EXCLUDED.plan,
            updated_at=NOW()
    """, (key.strip(), hwid.strip(), expires_at, note, plan))

    cur.execute("INSERT INTO admin_audit(action, key, hwid, info) VALUES(%s,%s,%s,%s)",
                ("upsert", key.strip(), hwid.strip(), f"days={days}, plan={plan}"))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse("/admin", status_code=302)


@app.post("/admin/add_days")
def add_days(request: Request, key: str = Form(...), days: int = Form(...)):
    if not is_admin_session(request):
        return RedirectResponse("/admin/login", status_code=302)

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET expires_at=expires_at + (%s || ' days')::interval, updated_at=NOW() WHERE key=%s",
                (int(days), key.strip()))
    cur.execute("INSERT INTO admin_audit(action, key, info) VALUES(%s,%s,%s)",
                ("add_days", key.strip(), f"days={days}"))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse("/admin", status_code=302)


@app.post("/admin/revoke")
def revoke(request: Request, key: str = Form(...)):
    if not is_admin_session(request):
        return RedirectResponse("/admin/login", status_code=302)

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=true, updated_at=NOW() WHERE key=%s", (key.strip(),))
    cur.execute("INSERT INTO admin_audit(action, key, info) VALUES(%s,%s,%s)",
                ("revoke", key.strip(), ""))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse("/admin", status_code=302)


@app.post("/admin/unrevoke")
def unrevoke(request: Request, key: str = Form(...)):
    if not is_admin_session(request):
        return RedirectResponse("/admin/login", status_code=302)

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=false, updated_at=NOW() WHERE key=%s", (key.strip(),))
    cur.execute("INSERT INTO admin_audit(action, key, info) VALUES(%s,%s,%s)",
                ("unrevoke", key.strip(), ""))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse("/admin", status_code=302)


@app.post("/admin/delete")
def delete(request: Request, key: str = Form(...)):
    if not is_admin_session(request):
        return RedirectResponse("/admin/login", status_code=302)

    con = db()
    cur = con.cursor()
    cur.execute("DELETE FROM licenses WHERE key=%s", (key.strip(),))
    cur.execute("INSERT INTO admin_audit(action, key, info) VALUES(%s,%s,%s)",
                ("delete", key.strip(), ""))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse("/admin", status_code=302)


@app.get("/admin/export")
def export_csv(request: Request):
    if not is_admin_session(request):
        return RedirectResponse("/admin/login", status_code=302)

    con = db()
    cur = con.cursor()
    cur.execute("SELECT key, hwid, expires_at, revoked, note, plan, created_at, updated_at, last_check_at, check_count FROM licenses")
    rows = cur.fetchall()
    cur.close()
    con.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["key", "hwid", "expires_at", "revoked", "note", "plan", "created_at", "updated_at", "last_check_at", "check_count"])
    for r in rows:
        writer.writerow(r)

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=licenses.csv"},
    )


# =========================
# ADMIN JSON API (для аккаунтов/баланса)
# =========================
class AdminUserReq(BaseModel):
    email: EmailStr


class AdminTopupReq(BaseModel):
    email: EmailStr
    amount_cents: int
    reason: str = "manual_topup"


class AdminGrantSubReq(BaseModel):
    email: EmailStr
    days: int
    reason: str = "manual_subscription"


@app.post("/admin/api/topup_balance")
def admin_topup_balance(
    request: Request,
    payload: AdminTopupReq,
    x_admin_token: Optional[str] = Header(default=None),
):
    require_admin(request, x_admin_token)
    amt = int(payload.amount_cents)
    if amt == 0:
        return {"ok": True}

    con = db()
    cur = con.cursor()
    cur.execute("SELECT id FROM users WHERE email=%s", (payload.email.lower().strip(),))
    row = cur.fetchone()
    if not row:
        cur.close()
        con.close()
        raise HTTPException(status_code=404, detail="user_not_found")
    user_id = row[0]

    cur.execute("UPDATE users SET ai_balance_cents = ai_balance_cents + %s WHERE id=%s", (amt, user_id))
    cur.execute(
        "INSERT INTO wallet_ledger(user_id, delta_cents, reason, meta) VALUES(%s,%s,%s,%s)",
        (user_id, amt, payload.reason, json.dumps({"admin": True})),
    )
    con.commit()
    cur.close()
    con.close()
    return {"ok": True, "email": payload.email.lower().strip(), "delta_cents": amt}


@app.post("/admin/api/grant_subscription_days")
def admin_grant_subscription_days(
    request: Request,
    payload: AdminGrantSubReq,
    x_admin_token: Optional[str] = Header(default=None),
):
    require_admin(request, x_admin_token)
    days = int(payload.days)
    if days <= 0:
        raise HTTPException(status_code=400, detail="days_must_be_positive")

    con = db()
    cur = con.cursor()
    cur.execute("SELECT id, subscription_expiry FROM users WHERE email=%s", (payload.email.lower().strip(),))
    row = cur.fetchone()
    if not row:
        cur.close()
        con.close()
        raise HTTPException(status_code=404, detail="user_not_found")
    user_id, expiry = row

    base = expiry if expiry and expiry > now_utc() else now_utc()
    new_expiry = base + timedelta(days=days)

    cur.execute("UPDATE users SET subscription_expiry=%s WHERE id=%s", (new_expiry, user_id))
    cur.execute(
        "INSERT INTO wallet_ledger(user_id, delta_cents, reason, meta) VALUES(%s,%s,%s,%s)",
        (user_id, 0, payload.reason, json.dumps({"days": days, "admin": True})),
    )
    con.commit()
    cur.close()
    con.close()
    return {"ok": True, "email": payload.email.lower().strip(), "subscription_expiry": new_expiry.isoformat()}


@app.post("/admin/api/reset_device")
def admin_reset_device(
    request: Request,
    payload: AdminUserReq,
    x_admin_token: Optional[str] = Header(default=None),
):
    require_admin(request, x_admin_token)

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE users SET device_hwid=NULL WHERE email=%s RETURNING id", (payload.email.lower().strip(),))
    row = cur.fetchone()
    if not row:
        cur.close()
        con.close()
        raise HTTPException(status_code=404, detail="user_not_found")
    user_id = row[0]
    cur.execute(
        "INSERT INTO wallet_ledger(user_id, delta_cents, reason, meta) VALUES(%s,%s,%s,%s)",
        (user_id, 0, "reset_device", json.dumps({"admin": True})),
    )
    con.commit()
    cur.close()
    con.close()
    return {"ok": True}


# =========================
# AI helpers
# =========================
def _extract_json(txt: str) -> Any:
    txt = (txt or "").strip()
    # Если модель вдруг обернула в текст — попробуем вытащить { ... }
    m = re.search(r"\{.*\}", txt, flags=re.S)
    if m:
        txt = m.group(0)
    return json.loads(txt)


class AIScoreItem(BaseModel):
    id: str
    text: str


class AIScoreReq(BaseModel):
    prompt: str
    min_score: int = 60
    items: List[AIScoreItem]


@app.get("/api/ai/ping")
def ai_ping():
    return {"ok": True}


def _subscription_active(expiry: Optional[datetime]) -> bool:
    if not expiry:
        return False
    return expiry > now_utc()


@app.post("/api/ai/score")
def ai_score(req: AIScoreReq, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    # 1) auth
    user = get_user_from_auth(authorization)

    # 2) subscription check
    if not _subscription_active(user.get("subscription_expiry")):
        raise HTTPException(status_code=403, detail="subscription_expired")

    # 3) compute cost
    items_count = len(req.items or [])
    if items_count <= 0:
        return {"results": []}
    cost_cents = items_count * max(0, AI_PRICE_PER_ITEM_CENTS)

    # 4) deduct balance atomically (and log)
    con = db()
    try:
        cur = con.cursor()
        cur.execute("BEGIN")
        cur.execute("SELECT ai_balance_cents FROM users WHERE id=%s FOR UPDATE", (user["id"],))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="user_not_found")
        balance = int(row[0])

        if balance < cost_cents:
            con.rollback()
            raise HTTPException(status_code=402, detail="no_balance")

        cur.execute("UPDATE users SET ai_balance_cents = ai_balance_cents - %s WHERE id=%s", (cost_cents, user["id"]))
        cur.execute(
            "INSERT INTO wallet_ledger(user_id, delta_cents, reason, meta) VALUES(%s,%s,%s,%s)",
            (user["id"], -cost_cents, "ai_charge", json.dumps({"items": items_count, "price_per_item": AI_PRICE_PER_ITEM_CENTS})),
        )
        con.commit()
        cur.close()
    except HTTPException:
        raise
    except Exception as e:
        try:
            con.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"billing_error: {type(e).__name__}: {e}")
    finally:
        con.close()

    # 5) call OpenAI
    try:
        client = get_openai_client()

        items = [{"id": it.id, "text": (it.text or "")[:1200]} for it in req.items]

        system_prompt = (
            "Ты анализируешь сообщения пользователей Telegram на русском языке.\n"
            "Я дам промт (кого ищем) и тексты сообщений людей.\n"
            "Верни СТРОГО валидный JSON (без markdown, без пояснений) строго в формате:\n"
            "{ \"results\": [ {\"id\":\"...\",\"score\":0-100,\"pass\":true/false,"
            "\"reason\":\"коротко 5-12 слов\",\"flags\":[\"bot_like|spam_like|toxic|low_quality\"...]}, ... ] }\n"
            "Правило pass: true если score >= min_score и нет flags bot_like/spam_like/toxic.\n"
            "Reason на русском."
        )

        payload = {"prompt": req.prompt, "min_score": req.min_score, "items": items}

        resp = client.responses.create(
            model="gpt-4.1-mini",
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
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
        # 6) если AI упал — делаем возврат средств (best effort)
        try:
            con2 = db()
            cur2 = con2.cursor()
            cur2.execute("UPDATE users SET ai_balance_cents = ai_balance_cents + %s WHERE id=%s", (cost_cents, user["id"]))
            cur2.execute(
                "INSERT INTO wallet_ledger(user_id, delta_cents, reason, meta) VALUES(%s,%s,%s,%s)",
                (user["id"], cost_cents, "ai_refund", json.dumps({"error": f"{type(e).__name__}: {str(e)[:200]}"})),
            )
            con2.commit()
            cur2.close()
            con2.close()
        except Exception:
            pass

        raise HTTPException(status_code=500, detail=f"AI error: {type(e).__name__}: {e}")
