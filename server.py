import os
from datetime import datetime, timedelta, timezone

import psycopg2
from psycopg2.extras import RealDictCursor

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from starlette.middleware.sessions import SessionMiddleware


app = FastAPI()

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
ADMIN_PANEL_SECRET = os.environ.get("ADMIN_PANEL_SECRET", "change-me-please")


# --- Sessions for web panel ---
app.add_middleware(
    SessionMiddleware,
    secret_key=ADMIN_PANEL_SECRET,
    https_only=True,      # Render uses HTTPS
    same_site="lax",
)

templates = Jinja2Templates(directory="templates")


# -------------------- DB --------------------

def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg2.connect(DATABASE_URL)


def init_db():
    con = db()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        key TEXT PRIMARY KEY,
        hwid TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        note TEXT DEFAULT ''
    );
    """)
    con.commit()
    cur.close()
    con.close()


@app.on_event("startup")
def on_startup():
    init_db()


def _is_admin(request: Request) -> bool:
    return bool(request.session.get("is_admin"))


def _require_admin(request: Request):
    if not _is_admin(request):
        raise HTTPException(status_code=401, detail="not_logged_in")


# -------------------- API --------------------

class CheckReq(BaseModel):
    key: str
    hwid: str


@app.post("/api/check")
def check(req: CheckReq):
    con = db()
    cur = con.cursor()
    cur.execute("SELECT key, hwid, expires_at, revoked FROM licenses WHERE key=%s", (req.key,))
    row = cur.fetchone()
    cur.close()
    con.close()

    if not row:
        raise HTTPException(status_code=401, detail="key_not_found")

    _key, _hwid, expires_at, revoked = row

    if revoked:
        raise HTTPException(status_code=403, detail="revoked")
    if _hwid != req.hwid:
        raise HTTPException(status_code=403, detail="hwid_mismatch")

    now = datetime.now(timezone.utc)
    if now > expires_at:
        raise HTTPException(status_code=403, detail="expired")

    return {"ok": True, "expires_at": expires_at.isoformat()}


class UpsertReq(BaseModel):
    admin_token: str
    key: str
    hwid: str
    days: int
    note: str = ""


@app.post("/api/admin/upsert")
def admin_upsert(req: UpsertReq):
    if not ADMIN_TOKEN or req.admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="bad_admin_token")

    expires_at = datetime.now(timezone.utc) + timedelta(days=req.days)

    con = db()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO licenses(key, hwid, expires_at, revoked, note)
        VALUES (%s, %s, %s, FALSE, %s)
        ON CONFLICT (key) DO UPDATE SET
            hwid=EXCLUDED.hwid,
            expires_at=EXCLUDED.expires_at,
            revoked=FALSE,
            note=EXCLUDED.note
    """, (req.key, req.hwid, expires_at, req.note))
    con.commit()
    cur.close()
    con.close()

    return {"ok": True, "expires_at": expires_at.isoformat()}


class RevokeReq(BaseModel):
    admin_token: str
    key: str


@app.post("/api/admin/revoke")
def admin_revoke(req: RevokeReq):
    if not ADMIN_TOKEN or req.admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="bad_admin_token")

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=TRUE WHERE key=%s", (req.key,))
    con.commit()
    cur.close()
    con.close()
    return {"ok": True, "revoked": True}


class UnrevokeReq(BaseModel):
    admin_token: str
    key: str


@app.post("/api/admin/unrevoke")
def admin_unrevoke(req: UnrevokeReq):
    if not ADMIN_TOKEN or req.admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="bad_admin_token")

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=FALSE WHERE key=%s", (req.key,))
    con.commit()
    cur.close()
    con.close()
    return {"ok": True, "revoked": False}


# -------------------- WEB PANEL --------------------

@app.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request, q: str = ""):
    if not _is_admin(request):
        return RedirectResponse(url="/admin/login", status_code=303)

    q = (q or "").strip()
    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)

    if q:
        like = f"%{q}%"
        cur.execute("""
            SELECT key, hwid, expires_at, revoked, note
            FROM licenses
            WHERE key ILIKE %s OR hwid ILIKE %s OR note ILIKE %s
            ORDER BY expires_at DESC
            LIMIT 500
        """, (like, like, like))
    else:
        cur.execute("""
            SELECT key, hwid, expires_at, revoked, note
            FROM licenses
            ORDER BY expires_at DESC
            LIMIT 500
        """)

    rows = cur.fetchall()
    cur.close()
    con.close()

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "rows": rows,
            "q": q,
        }
    )


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    if _is_admin(request):
        return RedirectResponse(url="/admin", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": ""})


@app.post("/admin/login")
def admin_login(request: Request, token: str = Form(...)):
    token = token.strip()
    if not ADMIN_TOKEN:
        return templates.TemplateResponse("login.html", {"request": request, "error": "ADMIN_TOKEN не задан в Render."})

    if token != ADMIN_TOKEN:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный токен."})

    request.session["is_admin"] = True
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/logout")
def admin_logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/admin/login", status_code=303)


@app.post("/admin/upsert")
def admin_upsert_form(
    request: Request,
    key: str = Form(...),
    hwid: str = Form(...),
    days: int = Form(...),
    note: str = Form(""),
):
    _require_admin(request)

    expires_at = datetime.now(timezone.utc) + timedelta(days=int(days))

    con = db()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO licenses(key, hwid, expires_at, revoked, note)
        VALUES (%s, %s, %s, FALSE, %s)
        ON CONFLICT (key) DO UPDATE SET
            hwid=EXCLUDED.hwid,
            expires_at=EXCLUDED.expires_at,
            revoked=FALSE,
            note=EXCLUDED.note
    """, (key.strip(), hwid.strip(), expires_at, (note or "").strip()))
    con.commit()
    cur.close()
    con.close()

    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/revoke")
def admin_revoke_form(request: Request, key: str = Form(...)):
    _require_admin(request)
    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=TRUE WHERE key=%s", (key.strip(),))
    con.commit()
    cur.close()
    con.close()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/unrevoke")
def admin_unrevoke_form(request: Request, key: str = Form(...)):
    _require_admin(request)
    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=FALSE WHERE key=%s", (key.strip(),))
    con.commit()
    cur.close()
    con.close()
    return RedirectResponse(url="/admin", status_code=303)
