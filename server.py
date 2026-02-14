import os
import csv
import io
import secrets
import string
from datetime import datetime, timedelta, timezone

import psycopg2
from psycopg2.extras import RealDictCursor

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, PlainTextResponse
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
    https_only=True,  # Render uses HTTPS
    same_site="lax",
)

templates = Jinja2Templates(directory="templates")


# -------------------- Health / Render port checks --------------------

@app.get("/", response_class=PlainTextResponse)
def root():
    return "OK"

@app.head("/")
def root_head():
    return

@app.head("/admin")
def admin_head():
    return


# -------------------- DB --------------------

def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg2.connect(DATABASE_URL)


def init_db():
    con = db()
    cur = con.cursor()

    # Main table (licenses)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        key TEXT PRIMARY KEY,
        hwid TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        note TEXT DEFAULT '',
        plan TEXT DEFAULT 'custom',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_check_at TIMESTAMPTZ,
        check_count BIGINT NOT NULL DEFAULT 0
    );
    """)

    # Admin audit log (optional but very useful)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS admin_audit (
        id BIGSERIAL PRIMARY KEY,
        ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        action TEXT NOT NULL,
        key TEXT,
        hwid TEXT,
        info TEXT DEFAULT ''
    );
    """)

    con.commit()
    cur.close()
    con.close()


@app.on_event("startup")
def on_startup():
    init_db()


def _now_utc():
    return datetime.now(timezone.utc)


def _audit(action: str, key: str | None = None, hwid: str | None = None, info: str = ""):
    # Audit should never break core flow
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "INSERT INTO admin_audit(action, key, hwid, info) VALUES (%s,%s,%s,%s)",
            (action, key, hwid, info or "")
        )
        con.commit()
        cur.close()
        con.close()
    except Exception:
        pass


def _is_admin(request: Request) -> bool:
    return bool(request.session.get("is_admin"))


def _require_admin(request: Request):
    if not _is_admin(request):
        raise HTTPException(status_code=401, detail="not_logged_in")


def _gen_key(prefix: str = "", groups: int = 3, group_len: int = 4) -> str:
    alphabet = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(alphabet) for _ in range(group_len)) for _ in range(groups)]
    key = "-".join(parts)
    if prefix:
        p = prefix.strip()
        if p and not p.endswith("-"):
            p += "-"
        return p + key
    return key


# -------------------- API (client) --------------------

class CheckReq(BaseModel):
    key: str
    hwid: str


@app.post("/api/check")
def check(req: CheckReq):
    con = db()
    cur = con.cursor()

    cur.execute("SELECT key, hwid, expires_at, revoked FROM licenses WHERE key=%s", (req.key,))
    row = cur.fetchone()

    if not row:
        cur.close()
        con.close()
        raise HTTPException(status_code=401, detail="key_not_found")

    _key, _hwid, expires_at, revoked = row

    # Update stats
    cur.execute("""
        UPDATE licenses
        SET last_check_at = NOW(), check_count = check_count + 1
        WHERE key=%s
    """, (req.key,))
    con.commit()

    cur.close()
    con.close()

    if revoked:
        raise HTTPException(status_code=403, detail="revoked")
    if _hwid != req.hwid:
        raise HTTPException(status_code=403, detail="hwid_mismatch")
    if _now_utc() > expires_at:
        raise HTTPException(status_code=403, detail="expired")

    return {"ok": True, "expires_at": expires_at.isoformat()}


# -------------------- API (admin) --------------------

class UpsertReq(BaseModel):
    admin_token: str
    key: str
    hwid: str
    days: int
    note: str = ""
    plan: str = "custom"


@app.post("/api/admin/upsert")
def admin_upsert(req: UpsertReq):
    if not ADMIN_TOKEN or req.admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="bad_admin_token")

    expires_at = _now_utc() + timedelta(days=req.days)

    con = db()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO licenses(key, hwid, expires_at, revoked, note, plan, created_at, updated_at)
        VALUES (%s, %s, %s, FALSE, %s, %s, NOW(), NOW())
        ON CONFLICT (key) DO UPDATE SET
            hwid=EXCLUDED.hwid,
            expires_at=EXCLUDED.expires_at,
            revoked=FALSE,
            note=EXCLUDED.note,
            plan=EXCLUDED.plan,
            updated_at=NOW()
    """, (req.key.strip(), req.hwid.strip(), expires_at, (req.note or "").strip(), (req.plan or "custom").strip()))
    con.commit()
    cur.close()
    con.close()

    _audit("upsert_api", req.key, req.hwid, f"days={req.days}, plan={req.plan}")
    return {"ok": True, "expires_at": expires_at.isoformat()}


class TokenKeyReq(BaseModel):
    admin_token: str
    key: str


@app.post("/api/admin/revoke")
def admin_revoke(req: TokenKeyReq):
    if not ADMIN_TOKEN or req.admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="bad_admin_token")

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=TRUE, updated_at=NOW() WHERE key=%s", (req.key.strip(),))
    con.commit()
    cur.close()
    con.close()

    _audit("revoke_api", req.key)
    return {"ok": True, "revoked": True}


@app.post("/api/admin/unrevoke")
def admin_unrevoke(req: TokenKeyReq):
    if not ADMIN_TOKEN or req.admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="bad_admin_token")

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=FALSE, updated_at=NOW() WHERE key=%s", (req.key.strip(),))
    con.commit()
    cur.close()
    con.close()

    _audit("unrevoke_api", req.key)
    return {"ok": True, "revoked": False}


# -------------------- WEB PANEL --------------------

@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    if _is_admin(request):
        return RedirectResponse("/admin", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": ""})


@app.post("/admin/login")
def admin_login(request: Request, token: str = Form(...)):
    token = token.strip()

    if not ADMIN_TOKEN:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "ADMIN_TOKEN не задан в Render."}
        )

    if token != ADMIN_TOKEN:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверный токен."}
        )

    request.session["is_admin"] = True
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/logout")
def admin_logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)


def _fetch_stats():
    con = db()
    cur = con.cursor()

    cur.execute("SELECT COUNT(*) FROM licenses")
    total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM licenses WHERE revoked=TRUE")
    revoked = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM licenses WHERE revoked=FALSE AND expires_at > NOW()")
    active = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM licenses WHERE revoked=FALSE AND expires_at <= NOW()")
    expired = cur.fetchone()[0]

    cur.close()
    con.close()
    return {"total": total, "active": active, "revoked": revoked, "expired": expired}


@app.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request, q: str = "", status: str = "all"):
    if not _is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    q = (q or "").strip()
    status = (status or "all").strip().lower()

    where = []
    params = []

    if q:
        like = f"%{q}%"
        where.append("(key ILIKE %s OR hwid ILIKE %s OR note ILIKE %s)")
        params += [like, like, like]

    if status == "active":
        where.append("revoked=FALSE AND expires_at > NOW()")
    elif status == "expired":
        where.append("revoked=FALSE AND expires_at <= NOW()")
    elif status == "revoked":
        where.append("revoked=TRUE")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    cur.execute(f"""
        SELECT key, hwid, expires_at, revoked, note, plan, created_at, updated_at, last_check_at, check_count
        FROM licenses
        {where_sql}
        ORDER BY updated_at DESC
        LIMIT 500
    """, tuple(params))
    rows = cur.fetchall()
    cur.close()
    con.close()

    stats = _fetch_stats()

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "rows": rows,
            "q": q,
            "status": status,
            "stats": stats,
        }
    )


@app.post("/admin/generate_key")
def admin_generate_key(request: Request, prefix: str = Form("")):
    _require_admin(request)
    k = _gen_key(prefix=prefix or "")
    _audit("generate_key_web", k, None, f"prefix={prefix}")
    # Возвращаемся в /admin — ключ можно просто скопировать из логов/формы,
    # или ты можешь вставить его руками в поле KEY.
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/upsert")
def admin_upsert_form(
    request: Request,
    key: str = Form(...),
    hwid: str = Form(...),
    days: int = Form(...),
    note: str = Form(""),
    plan: str = Form("custom"),
):
    _require_admin(request)

    expires_at = _now_utc() + timedelta(days=int(days))

    con = db()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO licenses(key, hwid, expires_at, revoked, note, plan, created_at, updated_at)
        VALUES (%s, %s, %s, FALSE, %s, %s, NOW(), NOW())
        ON CONFLICT (key) DO UPDATE SET
            hwid=EXCLUDED.hwid,
            expires_at=EXCLUDED.expires_at,
            revoked=FALSE,
            note=EXCLUDED.note,
            plan=EXCLUDED.plan,
            updated_at=NOW()
    """, (key.strip(), hwid.strip(), expires_at, (note or "").strip(), (plan or "custom").strip()))
    con.commit()
    cur.close()
    con.close()

    _audit("upsert_web", key, hwid, f"days={days}, plan={plan}")
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/add_days")
def admin_add_days(request: Request, key: str = Form(...), add: int = Form(...)):
    _require_admin(request)
    add = int(add)

    con = db()
    cur = con.cursor()
    # If expired -> extend from NOW, else from current expires_at
    cur.execute("""
        UPDATE licenses
        SET expires_at = CASE
            WHEN expires_at <= NOW() THEN NOW() + (%s || ' days')::interval
            ELSE expires_at + (%s || ' days')::interval
        END,
        updated_at = NOW(),
        revoked = FALSE
        WHERE key = %s
    """, (add, add, key.strip()))
    con.commit()
    cur.close()
    con.close()

    _audit("add_days_web", key, None, f"add={add}")
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/revoke")
def admin_revoke_form(request: Request, key: str = Form(...)):
    _require_admin(request)
    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=TRUE, updated_at=NOW() WHERE key=%s", (key.strip(),))
    con.commit()
    cur.close()
    con.close()

    _audit("revoke_web", key)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/unrevoke")
def admin_unrevoke_form(request: Request, key: str = Form(...)):
    _require_admin(request)
    con = db()
    cur = con.cursor()
    cur.execute("UPDATE licenses SET revoked=FALSE, updated_at=NOW() WHERE key=%s", (key.strip(),))
    con.commit()
    cur.close()
    con.close()

    _audit("unrevoke_web", key)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/delete")
def admin_delete_form(request: Request, key: str = Form(...)):
    _require_admin(request)
    con = db()
    cur = con.cursor()
    cur.execute("DELETE FROM licenses WHERE key=%s", (key.strip(),))
    con.commit()
    cur.close()
    con.close()

    _audit("delete_web", key)
    return RedirectResponse("/admin", status_code=303)


@app.get("/admin/export.csv")
def admin_export_csv(request: Request, status: str = "all"):
    if not _is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)

    status = (status or "all").strip().lower()
    where = ""
    if status == "active":
        where = "WHERE revoked=FALSE AND expires_at > NOW()"
    elif status == "expired":
        where = "WHERE revoked=FALSE AND expires_at <= NOW()"
    elif status == "revoked":
        where = "WHERE revoked=TRUE"

    con = db()
    cur = con.cursor(cursor_factory=RealDictCursor)
    cur.execute(f"""
        SELECT key, hwid, expires_at, revoked, note, plan, created_at, updated_at, last_check_at, check_count
        FROM licenses
        {where}
        ORDER BY updated_at DESC
    """)
    rows = cur.fetchall()
    cur.close()
    con.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "key","hwid","expires_at","revoked","note","plan",
        "created_at","updated_at","last_check_at","check_count"
    ])
    for r in rows:
        writer.writerow([
            r["key"], r["hwid"], r["expires_at"], r["revoked"], r["note"], r["plan"],
            r["created_at"], r["updated_at"], r["last_check_at"], r["check_count"]
        ])

    output.seek(0)
    _audit("export_csv_web", None, None, f"status={status}")
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=licenses_export.csv"}
    )
