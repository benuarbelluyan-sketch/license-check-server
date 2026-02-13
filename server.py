import os
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import psycopg2

app = FastAPI()

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")  # придумай сам
GRACE_DAYS = 7  # на клиенте тоже будет grace, но серверу это не нужно

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

# --- Админ-эндпоинт: добавить/обновить подписку на N дней ---
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
