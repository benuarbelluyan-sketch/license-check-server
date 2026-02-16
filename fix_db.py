import psycopg2
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://license_db_frca_user:2t9QnU0st3C0tUqLUEuPvr8z3wteggwj@dpg-d67p9k95pdvs73fjvng-a.frankfurt-postgres.render.com/license_db_frca")

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()
cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;")
conn.commit()
cur.close()
conn.close()
print("✅ Колонка добавлена!")
