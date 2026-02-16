import psycopg2
import os

# Строка подключения к твоей базе данных
DATABASE_URL = "postgresql://license_db_frca_user:2t9QnU0st3C0tUqLUEuPvr8z3wteggwj@dpg-d67p9k95pdvs73fjvng-a.frankfurt-postgres.render.com/license_db_frca"

try:
    # Подключаемся к базе
    print("🔄 Подключаюсь к базе данных...")
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    
    # Добавляем колонку
    print("🔄 Добавляю колонку last_login...")
    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;")
    
    # Сохраняем изменения
    conn.commit()
    print("✅ Колонка успешно добавлена!")
    
    # Закрываем соединение
    cur.close()
    conn.close()
    
except Exception as e:
    print(f"❌ Ошибка: {e}")
