import os
import sqlite3
import json

DB_PATH = os.getenv("SQLITE_DB", "notification_service.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            api_key TEXT UNIQUE,
            active INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS students (
            id TEXT PRIMARY KEY,
            nom TEXT NOT NULL,
            email TEXT NOT NULL,
            telephone TEXT,
            langue TEXT,
            faculte TEXT,
            promotion TEXT,
            canal_prefere TEXT,
            actif INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_students_faculte ON students(faculte)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_students_promotion ON students(promotion)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_students_actif ON students(actif)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_students_canal ON students(canal_prefere)")
    conn.commit()
    conn.close()

def _table_empty(conn, table):
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(1) AS c FROM {table}")
    row = cur.fetchone()
    return (row is None) or (row[0] == 0)

def migrate_from_json():
    conn = get_conn()
    cur = conn.cursor()

    try:
        if _table_empty(conn, "users") and os.path.exists("users.json"):
            with open("users.json", "r", encoding="utf-8") as f:
                users = json.load(f)
            for _, u in users.items():
                cur.execute(
                    "INSERT OR IGNORE INTO users(username, password_hash, role, api_key, active) VALUES(?,?,?,?,?)",
                    (
                        u.get("username"),
                        u.get("password_hash"),
                        u.get("role", "viewer"),
                        u.get("api_key"),
                        1 if u.get("active", True) else 0,
                    ),
                )
            conn.commit()

        if _table_empty(conn, "students") and os.path.exists("students.json"):
            with open("students.json", "r", encoding="utf-8") as f:
                students = json.load(f)
            for sid, s in students.items():
                cur.execute(
                    "INSERT OR IGNORE INTO students(id, nom, email, telephone, langue, faculte, promotion, canal_prefere, actif) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        sid,
                        s.get("nom"),
                        s.get("email"),
                        s.get("telephone"),
                        s.get("langue", "fr"),
                        s.get("faculté", ""),
                        s.get("promotion", ""),
                        s.get("canal_prefere", "email"),
                        1 if s.get("actif", True) else 0,
                    ),
                )
            conn.commit()
    finally:
        conn.close()