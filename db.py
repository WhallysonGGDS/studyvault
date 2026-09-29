"""
Camada de banco.

- Local: SQLite em instance/studyvault.db (zero configuração).
- Produção: Postgres via DATABASE_URL (ex: Supabase, plano gratuito).

As queries do app usam o placeholder "?" do SQLite; aqui ele é traduzido
para "%s" quando o backend é Postgres.
"""
import os
import sqlite3

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
USE_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))

if USE_POSTGRES:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    IntegrityError = psycopg.IntegrityError
    _pool = None
else:
    IntegrityError = sqlite3.IntegrityError


class Database:
    def __init__(self, conn, pooled=False):
        self._conn = conn
        self._pooled = pooled

    def execute(self, sql, params=()):
        if USE_POSTGRES:
            sql = sql.replace("?", "%s")
        return self._conn.execute(sql, params)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        if self._pooled:
            # Encerra a transação aberta por SELECTs antes de devolver ao pool
            self._conn.rollback()
            _pool.putconn(self._conn)
        else:
            self._conn.close()


def connect(sqlite_path: str) -> Database:
    if USE_POSTGRES:
        global _pool
        if _pool is None:
            _pool = ConnectionPool(
                DATABASE_URL,
                min_size=1,
                max_size=5,
                # prepare_threshold=None: compatível com o pooler do Supabase
                kwargs={"row_factory": dict_row, "prepare_threshold": None},
                open=True,
            )
        conn = _pool.getconn()
        return Database(conn, pooled=True)

    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return Database(conn)


_ID = "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY" if USE_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"
_FK = "BIGINT" if USE_POSTGRES else "INTEGER"

SCHEMA = [
    f"""
    CREATE TABLE IF NOT EXISTS users (
        id {_ID},
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    f"""
    CREATE TABLE IF NOT EXISTS topics (
        id {_ID},
        user_id {_FK} NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    f"""
    CREATE TABLE IF NOT EXISTS notes (
        id {_ID},
        topic_id {_FK} NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        content TEXT,
        tags TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT
    )
    """,
    f"""
    CREATE TABLE IF NOT EXISTS images (
        id {_ID},
        note_id {_FK} NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
        file_name TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_topics_user ON topics(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_notes_topic ON notes(topic_id)",
    "CREATE INDEX IF NOT EXISTS idx_images_note ON images(note_id)",
]


def init_db(db: Database):
    for stmt in SCHEMA:
        db.execute(stmt)
    db.commit()

    # Migração: bancos SQLite antigos, criados antes das tags
    if not USE_POSTGRES:
        cols = db.execute("PRAGMA table_info(notes)").fetchall()
        if not any(c["name"] == "tags" for c in cols):
            db.execute("ALTER TABLE notes ADD COLUMN tags TEXT")
            db.commit()
