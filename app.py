import os
import re
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, abort, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import markdown as md


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")

os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

DB_PATH = os.path.join(INSTANCE_DIR, "studyvault.db")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}
MAX_CONTENT_LENGTH = 8 * 1024 * 1024  # 8MB


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-me")
    app.config["DATABASE"] = DB_PATH
    app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    @app.before_request
    def before_request():
        g.db = get_db(app)
        init_db(g.db)

    @app.teardown_request
    def teardown_request(exception):
        db = getattr(g, "db", None)
        if db is not None:
            db.close()

    # ---------- Auth Helpers ----------
    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def current_user_id():
        return session.get("user_id")

    # ---------- Utils ----------
    def allowed_file(filename: str) -> bool:
        if "." not in filename:
            return False
        ext = filename.rsplit(".", 1)[1].lower()
        return ext in ALLOWED_EXTENSIONS

    def safe_markdown(text: str) -> str:
        """
        Markdown -> HTML.
        Para MVP/portfólio, usamos Markdown padrão.
        Observação: não é sanitizado contra HTML malicioso. Para produção real,
        use uma sanitização (ex: bleach) e desabilite HTML.
        """
        return md.markdown(
            text or "",
            extensions=["fenced_code", "codehilite", "tables", "nl2br"]
        )

    def require_owner(row_user_id: int):
        if row_user_id != current_user_id():
            abort(403)

    # ---------- Routes ----------
    @app.get("/")
    def home():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.get("/register")
    def register():
        return render_template("auth_register.html")

    @app.post("/register")
    def register_post():
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email or not password:
            flash("Preenche email e senha, pô.", "error")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Senha fraca. Coloca pelo menos 6 caracteres.", "error")
            return redirect(url_for("register"))

        try:
            g.db.execute(
                "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                (email, generate_password_hash(password), datetime.utcnow().isoformat())
            )
            g.db.commit()
        except sqlite3.IntegrityError:
            flash("Esse email já existe. Faz login.", "error")
            return redirect(url_for("login"))

        flash("Conta criada. Agora entra aí 👇", "success")
        return redirect(url_for("login"))

    @app.get("/login")
    def login():
        return render_template("auth_login.html")

    @app.post("/login")
    def login_post():
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        user = g.db.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Email ou senha errados.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["email"] = user["email"]
        return redirect(url_for("dashboard"))

    @app.get("/logout")
    def logout():
        session.clear()
        flash("Saiu. Volta logo 😌", "success")
        return redirect(url_for("login"))

    # ---------- Dashboard ----------
    @app.get("/dashboard")
    @login_required
    def dashboard():
        user_id = current_user_id()

        topics = g.db.execute(
            """
            SELECT t.id, t.name,
                   (SELECT COUNT(*) FROM notes n WHERE n.topic_id = t.id) AS notes_count
            FROM topics t
            WHERE t.user_id = ?
            ORDER BY t.created_at DESC
            """,
            (user_id,)
        ).fetchall()

        topic_id = request.args.get("topic_id", type=int)
        q = (request.args.get("q") or "").strip()

        notes = []
        topic_selected = None
        if topic_id:
            topic_selected = g.db.execute(
                "SELECT id, user_id, name FROM topics WHERE id = ?",
                (topic_id,)
            ).fetchone()
            if topic_selected:
                require_owner(topic_selected["user_id"])

                base_sql = """
                    SELECT id, topic_id, title, tags, created_at, updated_at
                    FROM notes
                    WHERE topic_id = ?
                """
                params = [topic_id]

                if q:
                    if q.lower().startswith("tag:"):
                        tag = q.split(":", 1)[1].strip().lower()
                        base_sql += " AND LOWER(COALESCE(tags,'')) LIKE ?"
                        params.append(f"%{tag}%")
                    else:
                        base_sql += " AND (LOWER(title) LIKE ? OR LOWER(COALESCE(content,'')) LIKE ? OR LOWER(COALESCE(tags,'')) LIKE ?)"
                        qq = f"%{q.lower()}%"
                        params.extend([qq, qq, qq])

                base_sql += " ORDER BY COALESCE(updated_at, created_at) DESC"
                notes = g.db.execute(base_sql, params).fetchall()

        return render_template(
            "dashboard.html",
            topics=topics,
            notes=notes,
            topic_selected=topic_selected
        )

    # ---------- Topics CRUD ----------
    @app.get("/topics/new")
    @login_required
    def topic_new():
        return render_template("topic_form.html", mode="new", topic=None)

    @app.post("/topics/new")
    @login_required
    def topic_new_post():
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Tópico sem nome é caos. Dá um nome aí.", "error")
            return redirect(url_for("topic_new"))

        g.db.execute(
            "INSERT INTO topics (user_id, name, created_at) VALUES (?, ?, ?)",
            (current_user_id(), name, datetime.utcnow().isoformat())
        )
        g.db.commit()
        flash("Tópico criado ✅", "success")
        return redirect(url_for("dashboard"))

    @app.get("/topics/<int:topic_id>/edit")
    @login_required
    def topic_edit(topic_id: int):
        topic = g.db.execute(
            "SELECT id, user_id, name FROM topics WHERE id = ?",
            (topic_id,)
        ).fetchone()
        if not topic:
            abort(404)
        require_owner(topic["user_id"])
        return render_template("topic_form.html", mode="edit", topic=topic)

    @app.post("/topics/<int:topic_id>/edit")
    @login_required
    def topic_edit_post(topic_id: int):
        topic = g.db.execute(
            "SELECT id, user_id, name FROM topics WHERE id = ?",
            (topic_id,)
        ).fetchone()
        if not topic:
            abort(404)
        require_owner(topic["user_id"])

        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Bota um nome decente pro tópico.", "error")
            return redirect(url_for("topic_edit", topic_id=topic_id))

        g.db.execute("UPDATE topics SET name = ? WHERE id = ?", (name, topic_id))
        g.db.commit()
        flash("Tópico atualizado ✨", "success")
        return redirect(url_for("dashboard", topic_id=topic_id))

    @app.post("/topics/<int:topic_id>/delete")
    @login_required
    def topic_delete(topic_id: int):
        topic = g.db.execute(
            "SELECT id, user_id FROM topics WHERE id = ?",
            (topic_id,)
        ).fetchone()
        if not topic:
            abort(404)
        require_owner(topic["user_id"])

        images = g.db.execute(
            """
            SELECT i.file_name
            FROM images i
            JOIN notes n ON n.id = i.note_id
            WHERE n.topic_id = ?
            """,
            (topic_id,)
        ).fetchall()
        for img in images:
            try:
                os.remove(os.path.join(app.config["UPLOAD_FOLDER"], img["file_name"]))
            except FileNotFoundError:
                pass

        g.db.execute("DELETE FROM topics WHERE id = ?", (topic_id,))
        g.db.commit()
        flash("Tópico deletado 🗑️", "success")
        return redirect(url_for("dashboard"))

    # ---------- Notes CRUD ----------
    @app.get("/topics/<int:topic_id>/notes/new")
    @login_required
    def note_new(topic_id: int):
        topic = g.db.execute(
            "SELECT id, user_id, name FROM topics WHERE id = ?",
            (topic_id,)
        ).fetchone()
        if not topic:
            abort(404)
        require_owner(topic["user_id"])
        return render_template("note_form.html", mode="new", topic=topic, note=None, images=[])

    @app.post("/topics/<int:topic_id>/notes/new")
    @login_required
    def note_new_post(topic_id: int):
        topic = g.db.execute(
            "SELECT id, user_id, name FROM topics WHERE id = ?",
            (topic_id,)
        ).fetchone()
        if not topic:
            abort(404)
        require_owner(topic["user_id"])

        title = (request.form.get("title") or "").strip()
        content = request.form.get("content") or ""
        tags = (request.form.get("tags") or "").strip()

        if not title:
            flash("Sem título não dá. Coloca um.", "error")
            return redirect(url_for("note_new", topic_id=topic_id))

        cur = g.db.execute(
            """
            INSERT INTO notes (topic_id, title, content, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (topic_id, title, content, tags, datetime.utcnow().isoformat(), None)
        )
        note_id = cur.lastrowid
        g.db.commit()

        files = request.files.getlist("images")
        saved = save_images(app, g.db, note_id, files)
        if saved:
            flash(f"{saved} imagem(ns) anexada(s) 📎", "success")

        return redirect(url_for("note_view", note_id=note_id))

    @app.get("/notes/<int:note_id>")
    @login_required
    def note_view(note_id: int):
        note = g.db.execute(
            """
            SELECT n.id, n.topic_id, n.title, n.content, n.tags, n.created_at, n.updated_at,
                   t.user_id, t.name AS topic_name
            FROM notes n
            JOIN topics t ON t.id = n.topic_id
            WHERE n.id = ?
            """,
            (note_id,)
        ).fetchone()
        if not note:
            abort(404)
        require_owner(note["user_id"])

        images = g.db.execute(
            "SELECT id, file_name, created_at FROM images WHERE note_id = ? ORDER BY created_at DESC",
            (note_id,)
        ).fetchall()

        rendered = safe_markdown(note["content"] or "")
        return render_template("note_view.html", note=note, images=images, rendered=rendered)

    @app.get("/notes/<int:note_id>/edit")
    @login_required
    def note_edit(note_id: int):
        note = g.db.execute(
            """
            SELECT n.id, n.topic_id, n.title, n.content, n.tags,
                   t.user_id, t.name AS topic_name
            FROM notes n
            JOIN topics t ON t.id = n.topic_id
            WHERE n.id = ?
            """,
            (note_id,)
        ).fetchone()
        if not note:
            abort(404)
        require_owner(note["user_id"])

        images = g.db.execute(
            "SELECT id, file_name, created_at FROM images WHERE note_id = ? ORDER BY created_at DESC",
            (note_id,)
        ).fetchall()

        topic = {"id": note["topic_id"], "name": note["topic_name"]}
        return render_template("note_form.html", mode="edit", topic=topic, note=note, images=images)

    @app.post("/notes/<int:note_id>/edit")
    @login_required
    def note_edit_post(note_id: int):
        note = g.db.execute(
            """
            SELECT n.id, n.topic_id, t.user_id
            FROM notes n
            JOIN topics t ON t.id = n.topic_id
            WHERE n.id = ?
            """,
            (note_id,)
        ).fetchone()
        if not note:
            abort(404)
        require_owner(note["user_id"])

        title = (request.form.get("title") or "").strip()
        content = request.form.get("content") or ""
        tags = (request.form.get("tags") or "").strip()

        if not title:
            flash("Título vazio? Aí não.", "error")
            return redirect(url_for("note_edit", note_id=note_id))

        g.db.execute(
            "UPDATE notes SET title = ?, content = ?, tags = ?, updated_at = ? WHERE id = ?",
            (title, content, tags, datetime.utcnow().isoformat(), note_id)
        )
        g.db.commit()

        files = request.files.getlist("images")
        saved = save_images(app, g.db, note_id, files)
        if saved:
            flash(f"{saved} imagem(ns) anexada(s) 📎", "success")

        flash("Nota atualizada ✅", "success")
        return redirect(url_for("note_view", note_id=note_id))

    @app.post("/notes/<int:note_id>/delete")
    @login_required
    def note_delete(note_id: int):
        note = g.db.execute(
            """
            SELECT n.id, n.topic_id, t.user_id
            FROM notes n
            JOIN topics t ON t.id = n.topic_id
            WHERE n.id = ?
            """,
            (note_id,)
        ).fetchone()
        if not note:
            abort(404)
        require_owner(note["user_id"])

        images = g.db.execute(
            "SELECT file_name FROM images WHERE note_id = ?",
            (note_id,)
        ).fetchall()
        for img in images:
            try:
                os.remove(os.path.join(app.config["UPLOAD_FOLDER"], img["file_name"]))
            except FileNotFoundError:
                pass

        g.db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        g.db.commit()
        flash("Nota deletada 🗑️", "success")
        return redirect(url_for("dashboard", topic_id=note["topic_id"]))

    # ---------- Images ----------
    @app.get("/uploads/<path:filename>")
    @login_required
    def uploaded_file(filename):
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

    @app.post("/images/<int:image_id>/delete")
    @login_required
    def image_delete(image_id: int):
        row = g.db.execute(
            """
            SELECT i.id, i.note_id, i.file_name, t.user_id
            FROM images i
            JOIN notes n ON n.id = i.note_id
            JOIN topics t ON t.id = n.topic_id
            WHERE i.id = ?
            """,
            (image_id,)
        ).fetchone()
        if not row:
            abort(404)
        require_owner(row["user_id"])

        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], row["file_name"]))
        except FileNotFoundError:
            pass

        g.db.execute("DELETE FROM images WHERE id = ?", (image_id,))
        g.db.commit()
        flash("Imagem removida 🧼", "success")
        return redirect(url_for("note_edit", note_id=row["note_id"]))

    return app


# ---------- DB ----------
def get_db(app: Flask):
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def column_exists(db: sqlite3.Connection, table: str, column: str) -> bool:
    cols = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(c["name"] == column for c in cols)


def init_db(db: sqlite3.Connection):
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT,
            tags TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (topic_id) REFERENCES topics(id) ON DELETE CASCADE
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            note_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE
        )
        """
    )
    db.commit()

    # Migration safety: if DB existed pre-tags
    if not column_exists(db, "notes", "tags"):
        db.execute("ALTER TABLE notes ADD COLUMN tags TEXT")
        db.commit()


# ---------- Upload ----------
def save_images(app: Flask, db: sqlite3.Connection, note_id: int, files) -> int:
    saved = 0
    for file in files:
        if not file or not file.filename:
            continue

        filename = secure_filename(file.filename)
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in {"png", "jpg", "jpeg", "webp", "gif"}:
            continue

        stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        base = re.sub(r"[^a-zA-Z0-9_\-]", "_", filename.rsplit(".", 1)[0])[:50]
        unique_name = f"{base}_{note_id}_{stamp}.{ext}"

        out_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
        file.save(out_path)

        db.execute(
            "INSERT INTO images (note_id, file_name, created_at) VALUES (?, ?, ?)",
            (note_id, unique_name, datetime.utcnow().isoformat())
        )
        saved += 1

    if saved:
        db.commit()
    return saved


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
