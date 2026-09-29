import os
import re
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, abort
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import markdown as md
import nh3

import db as database
from storage import make_storage

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
UPLOAD_DIR = os.path.join(INSTANCE_DIR, "uploads")
DB_PATH = os.path.join(INSTANCE_DIR, "studyvault.db")

os.makedirs(INSTANCE_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}
MAX_CONTENT_LENGTH = 8 * 1024 * 1024  # 8MB

IS_PRODUCTION = bool(os.environ.get("RENDER")) or os.environ.get("APP_ENV") == "production"

# Markdown -> HTML sanitizado: mantém o que o Markdown gera, remove scripts,
# handlers (onclick...) e URLs perigosas (javascript:).
MD_EXTENSIONS = ["fenced_code", "codehilite", "tables", "nl2br", "sane_lists"]
MD_EXTENSION_CONFIGS = {"codehilite": {"guess_lang": False}}
MD_ATTRIBUTES = {
    **nh3.ALLOWED_ATTRIBUTES,
    "span": {"class"},
    "div": {"class"},
    "pre": {"class"},
    "code": {"class"},
    "th": {"align", "style"},
    "td": {"align", "style"},
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_tags(raw: str) -> str:
    seen = []
    for t in (raw or "").split(","):
        t = " ".join(t.strip().lower().split())
        if t and t not in seen:
            seen.append(t)
    return ", ".join(seen)


def create_app():
    app = Flask(__name__)

    secret = os.environ.get("SECRET_KEY")
    if not secret:
        if IS_PRODUCTION:
            raise RuntimeError(
                "SECRET_KEY não definida. Configure a variável de ambiente no Render "
                "(ex: python -c \"import secrets; print(secrets.token_hex(32))\")."
            )
        secret = "dev-only-insecure-key"

    app.config.update(
        SECRET_KEY=secret,
        MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=IS_PRODUCTION,
    )
    if IS_PRODUCTION:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    storage = make_storage(UPLOAD_DIR)

    # Schema criado uma vez, na subida do app — não a cada request.
    conn = database.connect(DB_PATH)
    try:
        database.init_db(conn)
    finally:
        conn.close()

    @app.before_request
    def before_request():
        if request.method == "POST":
            token = session.get("_csrf")
            sent = request.form.get("_csrf", "")
            if not token or not secrets.compare_digest(token, sent):
                abort(400, "Formulário expirou. Recarregue a página e tente de novo.")
        g.db = database.connect(DB_PATH)

    @app.teardown_request
    def teardown_request(exception):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def csrf_token():
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        return session["_csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    MONTHS = ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"]

    @app.template_filter("datefmt")
    def datefmt(value):
        if not value:
            return ""
        try:
            d = datetime.fromisoformat(value)
        except ValueError:
            return value[:10]
        return f"{d.day:02d} {MONTHS[d.month - 1]} {d.year}"

    @app.template_filter("reading_time")
    def reading_time(text):
        words = len((text or "").split())
        return max(1, round(words / 200))

    @app.template_filter("taglist")
    def taglist(tags):
        return [t.strip() for t in (tags or "").split(",") if t.strip()]

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
    def render_markdown(text: str) -> str:
        html = md.markdown(
            text or "",
            extensions=MD_EXTENSIONS,
            extension_configs=MD_EXTENSION_CONFIGS,
        )
        return nh3.clean(html, attributes=MD_ATTRIBUTES)

    def user_topics():
        """Tópicos do usuário (com contagem), cacheados por request."""
        if "topics" not in g:
            g.topics = g.db.execute(
                """
                SELECT t.id, t.name,
                       (SELECT COUNT(*) FROM notes n WHERE n.topic_id = t.id) AS notes_count
                FROM topics t
                WHERE t.user_id = ?
                ORDER BY t.created_at ASC
                """,
                (current_user_id(),)
            ).fetchall()
        return g.topics

    @app.context_processor
    def inject_nav():
        if "user_id" in session and "db" in g:
            return {"nav_topics": user_topics()}
        return {}

    def require_owner(row_user_id: int):
        if row_user_id != current_user_id():
            abort(403)

    def get_owned_topic(topic_id: int):
        topic = g.db.execute(
            "SELECT id, user_id, name FROM topics WHERE id = ?",
            (topic_id,)
        ).fetchone()
        if not topic:
            abort(404)
        require_owner(topic["user_id"])
        return topic

    def get_owned_note(note_id: int):
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
        return note

    def note_images(note_id: int):
        return g.db.execute(
            "SELECT id, file_name, created_at FROM images WHERE note_id = ? ORDER BY created_at DESC",
            (note_id,)
        ).fetchall()

    def save_images(note_id: int, files) -> int:
        saved = 0
        for file in files:
            if not file or not file.filename:
                continue

            filename = secure_filename(file.filename)
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext not in ALLOWED_EXTENSIONS:
                continue

            base = re.sub(r"[^a-zA-Z0-9_\-]", "_", filename.rsplit(".", 1)[0])[:40]
            unique_name = f"{note_id}/{base}_{secrets.token_hex(8)}.{ext}"
            storage.save(file, unique_name)

            g.db.execute(
                "INSERT INTO images (note_id, file_name, created_at) VALUES (?, ?, ?)",
                (note_id, unique_name, utcnow())
            )
            saved += 1

        if saved:
            g.db.commit()
        return saved

    def delete_image_files(rows):
        for img in rows:
            storage.delete(img["file_name"])

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
            flash("Preencha email e senha.", "error")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Senha fraca. Use pelo menos 8 caracteres.", "error")
            return redirect(url_for("register"))

        try:
            g.db.execute(
                "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                (email, generate_password_hash(password), utcnow())
            )
            g.db.commit()
        except database.IntegrityError:
            g.db.rollback()
            flash("Esse email já tem um cofre. Entre com ele.", "error")
            return redirect(url_for("login"))

        flash("Cofre criado. Agora é só entrar.", "success")
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
            flash("Email ou senha não conferem.", "error")
            return redirect(url_for("login"))

        session.clear()
        session["user_id"] = user["id"]
        session["email"] = user["email"]
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    def logout():
        session.clear()
        flash("Cofre trancado. Até a próxima.", "success")
        return redirect(url_for("login"))

    # ---------- Dashboard ----------
    @app.get("/dashboard")
    @login_required
    def dashboard():
        user_id = current_user_id()

        topics = user_topics()

        topic_id = request.args.get("topic_id", type=int)
        q = (request.args.get("q") or "").strip()

        # Sem tópico: busca/recentes em todo o cofre. Com tópico: só nele.
        topic_selected = get_owned_topic(topic_id) if topic_id else None

        base_sql = """
            SELECT n.id, n.topic_id, n.title, n.tags, n.created_at, n.updated_at,
                   t.name AS topic_name
            FROM notes n
            JOIN topics t ON t.id = n.topic_id
            WHERE t.user_id = ?
        """
        params = [user_id]
        if topic_selected:
            base_sql += " AND n.topic_id = ?"
            params.append(topic_id)

        if q:
            if q.lower().startswith("tag:"):
                # Match exato da tag: "tag:sql" não pega "mysql"
                tag = normalize_tags(q.split(":", 1)[1]).replace(" ", "")
                base_sql += " AND (',' || REPLACE(LOWER(COALESCE(n.tags,'')), ' ', '') || ',') LIKE ?"
                params.append(f"%,{tag},%")
            else:
                base_sql += " AND (LOWER(n.title) LIKE ? OR LOWER(COALESCE(n.content,'')) LIKE ? OR LOWER(COALESCE(n.tags,'')) LIKE ?)"
                qq = f"%{q.lower()}%"
                params.extend([qq, qq, qq])

        base_sql += " ORDER BY COALESCE(n.updated_at, n.created_at) DESC, n.id DESC"
        if not topic_selected and not q:
            base_sql += " LIMIT 8"
        notes = g.db.execute(base_sql, params).fetchall()

        return render_template(
            "dashboard.html",
            topics=topics,
            notes=notes,
            topic_selected=topic_selected,
            q=q,
            total_notes=sum(t["notes_count"] for t in topics),
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
            flash("Tópico sem nome é caos. Dê um nome.", "error")
            return redirect(url_for("topic_new"))

        row = g.db.execute(
            "INSERT INTO topics (user_id, name, created_at) VALUES (?, ?, ?) RETURNING id",
            (current_user_id(), name, utcnow())
        ).fetchone()
        g.db.commit()
        flash("Tópico criado.", "success")
        return redirect(url_for("dashboard", topic_id=row["id"]))

    @app.get("/topics/<int:topic_id>/edit")
    @login_required
    def topic_edit(topic_id: int):
        topic = get_owned_topic(topic_id)
        return render_template("topic_form.html", mode="edit", topic=topic)

    @app.post("/topics/<int:topic_id>/edit")
    @login_required
    def topic_edit_post(topic_id: int):
        get_owned_topic(topic_id)

        name = (request.form.get("name") or "").strip()
        if not name:
            flash("O tópico precisa de um nome.", "error")
            return redirect(url_for("topic_edit", topic_id=topic_id))

        g.db.execute("UPDATE topics SET name = ? WHERE id = ?", (name, topic_id))
        g.db.commit()
        flash("Tópico atualizado.", "success")
        return redirect(url_for("dashboard", topic_id=topic_id))

    @app.post("/topics/<int:topic_id>/delete")
    @login_required
    def topic_delete(topic_id: int):
        get_owned_topic(topic_id)

        images = g.db.execute(
            """
            SELECT i.file_name
            FROM images i
            JOIN notes n ON n.id = i.note_id
            WHERE n.topic_id = ?
            """,
            (topic_id,)
        ).fetchall()

        g.db.execute("DELETE FROM topics WHERE id = ?", (topic_id,))
        g.db.commit()
        delete_image_files(images)
        flash("Tópico excluído.", "success")
        return redirect(url_for("dashboard"))

    # ---------- Notes CRUD ----------
    @app.get("/topics/<int:topic_id>/notes/new")
    @login_required
    def note_new(topic_id: int):
        topic = get_owned_topic(topic_id)
        return render_template("note_form.html", mode="new", topic=topic, note=None, images=[])

    @app.post("/topics/<int:topic_id>/notes/new")
    @login_required
    def note_new_post(topic_id: int):
        get_owned_topic(topic_id)

        title = " ".join((request.form.get("title") or "").split())
        content = request.form.get("content") or ""
        tags = normalize_tags(request.form.get("tags"))

        if not title:
            flash("Toda nota precisa de um título.", "error")
            return redirect(url_for("note_new", topic_id=topic_id))

        row = g.db.execute(
            """
            INSERT INTO notes (topic_id, title, content, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (topic_id, title, content, tags, utcnow(), None)
        ).fetchone()
        note_id = row["id"]
        g.db.commit()

        saved = save_images(note_id, request.files.getlist("images"))
        if saved:
            flash(f"{saved} imagem(ns) anexada(s).", "success")

        return redirect(url_for("note_view", note_id=note_id))

    @app.get("/notes/<int:note_id>")
    @login_required
    def note_view(note_id: int):
        note = get_owned_note(note_id)
        rendered = render_markdown(note["content"] or "")
        return render_template("note_view.html", note=note, images=note_images(note_id), rendered=rendered)

    @app.get("/notes/<int:note_id>/edit")
    @login_required
    def note_edit(note_id: int):
        note = get_owned_note(note_id)
        topic = {"id": note["topic_id"], "name": note["topic_name"]}
        return render_template("note_form.html", mode="edit", topic=topic, note=note, images=note_images(note_id))

    @app.post("/notes/<int:note_id>/edit")
    @login_required
    def note_edit_post(note_id: int):
        get_owned_note(note_id)

        title = " ".join((request.form.get("title") or "").split())
        content = request.form.get("content") or ""
        tags = normalize_tags(request.form.get("tags"))

        if not title:
            flash("Título vazio? Aí não.", "error")
            return redirect(url_for("note_edit", note_id=note_id))

        g.db.execute(
            "UPDATE notes SET title = ?, content = ?, tags = ?, updated_at = ? WHERE id = ?",
            (title, content, tags, utcnow(), note_id)
        )
        g.db.commit()

        saved = save_images(note_id, request.files.getlist("images"))
        if saved:
            flash(f"{saved} imagem(ns) anexada(s).", "success")

        flash("Nota guardada.", "success")
        return redirect(url_for("note_view", note_id=note_id))

    @app.post("/notes/<int:note_id>/delete")
    @login_required
    def note_delete(note_id: int):
        note = get_owned_note(note_id)
        images = note_images(note_id)

        g.db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        g.db.commit()
        delete_image_files(images)
        flash("Nota excluída.", "success")
        return redirect(url_for("dashboard", topic_id=note["topic_id"]))

    # ---------- Images ----------
    @app.get("/images/<int:image_id>")
    @login_required
    def image_file(image_id: int):
        row = g.db.execute(
            """
            SELECT i.file_name, t.user_id
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
        return storage.serve(row["file_name"])

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

        g.db.execute("DELETE FROM images WHERE id = ?", (image_id,))
        g.db.commit()
        storage.delete(row["file_name"])
        flash("Imagem removida.", "success")
        return redirect(url_for("note_edit", note_id=row["note_id"]))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=not IS_PRODUCTION)
