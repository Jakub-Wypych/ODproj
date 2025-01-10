from flask import render_template, request
from flask_login import login_required, current_user
from database.models import get_db
import markdown
import bleach

def setup_notes_routes(app):
    @app.route("/hello", methods=["GET"])
    @login_required
    def hello():
        username = current_user.id
        db = get_db()
        sql = db.cursor()
        sql.execute("SELECT id FROM notes WHERE username = ?", (username,))
        notes = sql.fetchall()
        db.close()
        return render_template("hello.html", username=username, notes=notes)

    @app.route("/render", methods=["POST"])
    @login_required
    def render():
        md = request.form.get("markdown", "")
        # Renderowanie Markdown
        rendered = markdown.markdown(md, extensions=['extra', 'fenced_code'])

        # Oczyszczanie wygenerowanego HTML, pozwalamy na pewne tagi
        allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'a', 'img', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'ul', 'ol',
                        'li', 'code']
        allowed_attributes = {
            'a': ['href', 'title'],
            'img': ['src', 'alt', 'width', 'height']  # usuwamy 'onerror'
        }

        # Usuwamy wszelkie niebezpieczne atrybuty, takie jak 'onerror'
        cleaned_rendered = bleach.clean(rendered, tags=allowed_tags, attributes=allowed_attributes)

        username = current_user.id
        db = get_db()
        sql = db.cursor()
        sql.execute("INSERT INTO notes (username, note) VALUES (?, ?)", (username, cleaned_rendered))
        db.commit()
        db.close()
        return render_template("markdown.html", rendered=cleaned_rendered)

    @app.route("/render/<int:rendered_id>")
    @login_required
    def render_old(rendered_id):
        db = get_db()
        sql = db.cursor()
        sql.execute("SELECT username, note FROM notes WHERE id = ?", (rendered_id,))
        row = sql.fetchone()
        db.close()

        if row:
            username, rendered = row
            if username != current_user.id:
                return "Access to note forbidden", 403
            # Oczyszczanie starej notatki
            cleaned_rendered = bleach.clean(rendered, tags=['b', 'i', 'u', 'em', 'strong', 'a', 'img', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'ul', 'ol', 'li', 'code'],
                                           attributes={'a': ['href', 'title'], 'img': ['src', 'alt', 'width', 'height']})
            return render_template("markdown.html", rendered=cleaned_rendered)
        return "Note not found", 404
