import hashlib

from flask import render_template, request, redirect, url_for, flash
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
        sql.execute("""
                    SELECT id, note, is_public, is_shared, is_encrypted, username
                    FROM notes 
                    WHERE username = ? OR is_public = 1
                """, (username,))
        notes = sql.fetchall()

        db.close()
        return render_template("hello.html", username=username, notes=notes)

    @app.route("/render", methods=["POST"])
    @login_required
    def render():
        md = request.form.get("markdown", "")
        password = request.form.get("password_enc", "")
        is_public = request.form.get("is_public", "0") == "1"

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
        fingerprint = generate_fingerprint(cleaned_rendered, username)
        isencrypted = False
        if password:
            # Szyfrowanie notatki przed zapisaniem
            cleaned_rendered = encrypt_note(cleaned_rendered, password)
            isencrypted = True
        db = get_db()
        sql = db.cursor()
        sql.execute("INSERT INTO notes (username, note, fingerprint, is_encrypted, is_public, author) VALUES (?, ?, ?, ?, ?, ?)", (username, cleaned_rendered, fingerprint, isencrypted, is_public, username))
        db.commit()
        # Uzyskanie ID ostatnio wstawionej notatki
        note_id = sql.lastrowid
        db.close()
        return render_template("markdown.html", rendered=cleaned_rendered, fingerprint=fingerprint, note_id=note_id, author=username)

    def generate_fingerprint(content, username):
        """Generuje unikalny fingerprint na podstawie treści i nazwy użytkownika."""
        data = f"{username}:{content}"
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @app.route("/render/<int:rendered_id>", methods=["POST"])
    @login_required
    def render_old(rendered_id):
        password = request.form.get("password", "")  # Pobranie hasła z formularza
        db = get_db()
        sql = db.cursor()
        sql.execute("SELECT username, note, fingerprint, is_encrypted, is_public, author FROM notes WHERE id = ?", (rendered_id,))
        row = sql.fetchone()
        db.close()

        if row:
            username, rendered, fingerprint, isencrypted, ispublic, author = row
            if not ispublic:
                if username != current_user.id:
                    return "Access to note forbidden", 403
            if isencrypted:
                try:
                    rendered = decrypt_note(rendered, password)
                except Exception as e:
                    flash(f"Błąd odszyfrowania", "danger")
                    return redirect(url_for("hello"))
            # Oczyszczanie starej notatki
            cleaned_rendered = bleach.clean(rendered,
                                            tags=['b', 'i', 'u', 'em', 'strong', 'a', 'img', 'h1', 'h2', 'h3',
                                                        'h4', 'h5', 'h6', 'p', 'ul', 'ol', 'li', 'code'],
                                            attributes={'a': ['href', 'title'],
                                                        'img': ['src', 'alt', 'width', 'height']})
            return render_template("markdown.html", rendered=cleaned_rendered, fingerprint=fingerprint, note_id=rendered_id, author=author)

        return "Note not found", 404

    @app.route("/share_note/<int:note_id>", methods=["POST"])
    @login_required
    def share_note(note_id):
        db = get_db()
        sql = db.cursor()

        sql.execute("SELECT username, is_public, fingerprint FROM notes WHERE id = ?", (note_id,))
        row = sql.fetchone()
        if row:
            note_owner = row['username']
            is_public = row['is_public']
            fingerprint = row['fingerprint']

            if note_owner != current_user.id:
                flash("Nie masz dostępu do tej notatki", "danger")
                return redirect(url_for('hello'))

            # Jeśli notatka jest publiczna, nie można jej udostępniać
            if is_public:
                flash("Notatka jest publiczna, więc nie może być udostępniona", "danger")
                return redirect(url_for('hello'))
        else:
            flash("Notatka nie istnieje", "danger")
            return redirect(url_for('hello'))

        # Sprawdzamy, czy użytkownik podał nazwę użytkownika, któremu chce udostępnić notatkę
        shared_with_user = request.form.get("shared_with_user")
        if not shared_with_user:
            flash("Podaj nazwę użytkownika, któremu chcesz udostępnić notatkę", "danger")
            return redirect(url_for('hello'))

        # Sprawdzamy, czy użytkownik istnieje
        sql.execute("SELECT username FROM user WHERE username = ?", (shared_with_user,))
        if not sql.fetchone():
            flash("Użytkownik nie istnieje", "danger")
            return redirect(url_for('hello'))

        # Sprawdzamy, czy użytkownik już posiada notatkę o tym samym fingerprint
        sql.execute("""
            SELECT id FROM notes 
            WHERE username = ? AND fingerprint = ?
        """, (shared_with_user, fingerprint))
        if sql.fetchone():
            flash("Użytkownik już posiada taką samą notatkę", "danger")
            return redirect(url_for('hello'))

        # Tworzymy kopię notatki dla udostępnionego użytkownika
        sql.execute("""
            INSERT INTO notes (username, note, fingerprint, is_encrypted, is_public, is_shared, author)
            SELECT ?, note, fingerprint, is_encrypted, 0, 1, author
            FROM notes WHERE id = ?
        """, (shared_with_user, note_id))
        db.commit()

        flash("Notatka została udostępniona", "success")
        return redirect(url_for('hello'))

    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import os
    from base64 import b64encode, b64decode

    # Funkcja do generowania klucza AES z hasła
    def generate_key_from_password(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    # Funkcja do szyfrowania notatki
    def encrypt_note(note: str, password: str) -> str:
        salt = os.urandom(16)  # Generowanie soli (random)
        key = generate_key_from_password(password, salt)  # Generowanie klucza z hasła

        # Inicjalizacja IV (wektora inicjującego)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Padding, aby długość notatki była wielokrotnością 16
        padding_length = 16 - len(note) % 16
        padded_note = note + chr(padding_length) * padding_length

        # Szyfrowanie
        encrypted = encryptor.update(padded_note.encode()) + encryptor.finalize()

        # Łączenie soli, IV i zaszyfrowanych danych w jeden ciąg
        return b64encode(salt + iv + encrypted).decode()

    # Funkcja do odszyfrowania notatki
    def decrypt_note(encrypted_note: str, password: str) -> str:
        encrypted_note_bytes = b64decode(encrypted_note)  # Dekodowanie z base64

        # Rozdzielanie soli, IV i zaszyfrowanych danych
        salt = encrypted_note_bytes[:16]
        iv = encrypted_note_bytes[16:32]
        encrypted_data = encrypted_note_bytes[32:]

        key = generate_key_from_password(password, salt)  # Generowanie klucza z hasła
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Odszyfrowanie danych
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()

        # Usuwanie paddingu
        padding_length = ord(decrypted[-1:])
        return decrypted[:-padding_length].decode()
