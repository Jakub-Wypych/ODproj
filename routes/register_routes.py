# routes/register_routes.py
import base64

import pyotp
import qrcode
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user
from passlib.hash import sha256_crypt
from database import get_db
from database.auth import load_user
import re
from datetime import datetime
from io import BytesIO

def setup_register_routes(app):
    @app.route("/register", methods=["GET", "POST"])
    def register():
        ip_address = request.remote_addr  # Pobranie adresu IP użytkownika
        db = get_db()
        sql = db.cursor()

        # Sprawdzamy, czy IP jest zablokowane
        sql.execute("SELECT lock_until FROM login_attempts WHERE ip_address = ?", (ip_address,))
        record = sql.fetchone()
        if record:
            lock_until = record["lock_until"]
            if lock_until and datetime.strptime(lock_until, "%Y-%m-%d %H:%M:%S") > datetime.now():
                flash("Twoje konto jest zablokowane. Spróbuj ponownie później.", "danger")
                return render_template("register.html")

        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")

            # Sprawdzamy, czy hasła się zgadzają
            if password != confirm_password:
                flash("Hasła muszą być takie same", "danger")
                return redirect(url_for('register'))

            # Sprawdzamy, czy hasło jest wystarczająco silne
            if not is_strong_password(password):
                flash(
                    "Hasło musi mieć co najmniej 8 znaków, zawierać dużą literę, małą literę, cyfrę oraz znak specjalny.",
                    "danger")
                return redirect(url_for('register'))

            # Sprawdzamy, czy użytkownik już istnieje
            sql.execute("SELECT username FROM user WHERE username = ?", (username,))
            if sql.fetchone():
                flash("Użytkownik o takim loginie już istnieje", "danger")
                return redirect(url_for('register'))

            # Haszujemy hasło i zapisujemy nowego użytkownika
            hashed_password = sha256_crypt.hash(password)

            # Tworzymy sekret do 2FA
            totp = pyotp.TOTP(pyotp.random_base32())
            two_factor_secret = totp.secret

            sql.execute("INSERT INTO user (username, password, two_factor_secret) VALUES (?, ?, ?)",
                        (username, hashed_password, two_factor_secret))
            db.commit()

            # Logujemy nowego użytkownika
            user = load_user(username)
            login_user(user)
            flash("Rejestracja zakończona sukcesem!", "success")

            # Generujemy kod QR do Google Authenticator
            uri = totp.provisioning_uri(name=username, issuer_name="Twoje Aplikacja")
            img = qrcode.make(uri)

            # Zapisujemy QR kod w pamięci
            img_io = BytesIO()
            img.save(img_io)
            img_io.seek(0)

            img_base64 = base64.b64encode(img_io.read()).decode('utf-8')

            return render_template("two_factor_setup.html", image=img_base64)

        return render_template("register.html")

    def is_strong_password(password):
        """Sprawdza, czy hasło spełnia zasady bezpieczeństwa."""
        if len(password) <= 8:
            return False
        if not re.search(r"[A-Z]", password):  # Sprawdza, czy jest duża litera
            return False
        if not re.search(r"[a-z]", password):  # Sprawdza, czy jest mała litera
            return False
        if not re.search(r"\d", password):  # Sprawdza, czy jest cyfra
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # Sprawdza, czy jest znak specjalny
            return False
        return True
