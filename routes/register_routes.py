from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user
from passlib.hash import sha256_crypt
from database import get_db
from database.auth import load_user
import re
from datetime import datetime, timedelta

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
            db = get_db()
            sql = db.cursor()
            sql.execute("SELECT username FROM user WHERE username = ?", (username,))
            if sql.fetchone():
                flash("Użytkownik o takim loginie już istnieje", "danger")
                return redirect(url_for('register'))

            # Haszujemy hasło i zapisujemy nowego użytkownika
            hashed_password = sha256_crypt.hash(password)
            sql.execute("INSERT INTO user (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()

            # Logujemy nowego użytkownika
            user = load_user(username)
            login_user(user)
            flash("Rejestracja zakończona sukcesem!", "success")
            return redirect(url_for('hello'))

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