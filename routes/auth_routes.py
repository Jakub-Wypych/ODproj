from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user
from passlib.hash import sha256_crypt
from database import get_db
from database.auth import load_user
import re
from datetime import datetime, timedelta

MAX_FAILED_ATTEMPTS = 5  # Maksymalna liczba nieudanych prób logowania
LOCK_TIME = timedelta(minutes=1)  # Czas blokady konta po przekroczeniu liczby prób (15 minut)

def setup_auth_routes(app, login_manager):
    @login_manager.user_loader
    def user_loader(username):
        return load_user(username)

    @login_manager.request_loader
    def request_loader(request):
        username = request.form.get("username")
        return load_user(username)

    @app.route("/", methods=["GET", "POST"])
    def login():
        ip_address = request.remote_addr  # Pobieranie adresu IP użytkownika

        # Sprawdzamy, czy adres IP jest zablokowany
        db = get_db()
        sql = db.cursor()
        sql.execute("SELECT lock_until FROM login_attempts WHERE ip_address = ?", (ip_address,))
        row = sql.fetchone()

        if row:
            lock_until = row["lock_until"]
            if lock_until and datetime.strptime(lock_until, "%Y-%m-%d %H:%M:%S") > datetime.now():
                flash("Twoje konto jest zablokowane. Spróbuj ponownie później.", "danger")
                return render_template("index.html")

        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            user = load_user(username)

            if user and sha256_crypt.verify(password, user.password):
                login_user(user)
                reset_failed_attempts(ip_address)  # Resetujemy liczbę prób po udanym logowaniu
                return redirect(url_for('hello'))

            # Zwiększamy liczbę nieudanych prób dla tego IP
            increment_failed_attempts(ip_address)

            flash("Nieprawidłowy login lub hasło", "danger")
            return redirect(url_for('login'))

        return render_template("index.html")

    @app.route("/logout")
    def logout():
        logout_user()
        return redirect(url_for('login'))

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

    def increment_failed_attempts(ip_address):
        """Zwiększa liczbę nieudanych prób logowania z danego adresu IP"""
        db = get_db()
        sql = db.cursor()

        # Sprawdzamy liczbę prób z tego samego IP
        sql.execute("SELECT attempts, lock_until FROM login_attempts WHERE ip_address = ?", (ip_address,))
        row = sql.fetchone()

        if row:
            attempts, lock_until = row
            if attempts >= MAX_FAILED_ATTEMPTS:
                # Blokujemy adres IP
                lock_until_time = datetime.now() + LOCK_TIME
                sql.execute("UPDATE login_attempts SET attempts = ?, lock_until = ? WHERE ip_address = ?",
                            (attempts + 1, lock_until_time.strftime("%Y-%m-%d %H:%M:%S"), ip_address))
            else:
                # Zwiększamy liczbę prób
                sql.execute("UPDATE login_attempts SET attempts = ? WHERE ip_address = ?", (attempts + 1, ip_address))
        else:
            # Dodajemy nowy wpis o próbie logowania z nowego IP
            sql.execute("INSERT INTO login_attempts (ip_address, attempts) VALUES (?, ?)", (ip_address, 1))

        db.commit()

    def reset_failed_attempts(ip_address):
        """Resetuje liczbę nieudanych prób logowania z danego adresu IP po udanym logowaniu"""
        db = get_db()
        sql = db.cursor()

        # Resetujemy liczbę prób
        sql.execute("UPDATE login_attempts SET attempts = 0, lock_until = NULL WHERE ip_address = ?", (ip_address,))
        db.commit()