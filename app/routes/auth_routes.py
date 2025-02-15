# auth_routes.py
import pyotp
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user
from passlib.hash import sha256_crypt
from database import get_db
from database.auth import load_user
from datetime import datetime, timedelta
import time

MAX_FAILED_ATTEMPTS = 5  # Maksymalna liczba nieudanych prób logowania
LOCK_TIME = timedelta(minutes=1)  # Czas blokady konta po przekroczeniu liczby prób
TIME = 1 # opóźnienie w logowaniu

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
        time.sleep(TIME)

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

        honeypot = request.form.get('login')
        if honeypot:
            flash('Bot detected!', 'error')
            increment_failed_attempts(ip_address)
            return render_template("index.html")

        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            user = load_user(username)

            if user and sha256_crypt.verify(password, user.password):
                if(verify_2fa() == 0):
                    flash("Nieprawidłowy kod 2FA", "danger")
                    increment_failed_attempts(ip_address)
                    return redirect(url_for('login'))
                login_user(user)
                reset_failed_attempts(ip_address)  # Resetujemy liczbę prób po udanym logowaniu
                sql.execute("""
                    INSERT INTO user_login_ips (username, ip_address)
                    VALUES (?, ?)
                """, (username, ip_address))
                db.commit()
                return redirect(url_for('hello'))

            # Zwiększamy liczbę nieudanych prób dla tego IP
            increment_failed_attempts(ip_address)

            flash("Nieprawidłowy login lub hasło", "danger")
            return redirect(url_for('login'))

        return render_template("index.html")

    def verify_2fa():
        username = request.form.get("username")
        two_factor_secret = request.form.get("two_factor_secret")

        # Wczytujemy użytkownika z bazy danych
        db = get_db()
        sql = db.cursor()
        sql.execute("SELECT two_factor_secret FROM user WHERE username = ?", (username,))
        user = sql.fetchone()

        if user and user["two_factor_secret"]:
            totp = pyotp.TOTP(user["two_factor_secret"])

            # Sprawdzamy, czy kod 2FA jest poprawny
            if totp.verify(two_factor_secret):
                return 1
            else:
                return 0

        flash("Nie znaleziono użytkownika lub 2FA jest wyłączone", "danger")
        return redirect(url_for('login'))

    @app.route("/logout")
    def logout():
        logout_user()
        return redirect(url_for('login'))

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