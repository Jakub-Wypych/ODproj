import sqlite3

DATABASE = "database/sqlite3.db"

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Dzięki temu będziesz mógł używać nazw kolumn jak słowników
    return db

def init_db():
    db = get_db()
    sql = db.cursor()

    sql.execute("DROP TABLE IF EXISTS user")
    sql.execute("DROP TABLE IF EXISTS notes")
    sql.execute("DROP TABLE IF EXISTS login_attempts")

    # Tworzenie tabeli użytkowników
    sql.execute("""
        CREATE TABLE IF NOT EXISTS user (
            username VARCHAR(32) PRIMARY KEY,
            password VARCHAR(128) NOT NULL,
            secret VARCHAR(128)  -- Sekretny klucz do 2FA
        );
    """)

    # Tworzenie tabeli login_attempts
    sql.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            ip_address TEXT PRIMARY KEY,
            attempts INTEGER,
            lock_until DATETIME
        );
    """)

    # Tworzenie tabeli notatek
    sql.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(32),
            note TEXT,
            FOREIGN KEY (username) REFERENCES user(username)
        );
    """)

    db.commit()
    db.close()

