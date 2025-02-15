import sqlite3

DATABASE = "database/sqlite3.db"

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Dzięki temu będziesz mógł używać nazw kolumn jak słowników
    return db

def init_db():
    db = get_db()
    sql = db.cursor()

    #sql.execute("DROP TABLE IF EXISTS user")
    #sql.execute("DROP TABLE IF EXISTS notes")
    #sql.execute("DROP TABLE IF EXISTS login_attempts")
    #sql.execute("DROP TABLE IF EXISTS user_login_ips")

    # Tworzenie tabeli użytkowników
    sql.execute("""
        CREATE TABLE IF NOT EXISTS user (
            username VARCHAR(32) PRIMARY KEY,
            password VARCHAR(128) NOT NULL,
            two_factor_secret TEXT  -- Sekretny klucz do 2FA
        );
    """)

    # Tworzenie tabeli notatek
    sql.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(32),
            note TEXT,
            fingerprint TEXT,
            is_encrypted BOOLEAN DEFAULT 0,
            is_public BOOLEAN DEFAULT 0,
            is_shared BOOLEAN DEFAULT 0,
            author TEXT,
            FOREIGN KEY (username) REFERENCES user(username)
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

    # Tworzenie tabeli log ips
    sql.execute("""
        CREATE TABLE IF NOT EXISTS user_login_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(32) NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES user(username)
        );
    """)

    db.commit()
    db.close()

