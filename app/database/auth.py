# database/auth.py
from flask_login import UserMixin
from database.models import get_db

class User(UserMixin):
    pass

def load_user(username):
    if username is None:
        return None
    db = get_db()  # Uzyskujemy połączenie z bazą danych za pomocą get_db
    sql = db.cursor()
    sql.execute("SELECT username, password FROM user WHERE username = ?", (username,))
    row = sql.fetchone()
    db.close()  # Zamykamy połączenie z bazą danych

    if row:
        user = User()
        user.id = row[0]  # username
        user.password = row[1]  # password
        return user
    return None
