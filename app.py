# app.py
from flask import Flask
from flask_login import LoginManager
from routes import setup_auth_routes, setup_notes_routes
from database import init_db

app = Flask(__name__)
app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)

# Initialize database
init_db()

# Setup routes
setup_auth_routes(app, login_manager)  # Trasy logowania i rejestracji
setup_notes_routes(app)  # Trasy związane z notatkami

if __name__ == "__main__":
    app.run("0.0.0.0", 5000)
