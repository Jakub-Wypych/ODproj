# app.py
from flask import Flask, Talisman
from flask_login import LoginManager
from routes import setup_auth_routes, setup_notes_routes, setup_register_routes
from database import init_db
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

app.config['SERVER_NAME'] = 'localhost'
app.after_request(lambda response: response.headers.pop('Server', None) or response)

# Konfiguracja CSP
csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'"]
}

Talisman(app, content_security_policy=csp)
csrf = CSRFProtect(app)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)

# Initialize database
init_db()

# Setup routes
setup_auth_routes(app, login_manager)  # Trasy logowania
setup_register_routes(app) # Trasy rejestracji
setup_notes_routes(app)  # Trasy związane z notatkami

if __name__ == "__main__":
    app.run("0.0.0.0", 5000)
