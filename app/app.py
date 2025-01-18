# app.py
from flask import Flask
from flask_talisman import Talisman
from flask_login import LoginManager
from routes import setup_auth_routes, setup_notes_routes, setup_register_routes
from database import init_db
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

app.config['SERVER_NAME'] = 'localhost'
app.after_request(lambda response: response.headers.pop('Server', None) or response)

csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'"],  # Dopuszczamy inline scripts
    'style-src': ["'self'", "'unsafe-inline'"],   # Dopuszczamy inline styles
    'img-src': ["'self'", 'data:'],               # Dopuszczamy obrazy w formacie data URI
    'font-src': ["'self'"],                       # Dopuszczamy ładowanie czcionek
    'connect-src': ["'self'"],                    # Dopuszczamy połączenia z własnym serwerem
    'frame-src': ["'self'"],                      # Dopuszczamy ramki tylko z tej samej domeny
    'object-src': ["'none'"],                     # Blokujemy wczytywanie obiektów (np. Flash)
    'media-src': ["'self'"],                      # Dopuszczamy media tylko z tej samej domeny
    'child-src': ["'none'"],                      # Blokujemy child frames
    'manifest-src': ["'self'"],                   # Dopuszczamy manifesty tylko z tej samej domeny
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
