import os

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
from flask import Flask, render_template
from config import Config

# Database
from database.db import db, login_manager

# Blueprints
from routes.auth import auth
from routes.dashboard import dashboard
from routes.ai_assistant import ai_assistant
from routes.verification import verification
from routes.email_detector import email_detector
from routes.quarantine import quarantine
from routes.reported import reported
from routes.safe import safe
from routes.url_detector import url_detector
from routes.password_analyzer import password_analyzer
from routes.sms_detector import sms_detector
from routes.qr_scanner import qr_scanner
from routes.history import history
from routes.profile import profile
from routes.settings import settings_bp
from routes.notifications import notifications

# Gmail OAuth (Flask-Dance)
from gmail.oauth import google_bp


# ==========================================================
# Create Flask Application
# ==========================================================

app = Flask(__name__)

app.config.from_object(Config)


# ==========================================================
# Initialize Extensions
# ==========================================================

db.init_app(app)

login_manager.init_app(app)

login_manager.login_view = "auth.login"

app.register_blueprint(
    google_bp,
    url_prefix="/login"
)
# ==========================================================
# Register Blueprints
# ==========================================================

app.register_blueprint(auth)

app.register_blueprint(dashboard)

app.register_blueprint(ai_assistant)

app.register_blueprint(verification)

app.register_blueprint(quarantine)

app.register_blueprint(reported)

app.register_blueprint(safe)

app.register_blueprint(url_detector)

app.register_blueprint(password_analyzer)

app.register_blueprint(sms_detector)

app.register_blueprint(qr_scanner)

app.register_blueprint(history)

app.register_blueprint(profile)

app.register_blueprint(settings_bp)

app.register_blueprint(notifications)

# Google Gmail Login
app.register_blueprint(email_detector)

from routes.email_actions import email_actions

app.register_blueprint(email_actions)

# ==========================================================
# Gmail Success Route
# ==========================================================


# ==========================================================
# Home Route
# ==========================================================

@app.route("/")
def home():

    return render_template("index.html")


# ==========================================================
# Create Database Tables
# ==========================================================
from database.email_models import *
from models.scan_history import *
from models.user_settings import *
from models.notification import *

with app.app_context():

    db.create_all()

    # Lightweight, idempotent schema helper: adds the `details`
    # column to an existing scan_history table without requiring
    # a delete of guardianx.db.
    from models.scan_history import (
        migrate_add_details_column
    )

    migrate_add_details_column()


# ==========================================================
# Run Application
# ==========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )