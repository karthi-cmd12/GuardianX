import os

class Config:

    # -------------------------------------------------
    # Flask Configuration
    # -------------------------------------------------
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "dev-secret-key-change-before-deployment"
    )

    # -------------------------------------------------
    # Database Configuration
    # -------------------------------------------------
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    SQLALCHEMY_DATABASE_URI = (
        "sqlite:///" + os.path.join(BASE_DIR, "guardianx.db")
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # -------------------------------------------------
    # Upload Configuration
    # -------------------------------------------------
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

    # -------------------------------------------------
    # Session Configuration
    # -------------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # -------------------------------------------------
    # GuardianX Branding
    # -------------------------------------------------
    APP_NAME = "GuardianX"

    APP_TAGLINE = "AI-Powered Cybersecurity & Scam Detection Platform"

    COMPANY_NAME = "GuardianX Security"

    VERSION = "1.0.0"

    DEVELOPER = "GuardianX Team"

    COPYRIGHT = "© 2026 GuardianX. All Rights Reserved."