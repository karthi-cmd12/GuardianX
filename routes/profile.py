# ==========================================================
# GuardianX Profile Routes
#
# A user can only ever view and edit their OWN profile.
# All endpoints require login. Every request is validated
# server-side; the frontend is never trusted.
#
# Security notes:
#   - Passwords are never stored or logged in plaintext and
#     never appear in responses.
#   - Duplicate email / mobile are rejected.
#   - Email / mobile change resets their verification flags
#     so a changed contact must be re-verified.
# ==========================================================

import re
from datetime import datetime

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from flask_dance.contrib.google import google

from database.db import db, User
from models.scan_history import ScanHistory
from models.user_settings import get_user_settings
from models.password_analyzer import (
    analyze_password,
    STRONG_MIN,
    MIN_LENGTH,
)


# ==========================================================
# Blueprint
# ==========================================================

profile = Blueprint(
    "profile",
    __name__
)


# ==========================================================
# Validation Helpers
# ==========================================================

EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def _email_valid(value):
    value = str(value or "").strip()

    return bool(value) and len(value) <= 120 and bool(EMAIL_RE.match(value))


def _mobile_valid(value):
    value = str(value or "").strip()

    if not value:
        return True

    digits = re.sub(r"\D", "", value)

    return 10 <= len(digits) <= 15


# ==========================================================
# Data Helpers
# ==========================================================

def _profile_stats():
    """
    GuardianX statistics from the user's own scan history only.
    """
    rows = ScanHistory.query.filter_by(
        user_id=current_user.id
    ).all()

    return {
        "total": len(rows),
        "safe": sum(1 for row in rows if row.risk_level == "LOW"),
        "suspicious": sum(1 for row in rows if row.risk_level == "MEDIUM"),
        "high_risk": sum(1 for row in rows if row.risk_level == "HIGH"),
    }


def _protection_status():
    return {
        "email_verified": bool(current_user.email_verified),
        "mobile_verified": bool(current_user.mobile_verified),
        "gmail_connected": bool(google.authorized),
    }


def _security_status():
    """
    Honest posture derived from real account state, mirroring
    the dashboard scoring without overstating protection.
    """
    score = 30

    if current_user.email_verified:
        score += 25

    if current_user.mobile_verified:
        score += 25

    if google.authorized:
        score += 20

    score = min(score, 100)

    if score >= 80:
        return {"label": "Excellent", "level": "excellent", "score": score}

    if score >= 50:
        return {"label": "Good", "level": "good", "score": score}

    return {"label": "Needs attention", "level": "attention", "score": score}


# ==========================================================
# Profile Page
# ==========================================================

@profile.route("/profile")
@login_required
def profile_home():

    settings = get_user_settings(current_user.id)

    return render_template(
        "profile.html",
        stats=_profile_stats(),
        protection=_protection_status(),
        security=_security_status(),
        settings=settings
    )


# ==========================================================
# Update Personal Information
# ==========================================================

@profile.route(
    "/profile/update",
    methods=["POST"]
)
@login_required
def profile_update():

    data = request.get_json(
        silent=True
    )

    if not data or not isinstance(data, dict):

        return jsonify({
            "error":
            "Request body must be valid JSON."
        }), 400

    full_name = str(data.get("full_name") or "").strip()
    email = str(data.get("email") or "").strip()
    mobile = str(data.get("mobile") or "").strip()

    errors = {}

    if not full_name or len(full_name) < 2 or len(full_name) > 100:
        errors["full_name"] = (
            "Full name must be between 2 and 100 characters."
        )

    if not _email_valid(email):
        errors["email"] = "Please enter a valid email address."

    if not _mobile_valid(mobile):
        errors["mobile"] = (
            "Mobile number must contain 10-15 digits."
        )

    if errors:
        return jsonify({
            "error": "Please correct the highlighted fields.",
            "errors": errors,
        }), 400

    duplicate_email = User.query.filter(
        db.func.lower(User.email) == email.lower(),
        User.id != current_user.id,
    ).first()

    if duplicate_email:
        return jsonify({
            "error":
            "This email is already in use by another account.",
            "errors": {
                "email": "Email already in use.",
            },
        }), 400

    if mobile:
        duplicate_mobile = User.query.filter(
            User.mobile == mobile,
            User.id != current_user.id,
        ).first()

        if duplicate_mobile:
            return jsonify({
                "error":
                "This mobile number is already in use by another account.",
                "errors": {
                    "mobile": "Mobile number already in use.",
                },
            }), 400

    email_changed = email.lower() != (current_user.email or "").lower()
    mobile_changed = mobile != (current_user.mobile or "")

    current_user.full_name = full_name
    current_user.email = email
    current_user.mobile = mobile or None

    if email_changed:
        current_user.email_verified = False
        current_user.email_otp = None

    if mobile_changed:
        current_user.mobile_verified = False
        current_user.mobile_otp = None

    db.session.commit()

    return jsonify({
        "ok": True,
        "message": "Profile updated successfully.",
        "full_name": current_user.full_name,
        "email": current_user.email,
        "mobile": current_user.mobile or "",
        "email_verified": bool(current_user.email_verified),
        "mobile_verified": bool(current_user.mobile_verified),
    })


# ==========================================================
# Change Password
# ==========================================================

@profile.route(
    "/profile/change-password",
    methods=["POST"]
)
@login_required
def change_password():

    data = request.get_json(
        silent=True
    )

    if not data or not isinstance(data, dict):

        return jsonify({
            "error":
            "Request body must be valid JSON."
        }), 400

    current_password = str(data.get("current_password") or "")
    new_password = str(data.get("new_password") or "")
    confirm_password = str(data.get("confirm_password") or "")

    errors = {}

    # ----- Current password -----

    if not current_password:
        errors["current_password"] = "Enter your current password."
    elif not current_user.check_password(current_password):
        errors["current_password"] = "Current password is incorrect."

    # ----- New password strength (existing GuardianX rules) -----

    if not new_password:
        errors["new_password"] = "Enter a new password."
    elif new_password == current_password:
        errors["new_password"] = (
            "New password must be different from your current password."
        )

    if new_password:
        lower = new_password.lower()

        if lower in (
            (current_user.username or "").lower(),
            (current_user.email or "").lower(),
            (current_user.full_name or "").lower(),
        ):
            errors["new_password"] = (
                "New password must not match your name, username or email."
            )

        if "new_password" not in errors and len(new_password) < MIN_LENGTH:
            errors["new_password"] = (
                "New password must be at least "
                + str(MIN_LENGTH)
                + " characters."
            )

        if "new_password" not in errors:
            result = analyze_password(new_password)

            if result["score"] < STRONG_MIN:
                errors["new_password"] = (
                    "New password is too weak. Use at least 12 characters "
                    "with a mix of uppercase, lowercase, numbers and symbols."
                )

    # ----- Confirmation -----

    if confirm_password != new_password:
        errors["confirm_password"] = "Passwords do not match."

    if errors:
        return jsonify({
            "error": "Please correct the highlighted fields.",
            "errors": errors,
        }), 400

    # Never log or echo the password. Only the hash is stored.
    current_user.set_password(new_password)

    settings = get_user_settings(current_user.id)
    settings.last_password_changed = datetime.utcnow()

    db.session.commit()

    return jsonify({
        "ok": True,
        "message": "Password changed successfully.",
    })
