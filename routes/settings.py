# ==========================================================
# GuardianX Settings Routes
#
# A user can only ever read and modify their OWN settings.
# All endpoints require login and every request is validated
# server-side.
# ==========================================================

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from flask_dance.contrib.google import google

from database.db import db
from models.scan_history import ScanHistory
from models.user_settings import get_user_settings


# ==========================================================
# Blueprint
# ==========================================================

settings_bp = Blueprint(
    "settings",
    __name__
)


# ==========================================================
# Allowed Values
# ==========================================================

ALLOWED_RISK_DISPLAY = ("level", "score")


def _to_bool(value, default=False):
    """
    Accepts native booleans or common string representations.
    """
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "on", "yes")

    return default


# ==========================================================
# Settings Page
# ==========================================================

@settings_bp.route("/settings")
@login_required
def settings_home():

    settings = get_user_settings(current_user.id)

    return render_template(
        "settings.html",
        settings=settings,
        protection={
            "email_verified": bool(current_user.email_verified),
            "mobile_verified": bool(current_user.mobile_verified),
            "gmail_connected": bool(google.authorized),
        },
        history_count=ScanHistory.query.filter_by(
            user_id=current_user.id
        ).count(),
    )


# ==========================================================
# Update Settings
# ==========================================================

@settings_bp.route(
    "/settings/update",
    methods=["POST"]
)
@login_required
def settings_update():

    data = request.get_json(
        silent=True
    )

    if not data or not isinstance(data, dict):

        return jsonify({
            "error":
            "Request body must be valid JSON."
        }), 400

    settings = get_user_settings(current_user.id)

    risk_display = str(
        data.get("default_risk_display") or ""
    ).strip()

    errors = {}

    if risk_display and risk_display not in ALLOWED_RISK_DISPLAY:
        errors["default_risk_display"] = "Invalid risk display option."

    if errors:
        return jsonify({
            "error": "Please correct the highlighted fields.",
            "errors": errors,
        }), 400

    settings.security_alerts = _to_bool(
        data.get("security_alerts"),
        settings.security_alerts,
    )

    settings.save_scan_history = _to_bool(
        data.get("save_scan_history"),
        settings.save_scan_history,
    )

    settings.detailed_results = _to_bool(
        data.get("detailed_results"),
        settings.detailed_results,
    )

    settings.compact_mode = _to_bool(
        data.get("compact_mode"),
        settings.compact_mode,
    )

    settings.animations_enabled = _to_bool(
        data.get("animations_enabled"),
        settings.animations_enabled,
    )

    settings.reduced_motion = _to_bool(
        data.get("reduced_motion"),
        settings.reduced_motion,
    )

    if risk_display:
        settings.default_risk_display = risk_display

    db.session.commit()

    return jsonify({
        "ok": True,
        "message": "Settings saved successfully.",
        "settings": {
            "security_alerts": settings.security_alerts,
            "save_scan_history": settings.save_scan_history,
            "detailed_results": settings.detailed_results,
            "default_risk_display": settings.default_risk_display,
            "compact_mode": settings.compact_mode,
            "animations_enabled": settings.animations_enabled,
            "reduced_motion": settings.reduced_motion,
        },
    })
