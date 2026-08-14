# ==========================================================
# GuardianX Password Analyzer Route
# ==========================================================

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from models.password_analyzer import analyze_password, MAX_LENGTH

from services.scan_history_service import (
    record_scan,
    build_input_preview,
    build_scan_details,
    risk_level_for_password,
)

from services.notification_service import create_scan_notification



# ==========================================================
# Blueprint
# ==========================================================

password_analyzer = Blueprint(
    "password_analyzer",
    __name__
)



# ==========================================================
# Password Analyzer Page
# ==========================================================

@password_analyzer.route("/password-analyzer")
@login_required
def password_analyzer_home():

    return render_template(
        "password_analyzer.html"
    )



# ==========================================================
# Analyze Password API
#
# The password is used only to compute strength statistics
# and is never stored, logged or echoed back in the response.
# ==========================================================

@password_analyzer.route(
    "/password-analyzer/analyze",
    methods=["POST"]
)
@login_required
def analyze():

    data = request.get_json(
        silent=True
    )

    if not data or not isinstance(data, dict):

        return jsonify({

            "error":
            "Request body must be valid JSON."

        }), 400


    password = data.get(
        "password",
        ""
    )


    if not isinstance(password, str) or not password.strip():

        return jsonify({

            "error":
            "Please enter a password to analyze."

        }), 400


    if len(password) > MAX_LENGTH:

        return jsonify({

            "error":
            "Password is too long to analyze (maximum "
            + str(MAX_LENGTH)
            + " characters)."

        }), 400


    result = analyze_password(
        password
    )

    # Record privacy-safe scan history.
    # ABSOLUTELY NO password value is persisted; the analyzer
    # never returns one and only a generic summary is stored.
    scan_record = record_scan(
        user_id=current_user.id,
        scan_type="Password",
        risk_score=result["score"],
        risk_level=risk_level_for_password(result["score"]),
        input_preview=build_input_preview("Password", result),
        verdict=result["verdict"],
        request_id=data.get("request_id"),
        details=build_scan_details("Password", result),
    )

    # Warn when the analyzed password is weak. The password
    # value is never stored in the notification.
    create_scan_notification(
        user_id=current_user.id,
        scan_type="password",
        result=result,
        request_id=data.get("request_id"),
        related_scan_id=(
            scan_record.id
            if scan_record is not None
            else None
        ),
    )

    return jsonify(result)
