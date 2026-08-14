# ==========================================================
# GuardianX QR Scanner Route
# ==========================================================

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from models.qr_scanner import analyze_qr

from services.scan_history_service import (
    record_scan,
    build_input_preview,
    build_scan_details,
)

from services.notification_service import create_scan_notification



# ==========================================================
# Blueprint
# ==========================================================

qr_scanner = Blueprint(
    "qr_scanner",
    __name__
)



# ==========================================================
# QR Scanner Page
# ==========================================================

@qr_scanner.route("/qr-scanner")
@login_required
def qr_scanner_home():

    return render_template(
        "qr_scanner.html"
    )



# ==========================================================
# Analyze QR Content API
# ==========================================================

@qr_scanner.route(
    "/qr-scanner/scan",
    methods=["POST"]
)
@login_required
def scan():

    data = request.get_json(
        silent=True
    )

    if not data or not isinstance(data, dict):

        return jsonify({

            "error":
            "Request body must be valid JSON."

        }), 400


    content = data.get(
        "content",
        ""
    )


    if not content or not isinstance(content, str) or not content.strip():

        return jsonify({

            "error":
            "Please provide the QR code content to analyze."

        }), 400


    result = analyze_qr(
        content
    )

    # Record privacy-safe scan history. The raw QR payload is
    # never stored; only a generic summary is persisted.
    scan_record = record_scan(
        user_id=current_user.id,
        scan_type="QR",
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        input_preview=build_input_preview("QR", result),
        verdict=result["verdict"],
        request_id=data.get("request_id"),
        details=build_scan_details("QR", result),
    )

    # Raise a security notification for suspicious/high-risk QR
    # content. The raw QR payload is never stored.
    create_scan_notification(
        user_id=current_user.id,
        scan_type="qr",
        result=result,
        request_id=data.get("request_id"),
        related_scan_id=(
            scan_record.id
            if scan_record is not None
            else None
        ),
    )

    return jsonify(result)
