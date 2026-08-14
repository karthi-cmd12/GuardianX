# ==========================================================
# GuardianX SMS Scam Detector Route
# ==========================================================

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from models.sms_detector import scan_sms

from services.scan_history_service import (
    record_scan,
    build_input_preview,
    build_scan_details,
)

from services.notification_service import create_scan_notification



# ==========================================================
# Blueprint
# ==========================================================

sms_detector = Blueprint(
    "sms_detector",
    __name__
)



# ==========================================================
# SMS Detector Page
# ==========================================================

@sms_detector.route("/sms-detector")
@login_required
def sms_detector_home():

    return render_template(
        "sms_detector.html"
    )



# ==========================================================
# Scan SMS API
# ==========================================================

@sms_detector.route(
    "/sms-detector/scan",
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


    sender = data.get(
        "sender",
        ""
    )

    message = data.get(
        "message",
        ""
    )


    if not message or not isinstance(message, str) or not message.strip():

        return jsonify({

            "error":
            "Please provide the SMS message to analyze."

        }), 400


    result = scan_sms(
        sender,
        message
    )

    if result.get("valid") is False:

        return jsonify({
            "error": result.get(
                "reason",
                "Unable to analyze the message. Please try again."
            )
        }), 400

    # Record privacy-safe scan history. The SMS content itself
    # is never stored; only a generic summary is persisted.
    scan_record = record_scan(
        user_id=current_user.id,
        scan_type="SMS",
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        input_preview=build_input_preview("SMS", result),
        verdict=result["verdict"],
        request_id=data.get("request_id"),
        details=build_scan_details("SMS", result),
    )

    # Raise a security notification for suspicious/high-risk
    # SMS messages. The message itself is never stored.
    create_scan_notification(
        user_id=current_user.id,
        scan_type="sms",
        result=result,
        request_id=data.get("request_id"),
        related_scan_id=(
            scan_record.id
            if scan_record is not None
            else None
        ),
    )

    return jsonify(result)
