# ==========================================================
# GuardianX URL Scanner Route
# ==========================================================

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from models.url_detector import scan_url

from services.scan_history_service import (
    record_scan,
    build_input_preview,
    build_scan_details,
)

from services.notification_service import create_scan_notification



# ==========================================================
# Blueprint
# ==========================================================

url_detector = Blueprint(
    "url_detector",
    __name__
)



# ==========================================================
# URL Scanner Page
# ==========================================================

@url_detector.route("/url-scanner")
@login_required
def url_detector_home():

    return render_template(
        "url_detector.html"
    )



# ==========================================================
# Scan URL API
# ==========================================================

@url_detector.route(
    "/url-scanner/scan",
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


    url = data.get(
        "url",
        ""
    )


    if not url or not isinstance(url, str) or not url.strip():

        return jsonify({

            "error":
            "Please provide a URL to scan."

        }), 400


    result = scan_url(
        url
    )

    if result.get("valid") is False:

        return jsonify({
            "error": result.get(
                "reason",
                "Unable to analyze the URL. Please try again."
            )
        }), 400

    # Record privacy-safe scan history (sensitive query
    # values are already masked by the scanner).
    scan_record = record_scan(
        user_id=current_user.id,
        scan_type="URL",
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        input_preview=build_input_preview("URL", result),
        verdict=result["verdict"],
        request_id=data.get("request_id"),
        details=build_scan_details("URL", result),
    )

    # Raise a security notification for suspicious/high-risk
    # URLs. The raw URL is never stored in the notification.
    create_scan_notification(
        user_id=current_user.id,
        scan_type="url",
        result=result,
        request_id=data.get("request_id"),
        related_scan_id=(
            scan_record.id
            if scan_record is not None
            else None
        ),
    )

    return jsonify(result)
