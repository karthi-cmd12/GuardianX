# ==========================================================
# GuardianX AI Assistant Route
# ==========================================================

from flask import Blueprint, render_template, request, jsonify
from flask_login import current_user

from ai_engine.threat_analyzer import analyze_message

from services.notification_service import create_security_notification



# ==========================================================
# Blueprint
# ==========================================================

ai_assistant = Blueprint(
    "ai_assistant",
    __name__
)



# ==========================================================
# AI Assistant Page
# ==========================================================

@ai_assistant.route("/ai-assistant")
def assistant_page():

    return render_template(
        "ai_assistant.html"
    )



# ==========================================================
# Analyze Message API
# ==========================================================

@ai_assistant.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    data = request.get_json()


    message = data.get(
        "message",
        ""
    )


    if not message:

        return jsonify({

            "error":
            "Please enter a message to analyze"

        })



    result = analyze_message(
        message
    )

    # Raise a security notification when a logged-in user asks
    # the assistant to analyze a suspicious or dangerous message.
    # The message text is never stored; only safe summary text.
    if current_user.is_authenticated:

        threat_level = result.get(
            "threat_level",
            ""
        ).upper()

        severity = (
            "HIGH"
            if threat_level == "DANGEROUS"
            else "MEDIUM"
            if threat_level == "SUSPICIOUS"
            else None
        )

        if severity is not None:

            create_security_notification(
                user_id=current_user.id,
                notification_type="ai_assistant",
                title=(
                    "Threat Identified in Analyzed Message"
                    if severity == "HIGH"
                    else "Suspicious Message Analyzed"
                ),
                message=(
                    result.get("recommendation")
                    or (
                        "Analysis found indicators of a potential "
                        "threat. Review the message with caution."
                    )
                ),
                severity=severity,
            )

    return jsonify(result)