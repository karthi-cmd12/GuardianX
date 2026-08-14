from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from flask_dance.contrib.google import google

from gmail.service import get_recent_emails
from ai.detector import analyze_email

from services.scan_history_service import (
    record_scan,
    build_input_preview,
    build_scan_details,
)

from services.notification_service import create_scan_notification


email_detector = Blueprint(
    "email_detector",
    __name__
)


@email_detector.route("/email-detector")
@login_required
def email_detector_home():

    gmail_connected = google.authorized

    emails = []
    selected_email = None

    # Search text from search bar
    search_query = request.args.get(
        "search",
        ""
    ).strip()


    if gmail_connected:

        # If user searches -> load 100 matching emails
        if search_query:

            emails = get_recent_emails(
                max_results=100,
                search_query=search_query
            )

        # Normal page -> latest 10 emails
        else:

            emails = get_recent_emails(
                max_results=10
            )


        # Analyze every email
        for email in emails:

            result = analyze_email(
                email.get("sender", ""),
                email.get("subject", ""),
                email.get("body", ""),
                email.get("links", []),
                email.get("attachments", [])
            )

            email.update(result)



        # Select email from inbox click
        email_id = request.args.get(
            "id"
        )


        if email_id:

            for email in emails:

                if email["id"] == email_id:

                    selected_email = email

                    break



        # Default first email
        if selected_email is None and emails:

            selected_email = emails[0]



    return render_template(
        "email_detector.html",
        gmail_connected=gmail_connected,
        emails=emails,
        selected_email=selected_email,
        search_query=search_query
    )


# ==========================================================
# Security Checks (derived from the existing analyzer output)
# ==========================================================

def build_security_checks(result, sender, subject, body):

    checks = []

    # Sender Reputation
    trust = int(result.get("sender_trust_score") or 0)

    if trust >= 80:
        checks.append({
            "check": "Sender Reputation",
            "risk": "SAFE",
            "detail": "Sender appears legitimate."
        })
    elif trust >= 50:
        checks.append({
            "check": "Sender Reputation",
            "risk": "SUSPICIOUS",
            "detail": "Sender shows moderate trust signals."
        })
    else:
        checks.append({
            "check": "Sender Reputation",
            "risk": "DANGEROUS",
            "detail": "Sender matches known suspicious patterns."
        })

    # URL Security
    links = result.get("links", [])

    dangerous_links = [
        link for link in links
        if link.get("risk") == "DANGEROUS"
    ]

    if dangerous_links:
        checks.append({
            "check": "URL Security",
            "risk": "DANGEROUS",
            "detail": "{} suspicious link(s) detected.".format(len(dangerous_links))
        })
    elif links:
        checks.append({
            "check": "URL Security",
            "risk": "SAFE",
            "detail": "{} external link(s) found, none flagged.".format(len(links))
        })
    else:
        checks.append({
            "check": "URL Security",
            "risk": "SAFE",
            "detail": "No external links detected."
        })

    # Attachment Security
    attachments = result.get("attachments", [])

    if any(item.get("risk") == "DANGEROUS" for item in attachments):
        checks.append({
            "check": "Attachment Security",
            "risk": "DANGEROUS",
            "detail": "Dangerous attachment detected."
        })
    else:
        checks.append({
            "check": "Attachment Security",
            "risk": "SAFE",
            "detail": "No dangerous attachments detected."
        })

    # Content Analysis
    indicators = result.get("indicators", [])

    suspicious = [
        item for item in indicators
        if item != "No suspicious indicators detected."
    ]

    level = result.get("risk_level")

    if suspicious:
        content_risk = (
            "DANGEROUS" if level == "HIGH"
            else "SUSPICIOUS" if level == "MEDIUM"
            else "SAFE"
        )
        checks.append({
            "check": "Content Analysis",
            "risk": content_risk,
            "detail": suspicious[0]
        })
    else:
        checks.append({
            "check": "Content Analysis",
            "risk": "SAFE",
            "detail": "No suspicious keywords or urgency patterns found."
        })

    return checks


# ==========================================================
# Manual Email Analysis API (uses the existing analyzer)
# ==========================================================

@email_detector.route("/email-detector/scan", methods=["POST"])
@login_required
def scan_email():

    data = request.get_json(silent=True)

    if not data or not isinstance(data, dict):

        return jsonify({
            "error": "Request body must be valid JSON."
        }), 400

    sender = data.get("sender", "")
    subject = data.get("subject", "")
    body = data.get("body", "")

    if not isinstance(sender, str):
        sender = str(sender)

    if not isinstance(subject, str):
        subject = str(subject)

    if not isinstance(body, str):
        body = str(body)

    if not any([sender.strip(), subject.strip(), body.strip()]):

        return jsonify({
            "error": "Please provide email details to analyze."
        }), 400

    result = analyze_email(sender, subject, body, [], [])

    result["checks"] = build_security_checks(
        result,
        sender,
        subject,
        body
    )

    # Record privacy-safe scan history for the explicit scan
    # action only. The email body is never stored; only a
    # generic summary is persisted.
    scan_record = record_scan(
        user_id=current_user.id,
        scan_type="Email",
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        input_preview=build_input_preview("Email", result),
        verdict=result["verdict"],
        request_id=data.get("request_id"),
        details=build_scan_details("Email", result),
    )

    # Raise a security notification when the scan found a
    # suspicious or high-risk email. Never includes the body.
    create_scan_notification(
        user_id=current_user.id,
        scan_type="email",
        result=result,
        request_id=data.get("request_id"),
        related_scan_id=(
            scan_record.id
            if scan_record is not None
            else None
        ),
    )

    return jsonify(result)