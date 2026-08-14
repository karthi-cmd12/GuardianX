from flask import Blueprint, redirect, url_for, flash

from database.db import db
from database.email_models import (
    QuarantineEmail,
    ReportedEmail,
    SafeEmail
)

from gmail.service import get_email_by_id
from ai.detector import analyze_email

email_actions = Blueprint(
    "email_actions",
    __name__
)


# ==========================================
# Helper
# ==========================================

def build_email_record(email):

    result = analyze_email(
        email["sender"],
        email["subject"],
        email["body"],
        email["links"],
        email["attachments"]
    )

    return {
        "sender": email["sender"],
        "subject": email["subject"],
        "body": email["body"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "verdict": result["verdict"],
        "recommendation": result["recommendation"],
        "indicators": "\n".join(result["indicators"])
    }


# ==========================================
# QUARANTINE
# ==========================================

@email_actions.route("/quarantine/<email_id>")
def quarantine_email(email_id):

    existing = QuarantineEmail.query.filter_by(
        email_id=email_id
    ).first()

    if existing:
        flash("Email already exists in Quarantine.", "warning")
        return redirect(
            url_for("email_detector.email_detector_home")
        )

    email = get_email_by_id(email_id)

    if email is None:
        flash("Unable to fetch Gmail message.", "danger")
        return redirect(
            url_for("email_detector.email_detector_home")
        )

    data = build_email_record(email)

    quarantine = QuarantineEmail(
        email_id=email_id,
        sender=data["sender"],
        subject=data["subject"],
        body=data["body"],
        risk_score=data["risk_score"],
        risk_level=data["risk_level"],
        verdict=data["verdict"],
        recommendation=data["recommendation"],
        indicators=data["indicators"]
    )

    db.session.add(quarantine)
    db.session.commit()

    flash(
        "Email moved to Quarantine successfully.",
        "success"
    )

    return redirect(
        url_for("email_detector.email_detector_home")
    )


# ==========================================
# REPORT
# ==========================================

@email_actions.route("/report/<email_id>")
def report_email(email_id):

    existing = ReportedEmail.query.filter_by(
        email_id=email_id
    ).first()

    if existing:
        flash("Email already reported.", "warning")
        return redirect(
            url_for("email_detector.email_detector_home")
        )

    email = get_email_by_id(email_id)

    if email is None:
        flash("Unable to fetch Gmail message.", "danger")
        return redirect(
            url_for("email_detector.email_detector_home")
        )

    data = build_email_record(email)

    report = ReportedEmail(
        email_id=email_id,
        sender=data["sender"],
        subject=data["subject"],
        body=data["body"],
        risk_score=data["risk_score"],
        risk_level=data["risk_level"],
        verdict=data["verdict"],
        recommendation=data["recommendation"],
        indicators=data["indicators"]
    )

    db.session.add(report)
    db.session.commit()

    flash(
        "Email reported successfully.",
        "success"
    )

    return redirect(
        url_for("email_detector.email_detector_home")
    )


# ==========================================
# MARK SAFE
# ==========================================

@email_actions.route("/mark-safe/<email_id>")
def mark_safe(email_id):

    existing = SafeEmail.query.filter_by(
        email_id=email_id
    ).first()

    if existing:
        flash("Email already marked safe.", "warning")
        return redirect(
            url_for("email_detector.email_detector_home")
        )

    email = get_email_by_id(email_id)

    if email is None:
        flash("Unable to fetch Gmail message.", "danger")
        return redirect(
            url_for("email_detector.email_detector_home")
        )

    data = build_email_record(email)

    safe = SafeEmail(
        email_id=email_id,
        sender=data["sender"],
        subject=data["subject"],
        body=data["body"],
        risk_score=data["risk_score"],
        risk_level=data["risk_level"],
        verdict=data["verdict"],
        recommendation=data["recommendation"],
        indicators=data["indicators"]
    )

    db.session.add(safe)
    db.session.commit()

    flash(
        "Email marked as Safe.",
        "success"
    )

    return redirect(
        url_for("email_detector.email_detector_home")
    )