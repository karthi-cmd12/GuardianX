# ==========================================================
# GuardianX Notification Service
#
# Creates and serializes per-user security notifications and
# maps scan results / notification types to destinations.
#
# RULES:
#   - HIGH and CRITICAL notifications are ALWAYS created.
#   - INFO / LOW / MEDIUM notifications respect the user's
#     "security_alerts" preference (default: enabled).
#   - MEDIUM notifications are only created when the scan
#     result contains meaningful suspicious indicators.
#   - An optional client request_id de-duplicates retries.
#   - Notifications are independent of scan-history recording:
#     an alert still fires when the user disabled history.
# ==========================================================

from datetime import datetime

from flask import url_for

from database.db import db
from models.notification import Notification
from models.user_settings import UserSettings

from services.scan_history_service import (
    risk_level_for_score,
    risk_level_for_password,
)


# ==========================================================
# Constants
# ==========================================================

SEVERITIES = (
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)

# Severities that fire even when security alerts are disabled.
ALWAYS_NOTIFY_SEVERITIES = ("HIGH", "CRITICAL")

# Severities that are gated by the user's preference.
GATED_SEVERITIES = ("INFO", "LOW", "MEDIUM")

HIGH_MIN = 70

DEFAULT_INDICATOR_STRINGS = (
    "No major suspicious indicators were detected.",
    "No suspicious indicators detected.",
)

TITLE_MAX = 200
MESSAGE_MAX = 300
DESTINATION_MAX = 255


# ==========================================================
# Type Metadata
# ==========================================================

# Safe internal route endpoints (name.rule) per notification
# type. Used to build `destination` when none is provided.
TYPE_DESTINATIONS = {
    "email": "email_detector.email_detector_home",
    "url": "url_detector.url_detector_home",
    "sms": "sms_detector.sms_detector_home",
    "qr": "qr_scanner.qr_scanner_home",
    "password": "password_analyzer.password_analyzer_home",
    "ai_assistant": "ai_assistant.assistant_page",
    "history": "history.scan_history_home",
    "system": "dashboard.dashboard_home",
}

TYPE_LABELS = {
    "email": "Email",
    "url": "URL",
    "sms": "SMS",
    "qr": "QR",
    "password": "Password",
    "ai_assistant": "AI Assistant",
    "history": "Scan History",
    "system": "GuardianX",
}

TYPE_ICONS = {
    "email": "envelope-circle-check",
    "url": "link",
    "sms": "comment-sms",
    "qr": "qrcode",
    "password": "key",
    "ai_assistant": "robot",
    "history": "clock-rotate-left",
    "system": "shield-halved",
}


# ==========================================================
# Small Helpers
# ==========================================================


def _truncate(value, length):
    value = str(value or "").strip()

    if len(value) <= length:
        return value

    return value[: length - 3] + "..."


def _alerts_enabled(user_id):
    """
    Respects the user's "security alerts" preference. Defaults
    to enabled when the user has not configured settings yet.
    """
    settings = UserSettings.query.filter_by(
        user_id=user_id
    ).first()

    if settings is None:
        return True

    return bool(settings.security_alerts)


def destination_for_type(notification_type):
    """
    Returns the safe internal destination URL for a notification
    type. Falls back to the dashboard for unknown types.
    """
    endpoint = TYPE_DESTINATIONS.get(
        str(notification_type or "").lower()
    )

    if endpoint is None:
        endpoint = TYPE_DESTINATIONS["system"]

    try:
        return url_for(endpoint)
    except Exception:
        return "/dashboard"


def _time_ago(created_at):
    if not created_at:
        return ""

    delta = datetime.utcnow() - created_at
    seconds = int(delta.total_seconds())

    if seconds < 60:
        return "Just now"

    if seconds < 3600:
        return str(seconds // 60) + "m ago"

    if seconds < 86400:
        return str(seconds // 3600) + "h ago"

    if seconds < 86400 * 7:
        return str(seconds // 86400) + "d ago"

    return created_at.strftime("%d %b %Y")


# ==========================================================
# Serialization
# ==========================================================


def serialize(notification):
    """
    Converts a Notification row into a safe JSON-safe dict.
    Never exposes any raw user input content.
    """
    return {
        "id": notification.id,
        "notification_type": notification.notification_type,
        "type_label": TYPE_LABELS.get(
            notification.notification_type, "Alert"
        ),
        "icon": TYPE_ICONS.get(
            notification.notification_type, "bell"
        ),
        "title": notification.title,
        "message": notification.message,
        "severity": notification.severity,
        "related_scan_id": notification.related_scan_id,
        "destination": (
            notification.destination
            or destination_for_type(notification.notification_type)
        ),
        "is_read": bool(notification.is_read),
        "created_at": (
            notification.created_at.isoformat()
            if notification.created_at else None
        ),
        "created_at_display": (
            notification.created_at.strftime("%d %b %Y, %I:%M %p")
            if notification.created_at else ""
        ),
        "time_ago": _time_ago(notification.created_at),
    }


def unread_count(user_id):
    """
    Number of unread notifications for the given user.
    """
    return Notification.query.filter_by(
        user_id=user_id,
        is_read=False
    ).count()


# ==========================================================
# Creation
# ==========================================================


def create_security_notification(
    user_id,
    notification_type,
    title,
    message,
    severity="INFO",
    related_scan_id=None,
    request_id=None,
    destination=None,
):
    """
    Creates one notification for the given user.

    - HIGH / CRITICAL always fire.
    - INFO / LOW / MEDIUM fire only when the user has security
      alerts enabled.
    - A provided request_id de-duplicates retried requests.

    Returns the created Notification, an existing duplicate, or
    None when the alert was skipped by the user's preferences.
    """
    severity = str(severity or "INFO").upper()

    if severity not in SEVERITIES:
        severity = "INFO"

    if severity in GATED_SEVERITIES and not _alerts_enabled(user_id):
        return None

    if request_id:
        existing = Notification.query.filter_by(
            user_id=user_id,
            request_id=request_id,
        ).first()

        if existing is not None:
            return existing

    notification = Notification(
        user_id=user_id,
        notification_type=str(notification_type or "system").lower(),
        title=_truncate(title, TITLE_MAX),
        message=_truncate(message, MESSAGE_MAX),
        severity=severity,
        related_scan_id=related_scan_id,
        destination=_truncate(
            destination or destination_for_type(notification_type),
            DESTINATION_MAX,
        ),
        request_id=request_id or None,
    )

    db.session.add(notification)

    db.session.commit()

    return notification


# ==========================================================
# Scan Notification Mapping
# ==========================================================


def _has_meaningful_indicators(result):
    """
    True when a result contains real suspicious indicators and
    not just the default "nothing found" placeholder string.
    """
    indicators = result.get("indicators") or []

    for item in indicators:
        text = str(item or "").strip()

        if text and text not in DEFAULT_INDICATOR_STRINGS:
            return True

    return False


def _has_meaningful_weaknesses(result):
    return bool(result.get("weaknesses"))


def _build_scan_notification(scan_type, result):
    """
    Maps one completed scan result to a notification descriptor
    (notification_type / severity / title / message) or returns
    None when no notification should be raised.
    """
    scan_type = str(scan_type or "").lower()

    # ---------- Password (strength score, inverted risk) ----------

    if scan_type == "password":
        score = result.get("score")

        if score is None:
            return None

        risk = risk_level_for_password(score)

        if risk == "HIGH":
            return {
                "notification_type": "password",
                "severity": "HIGH",
                "title": "Weak Password Detected",
                "message": (
                    result.get("security_message")
                    or result.get("verdict")
                    or "The analyzed password is weak and should be changed."
                ),
            }

        if risk == "MEDIUM" and _has_meaningful_weaknesses(result):
            return {
                "notification_type": "password",
                "severity": "MEDIUM",
                "title": "Password Needs Strengthening",
                "message": (
                    result.get("security_message")
                    or result.get("verdict")
                    or "The analyzed password could be stronger."
                ),
            }

        return None

    # ---------- Standard 0-100 risk scanners ----------

    level = result.get("risk_level") or risk_level_for_score(
        result.get("risk_score")
    )

    if scan_type == "url":
        if level == "HIGH":
            return {
                "notification_type": "url",
                "severity": "HIGH",
                "title": "High-Risk URL Detected",
                "message": (
                    result.get("verdict")
                    or "Multiple high-risk phishing indicators were "
                    "detected in the scanned URL."
                ),
            }

        if level == "MEDIUM" and _has_meaningful_indicators(result):
            return {
                "notification_type": "url",
                "severity": "MEDIUM",
                "title": "Suspicious URL Detected",
                "message": (
                    result.get("verdict")
                    or "The scanned URL contains suspicious "
                    "characteristics. Verify it before proceeding."
                ),
            }

        return None

    if scan_type == "sms":
        if level == "HIGH":
            return {
                "notification_type": "sms",
                "severity": "HIGH",
                "title": "Potential Scam SMS Detected",
                "message": (
                    result.get("verdict")
                    or "Multiple high-risk scam indicators were "
                    "detected in the scanned message."
                ),
            }

        if level == "MEDIUM" and _has_meaningful_indicators(result):
            return {
                "notification_type": "sms",
                "severity": "MEDIUM",
                "title": "Suspicious SMS Detected",
                "message": (
                    result.get("verdict")
                    or "The scanned message shows characteristics "
                    "commonly found in scams."
                ),
            }

        return None

    if scan_type == "qr":
        if level == "HIGH":
            return {
                "notification_type": "qr",
                "severity": "HIGH",
                "title": "Suspicious QR Code Detected",
                "message": (
                    result.get("verdict")
                    or "The QR code contains a URL with multiple "
                    "suspicious indicators. Avoid opening it."
                ),
            }

        if level == "MEDIUM" and _has_meaningful_indicators(result):
            return {
                "notification_type": "qr",
                "severity": "MEDIUM",
                "title": "QR Code Requires Caution",
                "message": (
                    result.get("verdict")
                    or "The QR code contains a URL with some "
                    "suspicious characteristics."
                ),
            }

        return None

    if scan_type == "email":
        if level == "HIGH":
            return {
                "notification_type": "email",
                "severity": "HIGH",
                "title": "Email Threat Detected",
                "message": (
                    result.get("verdict")
                    or "The analyzed email shows a high probability "
                    "of phishing."
                ),
            }

        if level == "MEDIUM" and _has_meaningful_indicators(result):
            return {
                "notification_type": "email",
                "severity": "MEDIUM",
                "title": "Suspicious Email Detected",
                "message": (
                    result.get("verdict")
                    or "The analyzed email appears suspicious. Verify "
                    "the sender before opening links or attachments."
                ),
            }

        return None

    return None


def create_scan_notification(
    user_id,
    scan_type,
    result,
    request_id=None,
    related_scan_id=None,
):
    """
    Convenience wrapper: decides from a scan result whether a
    notification should be created and creates it.
    Returns the created Notification or None.
    """
    built = _build_scan_notification(scan_type, result)

    if built is None:
        return None

    return create_security_notification(
        user_id=user_id,
        notification_type=built["notification_type"],
        title=built["title"],
        message=built["message"],
        severity=built["severity"],
        related_scan_id=related_scan_id,
        request_id=request_id,
    )


# ==========================================================
# Read / Ownership Helpers
# ==========================================================


def get_owned_notification(user_id, notification_id):
    """
    Returns the notification only when it belongs to the given
    user; returns None for unknown IDs or other users' rows so
    notification IDs can never be probed cross-user.
    """
    record = Notification.query.get(notification_id)

    if record is None or record.user_id != user_id:
        return None

    return record
