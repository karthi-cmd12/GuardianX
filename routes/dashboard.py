# ==========================================================
# GuardianX Dashboard 2.0 - Security Command Center
#
# Every number shown is computed from the logged-in user's
# REAL database rows (scan_history, notifications, users,
# user_settings). Nothing is hard-coded, fabricated or derived
# from a user-supplied id: the browser never provides a user id.
#
# Queries are aggregate/count based and filtered by
# current_user.id only.
# ==========================================================

from datetime import datetime, timedelta

from flask import Blueprint, render_template
from flask_login import login_required, current_user
from flask_dance.contrib.google import google
from sqlalchemy import func

from database.db import db
from models.scan_history import ScanHistory
from models.notification import Notification
from models.user_settings import UserSettings

from ai_engine.model_loader import model_status

from services.notification_service import (
    serialize as serialize_notification,
    unread_count,
)


# ==========================================================
# Blueprint
# ==========================================================

dashboard = Blueprint(
    "dashboard",
    __name__
)


# ==========================================================
# Constants
# ==========================================================

# How far back scan-health and threat windows reach.
HEALTH_WINDOW_DAYS = 30
ALERT_WINDOW_DAYS = 7
WEEK_WINDOW_DAYS = 7

RECENT_LIMIT = 7
NOTIF_LIMIT = 5
REC_MAX = 5

SCAN_TYPE_META = {
    "Email": {"label": "Email", "icon": "envelope-circle-check"},
    "URL": {"label": "URL", "icon": "link"},
    "SMS": {"label": "SMS", "icon": "comment-sms"},
    "QR": {"label": "QR", "icon": "qrcode"},
    "Password": {"label": "Password", "icon": "key"},
}

SCAN_TYPE_ORDER = ("URL", "Email", "SMS", "QR", "Password")

RISK_TONES = {
    "HIGH": "critical",
    "MEDIUM": "warn",
    "LOW": "good",
}


# ==========================================================
# Small Helpers
# ==========================================================


def first_name(user):
    parts = (user.full_name or "").strip().split()
    return parts[0] if parts else (user.username or "there")


def time_ago(created_at):
    if not created_at:
        return ""
    delta = datetime.utcnow() - created_at
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "Just now"
    if seconds < 3600:
        return "{}m ago".format(seconds // 60)
    if seconds < 86400:
        return "{}h ago".format(seconds // 3600)
    if seconds < 86400 * 7:
        return "{}d ago".format(seconds // 86400)
    return created_at.strftime("%d %b %Y")


def _snippet(value, limit=90):
    value = str(value or "").strip()
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _level_counts(user_id, since=None):
    """
    One grouped query -> {risk_level: count} for the user.
    Optionally restricted to rows created after `since`.
    """
    query = db.session.query(
        ScanHistory.risk_level,
        func.count(ScanHistory.id),
    ).filter(
        ScanHistory.user_id == user_id
    )

    if since is not None:
        query = query.filter(
            ScanHistory.created_at >= since
        )

    return {
        level: count
        for level, count in query.group_by(ScanHistory.risk_level).all()
    }


# ==========================================================
# Overview Statistics
# ==========================================================


def overview_stats(user_id):
    counts = _level_counts(user_id)

    total = sum(counts.values())
    safe = counts.get("LOW", 0)
    suspicious = counts.get("MEDIUM", 0)
    high = counts.get("HIGH", 0)

    month_start = datetime.utcnow() - timedelta(days=30)

    month_counts = _level_counts(
        user_id,
        since=month_start,
    )

    def pct(value):
        if total == 0:
            return 0
        return round((value * 100) / total)

    return {
        "total_scans": total,
        "safe_scans": safe,
        "suspicious_scans": suspicious,
        "high_risk_scans": high,
        "pct_safe": pct(safe),
        "pct_suspicious": pct(suspicious),
        "pct_high": pct(high),
        "scans_this_month": sum(month_counts.values()),
    }


# ==========================================================
# Security Score (real, explainable)
# ==========================================================


def score_status(score):
    if score >= 80:
        return {
            "label": "Excellent",
            "tone": "good",
            "emoji": "🟢",
            "accessible": "Safe",
        }
    if score >= 60:
        return {
            "label": "Good",
            "tone": "good",
            "emoji": "🟢",
            "accessible": "Safe",
        }
    if score >= 40:
        return {
            "label": "Needs Attention",
            "tone": "warn",
            "emoji": "🟡",
            "accessible": "Needs Attention",
        }
    return {
        "label": "Critical",
        "tone": "critical",
        "emoji": "🔴",
        "accessible": "Critical",
    }


def security_score(user, gmail_connected, user_id):
    """
    Composite 0-100 score built from three real components:

      1. Account protection  (0-40)
         email verified / mobile verified / gmail connected.
      2. Scan health         (0-40)
         weighted threat ratio across the last 30 days.
      3. Security settings   (0-20)
         security alerts + automatic scan history enabled.
    """
    components = []
    points = 0

    # ---------- Account protection (0-40) ----------

    account_points = 0
    account_details = []

    if user.email_verified:
        account_points += 15
        account_details.append("Email verified")
    else:
        account_details.append("Email not verified")

    if user.mobile_verified:
        account_points += 15
        account_details.append("Mobile verified")
    else:
        account_details.append("Mobile not verified")

    if gmail_connected:
        account_points += 10
        account_details.append("Gmail connected")
    else:
        account_details.append("Gmail not connected")

    components.append({
        "key": "account",
        "label": "Account protection",
        "points": account_points,
        "max": 40,
        "details": account_details,
    })

    points += account_points

    # ---------- Scan health (0-40) ----------

    since = datetime.utcnow() - timedelta(days=HEALTH_WINDOW_DAYS)

    counts = _level_counts(user_id, since=since)

    total_h = sum(counts.values())
    high = counts.get("HIGH", 0)
    suspicious = counts.get("MEDIUM", 0)

    if total_h > 0:
        weighted = (high + (0.5 * suspicious)) / total_h
        health = round(40 * (1 - weighted))
        health_details = [
            "{} scans analyzed (last {} days)".format(
                total_h,
                HEALTH_WINDOW_DAYS,
            ),
            "{} high-risk, {} suspicious".format(
                high,
                suspicious,
            ),
        ]
    else:
        # No data yet: neutral (not penalised, not rewarded).
        health = 30
        health_details = [
            "No scans in the last {} days".format(HEALTH_WINDOW_DAYS),
            "Neutral score - activity will refine it",
        ]

    components.append({
        "key": "scans",
        "label": "Scan health",
        "points": health,
        "max": 40,
        "details": health_details,
    })

    points += health

    # ---------- Security settings (0-20) ----------

    settings = UserSettings.query.filter_by(
        user_id=user_id
    ).first()

    settings_points = 0
    settings_details = []

    if settings is None or settings.security_alerts:
        settings_points += 10
        settings_details.append("Security alerts enabled")
    else:
        settings_details.append("Security alerts disabled")

    if settings is None or settings.save_scan_history:
        settings_points += 10
        settings_details.append("Scan history enabled")
    else:
        settings_details.append("Scan history disabled")

    components.append({
        "key": "settings",
        "label": "Security settings",
        "points": settings_points,
        "max": 20,
        "details": settings_details,
    })

    points += settings_points

    score = max(0, min(round(points), 100))

    return {
        "score": score,
        "status": score_status(score),
        "components": components,
    }


# ==========================================================
# Current Threat Level
# ==========================================================


def threat_level(user_id):
    since = datetime.utcnow() - timedelta(days=ALERT_WINDOW_DAYS)

    counts = _level_counts(user_id, since=since)

    high = counts.get("HIGH", 0)
    suspicious = counts.get("MEDIUM", 0)

    if high > 0:
        return {
            "level": "HIGH",
            "tone": "critical",
            "emoji": "🔴",
            "message": (
                "Recent high-risk activity detected. "
                "Review flagged items before proceeding."
            ),
            "count": high,
        }

    if suspicious > 0:
        return {
            "level": "MEDIUM",
            "tone": "warn",
            "emoji": "🟡",
            "message": (
                "Some suspicious activity detected recently. "
                "Keep an eye on flagged items."
            ),
            "count": suspicious,
        }

    return {
        "level": "LOW",
        "tone": "good",
        "emoji": "🟢",
        "message": "No major threats detected recently.",
        "count": 0,
    }


# ==========================================================
# Recent Security Activity
# ==========================================================


def activity_entry(record):
    meta = SCAN_TYPE_META.get(
        record.scan_type,
        {"label": record.scan_type, "icon": "shield-halved"},
    )

    return {
        "id": record.id,
        "scan_type": record.scan_type,
        "label": meta["label"],
        "icon": meta["icon"],
        "risk_level": record.risk_level,
        "tone": RISK_TONES.get(record.risk_level, "info"),
        "preview": _snippet(record.input_preview),
        "verdict": _snippet(record.verdict, 110),
        "time_ago": time_ago(record.created_at),
        "created_at": record.created_at,
    }


def recent_activity(user_id):
    records = (
        ScanHistory.query
        .filter_by(user_id=user_id)
        .order_by(
            ScanHistory.created_at.desc(),
            ScanHistory.id.desc(),
        )
        .limit(RECENT_LIMIT)
        .all()
    )

    return [activity_entry(record) for record in records]


# ==========================================================
# Security Activity (last 7 days)
# ==========================================================


def weekly_activity(user_id):
    today = datetime.utcnow().date()
    start = today - timedelta(days=WEEK_WINDOW_DAYS - 1)
    since = datetime(
        start.year,
        start.month,
        start.day,
    )

    rows = (
        db.session.query(
            func.date(ScanHistory.created_at).label("day"),
            ScanHistory.risk_level,
            func.count(ScanHistory.id),
        )
        .filter(
            ScanHistory.user_id == user_id,
            ScanHistory.created_at >= since,
        )
        .group_by("day", ScanHistory.risk_level)
        .all()
    )

    by_day = {}

    for day, level, count in rows:
        key = str(day)
        by_day.setdefault(key, {}).setdefault(level, 0)
        by_day[key][level] = count

    days = []

    for offset in range(WEEK_WINDOW_DAYS):
        day = start + timedelta(days=offset)
        counts = by_day.get(str(day), {})
        safe = counts.get("LOW", 0)
        suspicious = counts.get("MEDIUM", 0)
        high = counts.get("HIGH", 0)

        days.append({
            "label": day.strftime("%a"),
            "day": day.strftime("%d %b"),
            "safe": safe,
            "suspicious": suspicious,
            "high": high,
            "total": safe + suspicious + high,
        })

    max_day = max((day["total"] for day in days), default=0)

    for day in days:
        if max_day > 0:
            day["safe_pct"] = round((day["safe"] * 100) / max_day)
            day["suspicious_pct"] = round(
                (day["suspicious"] * 100) / max_day
            )
            day["high_pct"] = round((day["high"] * 100) / max_day)
        else:
            day["safe_pct"] = 0
            day["suspicious_pct"] = 0
            day["high_pct"] = 0

    return {
        "days": days,
        "max": max_day,
        "total": sum(day["total"] for day in days),
    }


# ==========================================================
# Scan Type Breakdown
# ==========================================================


def scan_type_breakdown(user_id):
    rows = (
        db.session.query(
            ScanHistory.scan_type,
            func.count(ScanHistory.id),
        )
        .filter_by(user_id=user_id)
        .group_by(ScanHistory.scan_type)
        .all()
    )

    counts = dict(rows)

    total = sum(counts.values())

    breakdown = []

    for scan_type in SCAN_TYPE_ORDER:
        count = counts.get(scan_type, 0)
        meta = SCAN_TYPE_META[scan_type]
        breakdown.append({
            "scan_type": scan_type,
            "label": meta["label"],
            "icon": meta["icon"],
            "count": count,
            "pct": round((count * 100) / total) if total else 0,
        })

    return breakdown


# ==========================================================
# Priority Alert
# ==========================================================


def priority_alert(user_id):
    since = datetime.utcnow() - timedelta(days=ALERT_WINDOW_DAYS)

    record = (
        ScanHistory.query
        .filter(
            ScanHistory.user_id == user_id,
            ScanHistory.risk_level == "HIGH",
            ScanHistory.created_at >= since,
        )
        .order_by(
            ScanHistory.created_at.desc(),
            ScanHistory.id.desc(),
        )
        .first()
    )

    if record is not None:
        return {
            "active": True,
            "record": activity_entry(record),
        }

    return {
        "active": False,
    }


# ==========================================================
# Security Recommendations
# ==========================================================


def recommendations(user, user_id):
    recs = []

    settings = UserSettings.query.filter_by(
        user_id=user_id
    ).first()

    # 1. Weak password analyzed recently.
    weak_password = (
        ScanHistory.query
        .filter(
            ScanHistory.user_id == user_id,
            ScanHistory.scan_type == "Password",
            ScanHistory.risk_level == "HIGH",
        )
        .order_by(ScanHistory.created_at.desc())
        .first()
    )

    if weak_password is not None:
        recs.append({
            "tone": "warn",
            "icon": "key",
            "title": "Password security needs attention",
            "text": (
                "A recent password check found weak credentials. "
                "Use a strong, unique password to stay protected."
            ),
            "button": "Improve Password",
            "url": "password_analyzer.password_analyzer_home",
        })

    # 2. Recent high-risk scan activity.
    high_scan = (
        ScanHistory.query
        .filter(
            ScanHistory.user_id == user_id,
            ScanHistory.risk_level == "HIGH",
        )
        .order_by(ScanHistory.created_at.desc())
        .first()
    )

    if high_scan is not None:
        recs.append({
            "tone": "critical",
            "icon": "shield-virus",
            "title": "Review recent threats",
            "text": (
                "High-risk results were recorded in your scan history. "
                "Review them to understand the risk."
            ),
            "button": "View Scan History",
            "url": "history.scan_history_home",
        })

    # 3. Security alerts disabled.
    if settings is not None and not settings.security_alerts:
        recs.append({
            "tone": "warn",
            "icon": "bell-slash",
            "title": "Security alerts are disabled",
            "text": (
                "Enable security alerts so GuardianX can notify you "
                "about suspicious activity."
            ),
            "button": "Open Settings",
            "url": "settings.settings_home",
        })

    # 4. Scan history disabled.
    if settings is not None and not settings.save_scan_history:
        recs.append({
            "tone": "warn",
            "icon": "clock-rotate-left",
            "title": "Scan history is disabled",
            "text": (
                "Turn on automatic scan history to keep a record "
                "of your security activity."
            ),
            "button": "Open Settings",
            "url": "settings.settings_home",
        })

    # 5. Email not verified.
    if not user.email_verified:
        recs.append({
            "tone": "info",
            "icon": "envelope",
            "title": "Verify your email address",
            "text": (
                "Verifying your email strengthens your account "
                "and boosts your security score."
            ),
            "button": "Verify Email",
            "url": "verification.verify_email",
        })

    # 6. Mobile not verified.
    if not user.mobile_verified:
        recs.append({
            "tone": "info",
            "icon": "mobile-screen-button",
            "title": "Verify your mobile number",
            "text": (
                "Verifying your mobile number adds a second "
                "confirmation channel to your account."
            ),
            "button": "Verify Mobile",
            "url": "verification.verify_mobile",
        })

    recs = recs[:REC_MAX]

    if not recs:
        recs.append({
            "tone": "good",
            "icon": "shield-check",
            "title": "Your security setup looks good",
            "text": (
                "No weak points found. Keep scanning regularly "
                "to maintain a strong posture."
            ),
            "button": "Run a Quick Scan",
            "url": "url_detector.url_detector_home",
        })

    return recs


# ==========================================================
# Dashboard Route
# ==========================================================

@dashboard.route("/dashboard")
@login_required
def dashboard_home():

    user_id = current_user.id

    gmail_connected = bool(google.authorized)

    engine = model_status()

    score = security_score(
        current_user,
        gmail_connected,
        user_id,
    )

    recent_notifications = (
        Notification.query
        .filter_by(user_id=user_id)
        .order_by(
            Notification.created_at.desc(),
            Notification.id.desc(),
        )
        .limit(NOTIF_LIMIT)
        .all()
    )

    return render_template(
        "dashboard.html",
        user=current_user,
        first_name=first_name(current_user),
        gmail_connected=gmail_connected,
        engine_status=engine.get("status", "RULE_ENGINE"),
        engine_message=engine.get("message", ""),
        score=score,
        stats=overview_stats(user_id),
        threat=threat_level(user_id),
        weekly=weekly_activity(user_id),
        breakdown=scan_type_breakdown(user_id),
        recent_activity=recent_activity(user_id),
        priority_alert=priority_alert(user_id),
        recommendations=recommendations(current_user, user_id),
        recent_notifications=[
            serialize_notification(item)
            for item in recent_notifications
        ],
        unread_count=unread_count(user_id),
    )
