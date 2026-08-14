# ==========================================================
# GuardianX Scan History Route
#
# A user can only ever see and delete their OWN scan history.
# All endpoints require login and ownership is always verified.
# ==========================================================

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import case

from database.db import db
from models.scan_history import ScanHistory
from models.user_settings import UserSettings

from services.scan_history_service import parse_details


# ==========================================================
# Blueprint
# ==========================================================

history = Blueprint(
    "history",
    __name__
)


# ==========================================================
# Helpers
# ==========================================================

SORT_OPTIONS = {
    "newest": (
        ScanHistory.created_at.desc(),
        ScanHistory.id.desc(),
    ),
    "oldest": (
        ScanHistory.created_at.asc(),
        ScanHistory.id.asc(),
    ),
}

# Risk-first ordering: sort by severity band first (HIGH, then
# MEDIUM, then LOW), newest within each band. This is meaningful
# across all scan types, including password scans where the
# stored score is a strength score.
_SEVERITY_ORDER = case(
    (ScanHistory.risk_level == "HIGH", 0),
    (ScanHistory.risk_level == "MEDIUM", 1),
    else_=2,
).label("risk_severity")

SORT_OPTIONS["risk_high"] = (
    _SEVERITY_ORDER,
    ScanHistory.created_at.desc(),
    ScanHistory.id.desc(),
)

SORT_OPTIONS["risk_low"] = (
    _SEVERITY_ORDER.desc(),
    ScanHistory.created_at.desc(),
    ScanHistory.id.desc(),
)


def _entry_to_dict(record):
    return {
        "id": record.id,
        "scan_type": record.scan_type,
        "risk_level": record.risk_level,
        "risk_score": record.risk_score,
        "input_preview": record.input_preview,
        "verdict": record.verdict,
        "details": parse_details(record),
        "created_at": record.created_at.isoformat()
        if record.created_at else None,
        "created_at_display": record.created_at.strftime(
            "%d %b %Y, %I:%M %p"
        ) if record.created_at else "",
    }


def _stats_for(user_id):
    """
    Summary counts over the user's ENTIRE history (unaffected
    by the active filters).
    """
    rows = ScanHistory.query.filter_by(
        user_id=user_id
    ).all()

    return {
        "total": len(rows),
        "safe": sum(1 for row in rows if row.risk_level == "LOW"),
        "suspicious": sum(
            1 for row in rows if row.risk_level == "MEDIUM"
        ),
        "dangerous": sum(
            1 for row in rows if row.risk_level == "HIGH"
        ),
    }


def _int_arg(name, default):
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


def _settings_for(user_id):
    """
    Display preferences read from the user's settings so the
    history page can honour them. Falls back to defaults when
    no settings row exists yet.
    """
    settings = UserSettings.query.filter_by(
        user_id=user_id
    ).first()

    if settings is None:
        return {
            "detailed_results": True,
            "risk_display": "level",
        }

    return {
        "detailed_results": bool(settings.detailed_results),
        "risk_display": settings.default_risk_display or "level",
    }


# ==========================================================
# Scan History Page
# ==========================================================

@history.route("/history")
@login_required
def history_home():

    return render_template(
        "history.html"
    )


# ==========================================================
# Scan History Page
# ==========================================================

@history.route("/scan-history")
@login_required
def scan_history_home():

    return render_template(
        "scan_history.html"
    )


# ==========================================================
# Scan History Data API
# ==========================================================

@history.route("/history/data", methods=["GET"])
@login_required
def history_data():
    """
    Returns the logged-in user's scan history.

    Optional filters:
      - type: Email | URL | SMS | QR | Password
      - risk: LOW | MEDIUM | HIGH
      - date: YYYY-MM-DD
      - search: free-text over the safe input preview

    Optional sorting:
      - sort: newest (default) | oldest | risk_high | risk_low

    Optional pagination:
      - page + per_page (default per_page 10, max 50)
      - legacy limit + offset still supported
    """

    query = ScanHistory.query.filter_by(
        user_id=current_user.id
    )

    scan_type = (request.args.get("type") or "").strip()

    if scan_type:
        query = query.filter(
            ScanHistory.scan_type == scan_type
        )

    risk = (request.args.get("risk") or "").strip().upper()

    if risk:
        query = query.filter(
            ScanHistory.risk_level == risk
        )

    date_str = (request.args.get("date") or "").strip()

    if date_str:
        query = query.filter(
            db.func.date(ScanHistory.created_at) == date_str
        )

    search = (request.args.get("search") or "").strip()

    if search:
        like = "%" + search + "%"

        query = query.filter(
            ScanHistory.input_preview.ilike(like)
        )

    sort = (
        (request.args.get("sort") or "newest")
        .strip()
        .lower()
    )

    order_by = SORT_OPTIONS.get(
        sort,
        SORT_OPTIONS["newest"],
    )

    page = _int_arg("page", 0)
    per_page = min(max(_int_arg("per_page", 10), 1), 50)
    limit = min(_int_arg("limit", 100), 500)
    offset = max(_int_arg("offset", 0), 0)

    if page > 0:
        limit = per_page
        offset = (page - 1) * per_page

    total = query.count()

    rows = (
        query
        .order_by(*order_by)
        .limit(limit)
        .offset(offset)
        .all()
    )

    return jsonify({
        "items": [_entry_to_dict(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "page": page if page > 0 else None,
        "per_page": per_page,
        "total_pages": (
            (total + per_page - 1) // per_page
            if page > 0 else None
        ),
        "sort": sort,
        "stats": _stats_for(current_user.id),
        "settings": _settings_for(current_user.id),
    })


# ==========================================================
# Delete Single Entry
# ==========================================================

@history.route(
    "/history/delete/<int:entry_id>",
    methods=["POST"]
)
@login_required
def history_delete(entry_id):

    record = ScanHistory.query.get(entry_id)

    if record is None:

        return jsonify({
            "error": "Scan history entry not found."
        }), 404

    if record.user_id != current_user.id:

        return jsonify({
            "error":
            "You are not allowed to delete another user's scan history."
        }), 403

    db.session.delete(record)

    db.session.commit()

    return jsonify({
        "deleted": entry_id
    })


# ==========================================================
# Clear All History (current user only)
# ==========================================================

@history.route(
    "/history/clear",
    methods=["POST"]
)
@login_required
def history_clear():

    deleted = (
        ScanHistory.query
        .filter_by(user_id=current_user.id)
        .delete(synchronize_session=False)
    )

    db.session.commit()

    return jsonify({
        "deleted": deleted
    })
