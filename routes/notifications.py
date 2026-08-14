# ==========================================================
# GuardianX Notification Center Routes
#
# A user can only ever see and modify their OWN notifications.
# All endpoints require login and ownership is always verified:
# unknown or foreign notification IDs return 404 so IDs cannot
# be probed across users.
# ==========================================================

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from database.db import db
from models.notification import Notification

from services.notification_service import (
    SEVERITIES,
    TYPE_LABELS,
    serialize,
    unread_count,
    get_owned_notification,
)


# ==========================================================
# Blueprint
# ==========================================================

notifications = Blueprint(
    "notifications",
    __name__
)


# ==========================================================
# Notification Center Page
# ==========================================================

@notifications.route("/notifications")
@login_required
def notifications_page():

    return render_template(
        "notifications.html"
    )


# ==========================================================
# Helpers
# ==========================================================

def _int_arg(name, default):
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


def _stats_for(user_id):
    """
    Summary counts over the user's ENTIRE notification set
    (unaffected by the active filters).
    """
    rows = Notification.query.filter_by(
        user_id=user_id
    ).all()

    stats = {
        "total": len(rows),
        "unread": sum(1 for row in rows if not row.is_read),
        "read": sum(1 for row in rows if row.is_read),
    }

    for severity in SEVERITIES:
        stats[severity.lower()] = sum(
            1 for row in rows if row.severity == severity
        )

    return stats


# ==========================================================
# Notification Data API
# ==========================================================

@notifications.route(
    "/notifications/data",
    methods=["GET"]
)
@login_required
def notifications_data():
    """
    Returns the logged-in user's notifications.

    Optional filters:
      - severity: INFO | LOW | MEDIUM | HIGH | CRITICAL
      - type: email | url | sms | qr | password |
              ai_assistant | history | system
      - read: read | unread
    """

    query = Notification.query.filter_by(
        user_id=current_user.id
    )

    severity = (request.args.get("severity") or "").strip().upper()

    if severity in SEVERITIES:
        query = query.filter(
            Notification.severity == severity
        )

    notification_type = (
        request.args.get("type") or ""
    ).strip().lower()

    if notification_type:
        query = query.filter(
            Notification.notification_type == notification_type
        )

    read_state = (request.args.get("read") or "").strip().lower()

    if read_state == "read":
        query = query.filter(
            Notification.is_read.is_(True)
        )
    elif read_state == "unread":
        query = query.filter(
            Notification.is_read.is_(False)
        )

    limit = min(_int_arg("limit", 100), 500)
    offset = max(_int_arg("offset", 0), 0)

    total = query.count()

    rows = (
        query
        .order_by(
            Notification.created_at.desc(),
            Notification.id.desc()
        )
        .limit(limit)
        .offset(offset)
        .all()
    )

    return jsonify({
        "items": [serialize(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "unread_count": unread_count(current_user.id),
        "stats": _stats_for(current_user.id),
        "type_labels": TYPE_LABELS,
    })


# ==========================================================
# Mark One Notification Read
# ==========================================================

@notifications.route(
    "/notifications/<int:notification_id>/read",
    methods=["POST"]
)
@login_required
def notifications_read(notification_id):

    record = get_owned_notification(
        current_user.id,
        notification_id
    )

    if record is None:

        return jsonify({
            "error": "Notification not found."
        }), 404

    if not record.is_read:
        record.is_read = True
        db.session.commit()

    from services.notification_service import destination_for_type

    return jsonify({
        "ok": True,
        "notification_id": record.id,
        "destination": (
            record.destination
            or destination_for_type(record.notification_type)
        ),
        "unread_count": unread_count(current_user.id),
    })


# ==========================================================
# Mark All Read
# ==========================================================

@notifications.route(
    "/notifications/read-all",
    methods=["POST"]
)
@login_required
def notifications_read_all():

    updated = (
        Notification.query
        .filter_by(
            user_id=current_user.id,
            is_read=False
        )
        .update(
            {Notification.is_read: True},
            synchronize_session=False
        )
    )

    db.session.commit()

    return jsonify({
        "ok": True,
        "updated": updated,
        "unread_count": 0,
    })


# ==========================================================
# Delete One Notification
# ==========================================================

@notifications.route(
    "/notifications/<int:notification_id>/delete",
    methods=["POST"]
)
@login_required
def notifications_delete(notification_id):

    record = get_owned_notification(
        current_user.id,
        notification_id
    )

    if record is None:

        return jsonify({
            "error": "Notification not found."
        }), 404

    db.session.delete(record)

    db.session.commit()

    return jsonify({
        "ok": True,
        "deleted": notification_id,
        "unread_count": unread_count(current_user.id),
    })


# ==========================================================
# Clear All Notifications
# ==========================================================

@notifications.route(
    "/notifications/clear",
    methods=["POST"]
)
@login_required
def notifications_clear():

    deleted = (
        Notification.query
        .filter_by(user_id=current_user.id)
        .delete(synchronize_session=False)
    )

    db.session.commit()

    return jsonify({
        "ok": True,
        "deleted": deleted,
        "unread_count": 0,
    })
