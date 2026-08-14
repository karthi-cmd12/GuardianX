# ==========================================================
# GuardianX User Settings Model
#
# Per-user preferences for the Profile & Settings feature.
# Each row belongs to exactly one user (user_id is unique)
# and is only ever read or written for the logged-in user.
# No sensitive data (passwords, tokens) is stored here.
# ==========================================================

from datetime import datetime

from database.db import db


# ==========================================================
# UserSettings Model
# ==========================================================

class UserSettings(db.Model):

    __tablename__ = "user_settings"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        unique=True,
        index=True
    )

    # ---------- Security ----------

    security_alerts = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    # ---------- Scan ----------

    save_scan_history = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    detailed_results = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    # "level" shows a risk badge, "score" shows the numeric score.
    default_risk_display = db.Column(
        db.String(10),
        nullable=False,
        default="level"
    )

    # ---------- Interface ----------

    compact_mode = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    animations_enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    reduced_motion = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    # ---------- Account ----------

    # Tracked here (not on User) so existing users/rows are
    # not altered by the new feature.
    last_password_changed = db.Column(
        db.DateTime,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    def __repr__(self):

        return "<UserSettings {}>".format(self.user_id)


# ==========================================================
# Helper
# ==========================================================

def get_user_settings(user_id):
    """
    Returns the settings row for a user, creating it with
    defaults on first access. Always called with the logged-in
    user's id only.
    """
    settings = UserSettings.query.filter_by(
        user_id=user_id
    ).first()

    if settings is None:

        settings = UserSettings(
            user_id=user_id
        )

        db.session.add(settings)

        db.session.commit()

    return settings
