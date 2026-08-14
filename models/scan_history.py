# ==========================================================
# GuardianX Scan History Model
#
# Privacy-first scan activity tracking. Only safe summaries
# are persisted here:
#   - URL       -> normalized (sensitive query values masked)
#   - SMS       -> generic summary, never the message content
#   - QR        -> generic summary, never the raw payload
#   - EMAIL     -> generic summary, never the email content
#   - PASSWORD  -> generic summary, the password is NEVER stored
# ==========================================================

from datetime import datetime

from database.db import db


class ScanHistory(db.Model):

    __tablename__ = "scan_history"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    scan_type = db.Column(
        db.String(20),
        nullable=False
    )

    risk_level = db.Column(
        db.String(10),
        nullable=False
    )

    risk_score = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    # Safe input preview only. Never raw passwords, message
    # bodies, email contents, OTPs, PINs, tokens or full QR
    # payloads.
    input_preview = db.Column(
        db.String(500),
        nullable=False
    )

    verdict = db.Column(
        db.String(1000),
        nullable=False
    )

    # Optional per-scan safe detail summary (JSON string):
    # indicators, recommendation and a few structural facts.
    # Never contains raw message bodies, passwords, OTPs, PINs,
    # CVVs, tokens or full QR payloads.
    details = db.Column(
        db.Text,
        nullable=True
    )

    # Client-provided idempotency key used to avoid duplicate
    # records when the same scan request is retried.
    request_id = db.Column(
        db.String(64),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        index=True
    )

    __table_args__ = (
        db.Index(
            "ix_scan_history_user_created",
            "user_id",
            "created_at"
        ),
    )

    def __repr__(self):

        return "<ScanHistory {} {}>".format(
            self.id,
            self.scan_type
        )


def migrate_add_details_column():
    """
    Idempotently adds the ``details`` column to an existing
    ``scan_history`` table (there is no migration tool in this
    project, so this tiny helper keeps existing databases
    working without deleting guardianx.db).
    """
    from sqlalchemy import inspect, text

    from database.db import db

    inspector = inspect(db.engine)

    if "scan_history" not in inspector.get_table_names():
        return

    columns = {
        column["name"]
        for column in inspector.get_columns("scan_history")
    }

    if "details" in columns:
        return

    db.session.execute(
        text(
            "ALTER TABLE scan_history ADD COLUMN details TEXT"
        )
    )

    db.session.commit()
