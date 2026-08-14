from datetime import datetime
from database.db import db


class QuarantineEmail(db.Model):

    __tablename__ = "quarantine_emails"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    email_id = db.Column(
        db.String(255),
        unique=True,
        nullable=False
    )

    sender = db.Column(
        db.String(255)
    )

    subject = db.Column(
        db.String(500)
    )

    body = db.Column(
        db.Text
    )

    risk_score = db.Column(
        db.Integer
    )

    risk_level = db.Column(
        db.String(20)
    )

    verdict = db.Column(
        db.Text
    )

    recommendation = db.Column(
        db.Text
    )

    indicators = db.Column(
        db.Text
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

class ReportedEmail(db.Model):

    __tablename__ = "reported_emails"

    id = db.Column(db.Integer, primary_key=True)

    email_id = db.Column(
        db.String(255),
        unique=True,
        nullable=False
    )

    sender = db.Column(db.String(255))

    subject = db.Column(db.String(500))

    body = db.Column(db.Text)

    risk_score = db.Column(db.Integer)

    risk_level = db.Column(db.String(20))

    verdict = db.Column(db.Text)

    recommendation = db.Column(db.Text)

    indicators = db.Column(db.Text)

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class SafeEmail(db.Model):

    __tablename__ = "safe_emails"

    id = db.Column(db.Integer, primary_key=True)

    email_id = db.Column(
        db.String(255),
        unique=True,
        nullable=False
    )

    sender = db.Column(db.String(255))

    subject = db.Column(db.String(500))

    body = db.Column(db.Text)

    risk_score = db.Column(db.Integer)

    risk_level = db.Column(db.String(20))

    verdict = db.Column(db.Text)

    recommendation = db.Column(db.Text)

    indicators = db.Column(db.Text)

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )