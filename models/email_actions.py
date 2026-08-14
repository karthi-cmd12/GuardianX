from datetime import datetime
from extensions import db


class QuarantineEmail(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    email_id = db.Column(
        db.String(200)
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

    indicators = db.Column(
        db.Text
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )



class ReportedEmail(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    email_id = db.Column(
        db.String(200)
    )

    sender = db.Column(
        db.String(255)
    )

    subject = db.Column(
        db.String(500)
    )

    reason = db.Column(
        db.Text
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )



class SafeEmail(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    email_id = db.Column(
        db.String(200)
    )

    sender = db.Column(
        db.String(255)
    )

    subject = db.Column(
        db.String(500)
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )