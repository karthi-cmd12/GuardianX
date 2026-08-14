from flask import Blueprint, render_template
from flask_login import login_required

from database.email_models import QuarantineEmail

quarantine = Blueprint(
    "quarantine",
    __name__
)


@quarantine.route("/quarantine")
@login_required
def quarantine_page():

    emails = QuarantineEmail.query.order_by(
        QuarantineEmail.created_at.desc()
    ).all()

    return render_template(
        "quarantine.html",
        emails=emails
    )