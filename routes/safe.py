from flask import Blueprint, render_template
from flask_login import login_required

from database.email_models import SafeEmail

safe = Blueprint(
    "safe",
    __name__
)


@safe.route("/safe")
@login_required
def safe_page():

    emails = SafeEmail.query.order_by(
        SafeEmail.created_at.desc()
    ).all()

    return render_template(
        "safe.html",
        emails=emails
    )