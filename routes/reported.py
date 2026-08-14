from flask import Blueprint, render_template
from flask_login import login_required

from database.email_models import ReportedEmail

reported = Blueprint(
    "reported",
    __name__
)


@reported.route("/reported")
@login_required
def reported_page():

    emails = ReportedEmail.query.order_by(
        ReportedEmail.created_at.desc()
    ).all()

    return render_template(
        "reported.html",
        emails=emails
    )