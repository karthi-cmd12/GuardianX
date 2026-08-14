from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from database.db import db
import random


verification = Blueprint(
    "verification",
    __name__
)


# ==========================================================
# Generate OTP
# ==========================================================

def generate_otp():

    return str(
        random.randint(100000, 999999)
    )



# ==========================================================
# Verify Email
# ==========================================================

@verification.route("/verify-email", methods=["GET", "POST"])
@login_required
def verify_email():


    if current_user.email_verified:

        return redirect(
            url_for("verification.verify_mobile")
        )


    if current_user.email_otp is None:

        current_user.email_otp = generate_otp()

        db.session.commit()


        print(
            "EMAIL OTP:",
            current_user.email_otp
        )


    if request.method == "POST":

        otp = request.form.get("otp")


        if otp == current_user.email_otp:


            current_user.email_verified = True

            current_user.email_otp = None

            db.session.commit()


            flash(
                "Email verified successfully.",
                "success"
            )


            return redirect(
                url_for(
                    "verification.verify_mobile"
                )
            )


        flash(
            "Invalid Email OTP.",
            "danger"
        )


    return render_template(
        "verify_email.html"
    )



# ==========================================================
# Verify Mobile
# ==========================================================

@verification.route("/verify-mobile", methods=["GET", "POST"])
@login_required
def verify_mobile():


    if current_user.mobile_verified:

        return redirect(
            url_for(
                "dashboard.dashboard_home"
            )
        )


    if current_user.mobile_otp is None:

        current_user.mobile_otp = generate_otp()

        db.session.commit()


        print(
            "MOBILE OTP:",
            current_user.mobile_otp
        )


    if request.method == "POST":

        otp = request.form.get("otp")


        if otp == current_user.mobile_otp:


            current_user.mobile_verified = True

            current_user.mobile_otp = None

            db.session.commit()


            flash(
                "Mobile verified successfully.",
                "success"
            )


            return redirect(
                url_for(
                    "dashboard.dashboard_home"
                )
            )


        flash(
            "Invalid Mobile OTP.",
            "danger"
        )


    return render_template(
        "verify_mobile.html"
    )