from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from database.db import db, User


# ==========================================================
# Blueprint
# ==========================================================

auth = Blueprint("auth", __name__)


# ==========================================================
# Register
# ==========================================================

@auth.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(
            url_for("dashboard.dashboard_home")
        )


    if request.method == "POST":

        full_name = request.form.get("full_name")
        username = request.form.get("username")
        email = request.form.get("email")
        mobile = request.form.get("mobile")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")


        # ----------------------------
        # Validation
        # ----------------------------

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return redirect(
                url_for("auth.register")
            )


        existing_email = User.query.filter_by(
            email=email
        ).first()


        if existing_email:

            flash(
                "Email already exists.",
                "warning"
            )

            return redirect(
                url_for("auth.register")
            )


        existing_username = User.query.filter_by(
            username=username
        ).first()


        if existing_username:

            flash(
                "Username already exists.",
                "warning"
            )

            return redirect(
                url_for("auth.register")
            )


        existing_mobile = User.query.filter_by(
            mobile=mobile
        ).first()


        if existing_mobile:

            flash(
                "Mobile number already exists.",
                "warning"
            )

            return redirect(
                url_for("auth.register")
            )


        # ----------------------------
        # Create User
        # ----------------------------

        user = User(

            full_name=full_name,

            username=username,

            email=email,

            mobile=mobile

        )


        user.set_password(password)


        db.session.add(user)

        db.session.commit()


        # Automatically login after registration

        login_user(user)


        flash(
            "Registration successful. Verify your email.",
            "success"
        )


        return redirect(
            url_for(
                "verification.verify_email"
            )
        )


    return render_template("register.html")



# ==========================================================
# Login
# ==========================================================

@auth.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard.dashboard_home")
        )


    if request.method == "POST":

        username = request.form.get("username")

        password = request.form.get("password")


        user = User.query.filter_by(
            username=username
        ).first()


        if user and user.check_password(password):

            login_user(user)


            flash(
                "Welcome back!",
                "success"
            )


            return redirect(
                url_for(
                    "dashboard.dashboard_home"
                )
            )


        flash(
            "Invalid username or password.",
            "danger"
        )


    return render_template("login.html")



# ==========================================================
# Logout
# ==========================================================

@auth.route("/logout")
@login_required
def logout():

    logout_user()


    flash(
        "Logged out successfully.",
        "info"
    )


    return redirect(
        url_for("auth.login")
    )