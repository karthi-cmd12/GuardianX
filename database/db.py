from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


# ==========================================================
# Database Initialization
# ==========================================================

db = SQLAlchemy()

login_manager = LoginManager()

login_manager.login_view = "auth.login"

login_manager.login_message = "Please login to continue."

login_manager.login_message_category = "warning"



# ==========================================================
# User Model
# ==========================================================

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    full_name = db.Column(
        db.String(100),
        nullable=False
    )

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )


    # ==============================
    # New Verification Fields
    # ==============================

    mobile = db.Column(
        db.String(15),
        unique=True,
        nullable=True
    )


    email_verified = db.Column(
        db.Boolean,
        default=False
    )


    mobile_verified = db.Column(
        db.Boolean,
        default=False
    )


    email_otp = db.Column(
        db.String(6),
        nullable=True
    )


    mobile_otp = db.Column(
        db.String(6),
        nullable=True
    )


    # ==============================
    # Password
    # ==============================

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )
    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )



    # ======================================================
    # Password Handling
    # ======================================================

    def set_password(self, password):

        self.password_hash = generate_password_hash(password)



    def check_password(self, password):

        return check_password_hash(
            self.password_hash,
            password
        )



    # ======================================================
    # String Representation
    # ======================================================

    def __repr__(self):

        return f"<User {self.username}>"




# ==========================================================
# Flask Login User Loader
# ==========================================================

@login_manager.user_loader
def load_user(user_id):

    return User.query.get(int(user_id))