import os

from flask_dance.contrib.google import make_google_blueprint

google_bp = make_google_blueprint(

    client_id=os.environ.get("GOOGLE_OAUTH_CLIENT_ID", ""),

    client_secret=os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", ""),

    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/gmail.readonly"
    ],

    redirect_url="/email-detector",

    offline=True

)

