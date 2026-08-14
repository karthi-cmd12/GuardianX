import os

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

from flask import Blueprint, redirect, session, url_for, request
from google_auth_oauthlib.flow import Flow

gmail_auth = Blueprint("gmail_auth", __name__)

CLIENT_SECRET_FILE = os.path.join(
    "credentials",
    "credentials.json"
)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]


@gmail_auth.route("/connect-gmail")
def connect_gmail():

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        redirect_uri=url_for(
            "gmail_auth.oauth2callback",
            _external=True
        )
    )

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent"
    )

    session["state"] = state

    return redirect(authorization_url)


@gmail_auth.route("/oauth2callback")
def oauth2callback():

    state = session.get("state")

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for(
            "gmail_auth.oauth2callback",
            _external=True
        )
    )

    flow.fetch_token(
        authorization_response=request.url
    )

    credentials = flow.credentials

    session["credentials"] = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes
    }

    return redirect(
        url_for("email_detector.email_detector_home")
    )