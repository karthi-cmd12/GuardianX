# AGENTS.md

GuardianX — Flask app for AI-powered phishing/scam detection (email, SMS, URL, QR). Runs on Windows with a local venv.

## Run & verify
- Start app: `venv\Scripts\python.exe app.py` → http://127.0.0.1:5000 (debug mode). On Windows always invoke Python via `venv\Scripts\python.exe`.
- There are **no tests, no CI, no linter/formatter**. To verify changes, import the app and inspect the route map:
  `venv\Scripts\python.exe -c "import app; [print(r.rule) for r in app.app.url_map.iter_rules()]"`
- `app.py` runs `db.create_all()` at import time on the SQLite DB, so importing it also (re)creates tables. Deleting `guardianx.db` resets all data.

## Dependencies (gotcha)
- `requirements.txt` lists the packages the app actually imports (Flask, Werkzeug, Flask-Login, Flask-SQLAlchemy, Flask-Dance, google-auth, google-auth-oauthlib, google-api-python-client, joblib). `nltk`/`sklearn`/`pandas` are installed in `venv` but unused by app code and intentionally not listed.

## Architecture
- Entrypoint `app.py` registers all blueprints. A new route file is dead code until imported+registered there. Currently **unregistered**: `routes/admin.py`, `routes/history.py`, `routes/profile.py`, `routes/detector.py`, and the `gmail_auth` blueprint in `gmail/auth.py`.
- Two overlapping Gmail OAuth flows exist; only the **Flask-Dance one is live**: `gmail/oauth.py` (`google_bp`, registered under `/login`, redirects to `/email-detector`). `gmail/auth.py` (OAuthlib `Flow` + `credentials/credentials.json`) is legacy/unregistered. `gmail/service.py` builds the Gmail API client from the Flask-Dance token.
- `app.py` and `gmail/auth.py` must set `os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"` **before** importing `flask_dance`/`google_auth_oauthlib`; keep that ordering.
- AI is rule/keyword based, not ML. Email analysis: `ai/detector.py:analyze_email()`. Message/SMS analysis: `ai_engine/threat_analyzer.py` + `ai_engine/risk_score.py`. `ai_engine/model_loader.py` loads `ai_engine/threat_model.pkl` when present; it does not exist, so `model_status()` falls back to `RULE_ENGINE`. No training script exists; `sklearn`/`nltk`/`pandas` in venv are unused by app code.
- DB models: `database/db.py` (User, LoginManager) and `database/email_models.py` (QuarantineEmail, ReportedEmail, SafeEmail). `database/seed.py` is empty.

## Security (current setup)
- Secrets are read from environment variables, never hardcoded: `config.py` uses `SECRET_KEY` (with a dev-only fallback), and `gmail/oauth.py` + `gmail/service.py` use `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET`. Without those Google vars set, Google login is unavailable but the app still imports and runs.
- `credentials/credentials.json` (the OAuthlib client secret file, used only by the legacy `gmail/auth.py` flow) and the local `guardianx.db` are gitignored — never commit them or any `.env` files.
- Uploads are capped at 16 MB via `MAX_CONTENT_LENGTH`; files land in `uploads/` (gitignored).
- Flask-Login guards most pages (`login_view = "auth.login"`); new routes requiring auth should use `@login_required`.
