# GuardianX

GuardianX is an AI-powered cybersecurity & scam detection platform that protects you from phishing emails, malicious URLs, scam SMS messages, dangerous QR codes, and weak passwords.

Built with Flask, GuardianX combines a rule-based AI analysis engine with a premium responsive dashboard to scan content in real time, compute risk scores, and give actionable security recommendations.

## Features

- AI-powered cybersecurity analysis
- Fake Email Detection
- URL Scanner
- SMS Scam Detection
- Password Strength Analyzer
- QR Code Scanner
- AI Assistant
- Risk Score Analysis
- Security Recommendations
- Scan History
- Security Alerts
- User Authentication
- Responsive premium dashboard

## Technology Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | HTML, CSS, JavaScript, Bootstrap, Font Awesome |
| **Backend** | Python, Flask |
| **Database** | SQLite / SQLAlchemy |
| **AI/ML** | Python ML components, joblib, and project-specific detection logic |

## Project Structure

```
GuardianX/
├── app.py                  # Flask application entry point
├── config.py               # Application configuration (env-driven)
├── requirements.txt        # Python dependencies
├── ai/                     # Email detection logic (rule/keyword engine)
├── ai_engine/              # Threat analyzer, risk scoring, model loader
├── database/               # SQLAlchemy models & database setup
├── gmail/                  # Gmail OAuth (Flask-Dance) & Gmail API service
├── models/                 # Detection models (password, URL, SMS, QR, scan history)
├── routes/                 # Blueprint route handlers
├── services/               # Business logic (notifications, scan history, etc.)
├── integrations/           # Gmail API, SMS reader, WhatsApp monitor
├── utils/                  # Helpers (email parser, validators, logger, scanner)
├── templates/              # Jinja2 HTML templates
├── static/                 # CSS, JS, images
├── datasets/               # Sample phishing/URL/SMS datasets
├── credentials/            # (Local only - NOT committed) Google OAuth credentials
└── uploads/                # (Runtime only - NOT committed) Uploaded files
```

## Installation

### Prerequisites

- Python 3.10+ installed on Windows
- Git installed

### Windows Setup

```bash
git clone <repository-url>
cd GuardianX
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
py app.py
```

Then open your browser and visit:

```
http://127.0.0.1:5000/
```

### Environment Variables

GuardianX reads sensitive configuration from environment variables so no secrets are stored in the repository. Set them before running the app if you want to use Gmail login:

```bash
set SECRET_KEY=your-random-secret-key
set GOOGLE_OAUTH_CLIENT_ID=your-google-client-id
set GOOGLE_OAUTH_CLIENT_SECRET=your-google-client-secret
```

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Optional* | Flask session signing key. A development fallback is built in. |
| `GOOGLE_OAUTH_CLIENT_ID` | For Gmail login | Google OAuth app client ID |
| `GOOGLE_OAUTH_CLIENT_SECRET` | For Gmail login | Google OAuth app client secret |

\* `SECRET_KEY` has a development-only default. Always set a strong value in production.

### Local Gmail OAuth (Optional)

For Gmail login you must create an OAuth app in the [Google Cloud Console](https://console.cloud.google.com/) and add `http://127.0.0.1:5000` as an authorized redirect origin.

## Usage

1. Register an account or log in.
2. Use the dashboard to access the tools:
   - **Email Detector** – paste or connect Gmail to scan emails for phishing.
   - **URL Scanner** – check if a link is malicious.
   - **SMS Detector** – analyze SMS messages for scams.
   - **QR Scanner** – upload or scan QR codes for dangerous URLs.
   - **Password Analyzer** – check password strength.
   - **AI Assistant** – ask security-related questions.
3. Review the risk score, threat indicators, and recommendations for each scan.
4. Track all scans and security alerts from the History and Notifications pages.

## Security Notice

GuardianX is an **educational / project** cybersecurity tool. Its detection engine is primarily rule- and keyword-based and is **not** a substitute for a professional, continuously updated security solution. Do not rely on it as your sole protection mechanism. Always combine it with official security software, strong unique passwords, and cautious online behavior.

## Future Enhancements

- Mobile SMS integration
- WhatsApp integration
- Advanced AI threat analysis
- Real-time threat intelligence
- Improved ML models
- Browser/mobile integration

## Author

Karthi

GitHub: [https://github.com/karthi-cmd12](https://github.com/karthi-cmd12)
