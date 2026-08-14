# ==========================================================
# GuardianX QR Code Content Analyzer
#
# Offline, static classifier for decoded QR code payloads.
# This module NEVER opens, visits, downloads, redirects to or
# executes decoded content. When the payload is a URL it is
# analyzed with the same offline structural scanner used by
# the URL Detector (models.url_detector). No URL risk-scoring
# logic is duplicated here.
# ==========================================================

import re

from models.url_detector import scan_url


# ==========================================================
# Content Type Detection
# ==========================================================

SCHEME_PATTERNS = [
    ("EMAIL", re.compile(r"^mailto:", re.IGNORECASE)),
    ("PHONE", re.compile(r"^tel:", re.IGNORECASE)),
    ("WIFI", re.compile(r"^wifi:", re.IGNORECASE)),
    ("SMS", re.compile(r"^sms(?:to)?:", re.IGNORECASE)),
    ("PAYMENT", re.compile(r"^upi:", re.IGNORECASE)),
]

VCARD_RE = re.compile(r"^BEGIN:VCARD", re.IGNORECASE)

EMAIL_RE = re.compile(
    r"^[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+$"
)

URL_SCHEME_RE = re.compile(
    r"^https?://",
    re.IGNORECASE,
)

# Bare domain (or IP) with optional path, e.g. "example.com",
# "example.com/login" or "192.168.1.1".
BARE_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)+"
    r"(?:/[^\s]*)?$",
    re.IGNORECASE,
)

# Phone numbers: an optional leading + followed by 7-15 digits.
PHONE_RE = re.compile(r"^\+?\d{7,15}$")


def classify_qr_content(content):
    """
    Classifies a decoded QR payload into one of:
    URL, EMAIL, PHONE, WIFI, SMS, PAYMENT, CONTACT, TEXT or
    UNKNOWN.

    Only structural classification; never opens or resolves
    anything.
    """
    if not content or not isinstance(content, str):
        return "UNKNOWN"

    value = content.strip()

    if not value:
        return "UNKNOWN"

    for content_type, pattern in SCHEME_PATTERNS:

        if pattern.match(value):
            return content_type

    if VCARD_RE.match(value):
        return "CONTACT"

    if EMAIL_RE.match(value):
        return "EMAIL"

    if URL_SCHEME_RE.match(value):
        return "URL"

    if BARE_DOMAIN_RE.match(value):
        return "URL"

    if PHONE_RE.match(value):
        return "PHONE"

    return "TEXT"


# ==========================================================
# Verdict + Recommendation Generation
# ==========================================================

NON_URL_VERDICT = "No URL was detected in this QR code."

NON_URL_RECOMMENDATION = (
    "Review the decoded content before sharing or using it."
)


def _qr_url_verdict(level):
    if level == "LOW":
        return (
            "This QR code contains a URL that appears relatively "
            "safe based on the available checks."
        )

    if level == "MEDIUM":
        return (
            "This QR code contains a URL with some suspicious "
            "characteristics. Verify the destination before opening it."
        )

    return (
        "This QR code contains a URL with multiple suspicious "
        "indicators. Avoid opening it unless you can verify the "
        "destination."
    )


# ==========================================================
# Main Analyze Function
# ==========================================================


def analyze_qr(content):
    """
    Analyzes a decoded QR code payload.

    For URL payloads the existing offline URL scanner
    (models.url_detector.scan_url) is reused verbatim.

    For non-URL payloads the content type is reported with a
    neutral LOW risk; non-URL content is never classified as
    malicious just for existing.
    """
    content_type = classify_qr_content(content)

    content_value = (content or "").strip()

    if content_type != "URL":

        return {
            "valid": True,
            "content_type": content_type,
            "content": content_value,
            "risk_score": 0,
            "risk_level": "LOW",
            "verdict": NON_URL_VERDICT,
            "recommendation": NON_URL_RECOMMENDATION,
            "indicators": [],
            "checks": [],
            "analysis": None,
        }

    url_result = scan_url(content_value)

    if not url_result.get("valid"):

        return {
            "valid": True,
            "content_type": "URL",
            "content": content_value,
            "risk_score": 0,
            "risk_level": "LOW",
            "verdict": NON_URL_VERDICT,
            "recommendation": NON_URL_RECOMMENDATION,
            "indicators": [],
            "checks": [],
            "analysis": None,
        }

    return {
        "valid": True,
        "content_type": "URL",
        "content": content_value,
        "risk_score": url_result["risk_score"],
        "risk_level": url_result["risk_level"],
        "verdict": _qr_url_verdict(url_result["risk_level"]),
        "recommendation": url_result["recommendation"],
        "indicators": url_result["indicators"],
        "checks": url_result["checks"],
        "normalized_url": url_result.get("normalized_url"),
        "hostname": url_result.get("hostname"),
        "scheme": url_result.get("scheme"),
        "analysis": url_result.get("analysis"),
    }
