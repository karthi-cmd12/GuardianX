# ==========================================================
# GuardianX Scan History Service
#
# Records privacy-safe scan activity for the logged-in user.
#
# PRIVACY GUARANTEES:
#   - Only safe summaries and generated verdicts are stored.
#   - Raw passwords, full SMS messages, full email bodies,
#     OTPs, PINs, CVVs, tokens and full QR payloads are
#     NEVER persisted.
#   - An optional client request_id prevents duplicate
#     records when the same scan request is retried.
# ==========================================================

import json

from database.db import db
from models.scan_history import ScanHistory
from models.user_settings import UserSettings


# ==========================================================
# Constants
# ==========================================================

ALLOWED_SCAN_TYPES = (
    "Email",
    "URL",
    "SMS",
    "QR",
    "Password",
)

RISK_LEVELS = (
    "LOW",
    "MEDIUM",
    "HIGH",
)

HIGH_MIN = 70
MEDIUM_MIN = 30

SUMMARY_MAX = 500
VERDICT_MAX = 1000
DETAILS_MAX = 6000


# ==========================================================
# Risk Level Mapping
# ==========================================================


def risk_level_for_score(score):
    """
    Maps a 0-100 risk score to LOW / MEDIUM / HIGH using the
    same thresholds as the other GuardianX scanners.
    """
    score = int(score or 0)

    if score >= HIGH_MIN:
        return "HIGH"

    if score >= MEDIUM_MIN:
        return "MEDIUM"

    return "LOW"


def risk_level_for_password(score):
    """
    Password scores are strength scores: a LOW strength score
    represents a HIGH security risk, so the mapping is inverted.
    """
    score = int(score or 0)

    if score >= 60:
        return "LOW"

    if score >= 40:
        return "MEDIUM"

    return "HIGH"


# ==========================================================
# Safe Target Summaries
# ==========================================================


def _truncate(value, length):
    value = str(value or "").strip()

    if len(value) <= length:
        return value

    return value[: length - 3] + "..."


def build_input_preview(scan_type, result):
    """
    Returns the privacy-safe input preview for a scan result.
    Content is reduced to a generic description unless the
    scan type already produces a safe, masked summary (URL).
    """
    scan_type = str(scan_type or "").strip()

    if scan_type == "URL":
        return _truncate(
            result.get("normalized_url")
            or result.get("input_preview")
            or "URL analyzed",
            SUMMARY_MAX,
        )

    if scan_type == "QR":
        if result.get("content_type") == "URL":
            return "QR code containing URL"

        return "QR code content analyzed"

    if scan_type == "Email":
        return "Email message analyzed"

    if scan_type == "SMS":
        return "SMS message analyzed"

    if scan_type == "Password":
        return "Password analyzed"

    return _truncate(
        result.get("input_preview")
        or "Security scan analyzed",
        SUMMARY_MAX,
    )


def build_scan_details(scan_type, result):
    """
    Builds a privacy-safe per-scan details dict from a scanner
    result.

    Only safe, generated information is included: indicators,
    recommendation and small structural facts. Raw passwords,
    message bodies, email contents, OTPs, PINs, CVVs, tokens and
    full QR payloads are NEVER included.
    """
    scan_type = str(scan_type or "").strip()

    if scan_type == "URL":
        return {
            "hostname": result.get("hostname"),
            "indicators": result.get("indicators") or [],
            "recommendation": result.get("recommendation"),
        }

    if scan_type == "SMS":
        return {
            "sender_type": result.get("sender_type"),
            "indicators": result.get("indicators") or [],
            "recommendation": result.get("recommendation"),
            "link_risk": (result.get("link") or {}).get("risk_level"),
        }

    if scan_type == "Email":
        return {
            "sender_trust_score": result.get("sender_trust_score"),
            "indicators": result.get("indicators") or [],
            "recommendation": result.get("recommendation"),
            "link_count": len(result.get("links") or []),
            "attachment_count": len(result.get("attachments") or []),
        }

    if scan_type == "Password":
        return {
            "score": result.get("score"),
            "strength": result.get("strength"),
            "weaknesses": result.get("weaknesses") or [],
            "recommendations": result.get("recommendations") or [],
        }

    if scan_type == "QR":
        return {
            "content_type": result.get("content_type"),
            "hostname": result.get("hostname"),
            "indicators": result.get("indicators") or [],
            "recommendation": result.get("recommendation"),
        }

    return None


def parse_details(record):
    """
    Parses the stored JSON ``details`` back into a dict (or
    None when absent / malformed).
    """
    value = getattr(record, "details", None)

    if not value:
        return None

    try:
        data = json.loads(value)
    except (TypeError, ValueError):
        return None

    return data if isinstance(data, dict) else None


# ==========================================================
# Recording
# ==========================================================


def _history_enabled(user_id):
    """
    Respects the user's "Automatically save scan history"
    preference. Defaults to enabled when the user has not
    configured settings yet.
    """
    settings = UserSettings.query.filter_by(
        user_id=user_id
    ).first()

    if settings is None:
        return True

    return bool(settings.save_scan_history)


def record_scan(
    user_id,
    scan_type,
    risk_score,
    risk_level,
    input_preview,
    verdict,
    request_id=None,
    details=None,
):
    """
    Records one scan history entry for the given user.

    ``details`` is an optional safe dict (see build_scan_details)
    serialized to JSON. Returns the created ScanHistory record,
    or the existing record when a request_id is provided that was
    already recorded (idempotent retries). Returns None when the
    user has disabled automatic scan history.
    """
    if not _history_enabled(user_id):
        return None

    scan_type = str(scan_type or "").strip()

    if scan_type not in ALLOWED_SCAN_TYPES:
        return None

    risk_level = str(risk_level or "").upper()

    if risk_level not in RISK_LEVELS:
        risk_level = risk_level_for_score(risk_score)

    if request_id:
        existing = ScanHistory.query.filter_by(
            user_id=user_id,
            request_id=request_id,
        ).first()

        if existing is not None:
            return existing

    details_json = None

    if details is not None:
        try:
            details_json = json.dumps(details, default=str)[
                :DETAILS_MAX
            ]
        except (TypeError, ValueError):
            details_json = None

    record = ScanHistory(
        user_id=user_id,
        scan_type=scan_type,
        risk_level=risk_level,
        risk_score=max(0, min(int(risk_score or 0), 100)),
        input_preview=_truncate(input_preview, SUMMARY_MAX),
        verdict=_truncate(verdict, VERDICT_MAX),
        request_id=request_id or None,
        details=details_json,
    )

    db.session.add(record)

    db.session.commit()

    return record
