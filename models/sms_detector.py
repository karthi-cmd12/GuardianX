# ==========================================================
# GuardianX SMS Threat Analyzer
#
# Offline, static, heuristic SMS scam detection engine.
# This module NEVER makes network requests: it does not
# resolve links, call numbers, query phone registries or
# contact any external service. It performs textual analysis
# only. When a message contains a URL, that URL is analyzed
# with the same offline structural scanner used by the URL
# Detector (models.url_detector).
# ==========================================================

import re

from models.url_detector import scan_url


# ==========================================================
# Configurable Signal Lists
# (kept together in one place so they are easy to extend)
# ==========================================================

# Urgency / pressure tactics used to rush the receiver into
# acting without thinking.
URGENCY_PHRASES = [
    "urgent",
    "urgently",
    "immediately",
    "immediate action",
    "act now",
    "act immediately",
    "asap",
    "right away",
    "last chance",
    "final notice",
    "final reminder",
    "final warning",
    "expires today",
    "expiring",
    "expires soon",
    "today only",
    "limited time",
    "deadline",
    "before it is too late",
    "before it's too late",
    "within 24 hours",
    "within the next",
    "respond now",
    "must reply",
    "do not delay",
    "hurry",
]

# Requests for credentials, identity details or payment data.
# NEVER echoed back; presence alone is a strong scam signal.
# Only REQUEST-type phrasing is matched so informative service
# messages (e.g. "Your OTP is ...") are not flagged.
SENSITIVE_INFO_PHRASES = [
    "verify otp",
    "enter your otp",
    "enter your pin",
    "enter your passcode",
    "send otp",
    "send your otp",
    "share your otp",
    "provide your otp",
    "confirm your otp",
    "type your otp",
    "one time password",
    "one-time password",
    "confirm your password",
    "enter your password",
    "update your password",
    "reset your password",
    "password has expired",
    "password will expire",
    "verify your account",
    "verify your identity",
    "verify your details",
    "verify account",
    "confirm your account",
    "confirm your identity",
    "confirm your details",
    "unlock your account",
    "update your account",
    "update your details",
    "reactivate your account",
    "account has been locked",
    "account will be blocked",
    "bank details",
    "card details",
    "card number",
    "credit card",
    "debit card",
    "account number",
    "account details",
    "pan number",
    "pan card",
    "aadhaar",
    "aadhar",
    "ssn",
    "kyc",
    "kyc update",
    "complete your kyc",
    "biometric",
    "provide your details",
    "submit your details",
    "share your details",
    "send your details",
    "please confirm",
    "identity verification",
    "security question",
]

# Money / prize / freebie bait. Often combined with a "fee"
# to release the prize or a link to a phishing form.
MONEY_BAIT_PHRASES = [
    "you have won",
    "you won",
    "you win",
    "winner",
    "congratulations",
    "congrats",
    "lottery",
    "jackpot",
    "prize",
    "cash prize",
    "cash reward",
    "cashback",
    "claim your prize",
    "claim your reward",
    "claim your cash",
    "claim reward",
    "claim prize",
    "reward",
    "you have been selected",
    "you are selected",
    "lucky",
    "lucky winner",
    "free gift",
    "free voucher",
    "free iphone",
    "free vacation",
    "free trip",
    "gift card",
    "discount offer",
    "special offer",
    "limited offer",
    "cash bonus",
    "refund",
    "tax refund",
    "gst refund",
    "money transfer",
    "inheritance",
    "transfer the amount",
    "processing fee",
    "delivery fee",
    "registration fee",
    "send money",
    "receive money",
    "earn money",
    "make money",
    "guaranteed",
    "no risk",
    "too good to be true",
]

# Brands, authorities and service desks frequently impersonated
# in SMS scams.
IMPERSONATION_BRANDS = [
    "sbi",
    "state bank of india",
    "hdfc bank",
    "icici bank",
    "axis bank",
    "kotak",
    "canara bank",
    "pnb",
    "paytm",
    "phonepe",
    "gpay",
    "google pay",
    "amazon",
    "flipkart",
    "myntra",
    "netflix",
    "paypal",
    "apple",
    "microsoft",
    "google",
    "whatsapp",
    "instagram",
    "facebook",
    "fedex",
    "dhl",
    "ups",
    "india post",
    "irctc",
    "aadhaar",
    "income tax",
    "gst",
    "epfo",
    "customer care",
    "support team",
    "security team",
    "help desk",
    "service desk",
    "bank official",
]

# Threats or negative consequences used to pressure the receiver.
THREAT_PHRASES = [
    "legal action",
    "court case",
    "lawsuit",
    "arrest",
    "arrest warrant",
    "warrant",
    "police case",
    "police complaint",
    "case filed",
    "penalty",
    "fine",
    "charges will apply",
    "you will be charged",
    "suspended",
    "will be suspended",
    "blocked",
    "will be blocked",
    "deactivated",
    "will be deactivated",
    "terminated",
    "will be terminated",
    "closed permanently",
    "seized",
    "action will be taken",
    "immediate action",
    "non-compliance",
    "tax fraud",
    "money laundering",
    "cyber crime",
]

# Common call-to-action / reply-bait instructions.
REPLY_BAIT_PHRASES = [
    "click the link",
    "click this link",
    "click here",
    "click below",
    "click on the link",
    "tap the link",
    "tap here",
    "tap the below link",
    "tap on the link",
    "open the link",
    "open this link",
    "visit the link",
    "reply yes",
    "reply stop",
    "reply ok",
    "text stop",
    "send stop",
    "type yes",
    "type stop",
    "call now",
    "call immediately",
    "call this number",
    "call the number",
    "call us now",
    "dial this number",
    "contact immediately",
    "contact us now",
    "visit the website",
]

# Low-weight language-quality red flags: generic greetings and
# misspellings common in scam / bulk messages.
GENERIC_GREETINGS = [
    "dear customer",
    "dear sir",
    "dear madam",
    "dear sir/madam",
    "dear user",
    "respected customer",
    "valued customer",
    "kindly",
]

COMMON_MISSPELLINGS = [
    "pyment",
    "pament",
    "paymnt",
    "acount",
    "accountt",
    "verif",
    "verifycation",
    "verfication",
    "congatulations",
    "congradulations",
    "winnger",
    "winer",
    "guaranteed",
    "guranteed",
    "recive",
    "recieve",
    "refnd",
    "refun",
    "resone",
    "unsubsribe",
    "comfirm",
    "confrim",
    "requird",
    "requried",
]

# Sender tokens that hint at bulk / prize / alert style
# senders often abused by scammers.
SUSPICIOUS_SENDER_TOKENS = [
    "winner",
    "win",
    "alert",
    "freemsg",
    "prize",
    "reward",
    "lottery",
    "refund",
    "cash",
    "claims",
    "services",
]


# ==========================================================
# Risk Weights
# (single location, easy to tune)
# ==========================================================

WEIGHTS = {
    "link_high": 45,
    "link_medium": 25,
    "link_low": 5,
    "urgency": 12,
    "sensitive_info": 12,
    "money_bait": 18,
    "impersonation": 15,
    "threats": 30,
    "suspicious_sender": 15,
    "language_quality": 8,
    "reply_bait": 12,
}

# Per-category caps so many tiny signals cannot reach 100 alone.
URGENCY_CAP = 30
SENSITIVE_INFO_CAP = 40
MONEY_BAIT_CAP = 40
IMPERSONATION_CAP = 50
THREATS_CAP = 60
LANGUAGE_CAP = 20
REPLY_BAIT_CAP = 24


# ==========================================================
# Centralized Risk Thresholds
# ==========================================================

LOW_MAX = 29
HIGH_MIN = 70

MAX_MESSAGE_CHARS = 5000

MIN_UPPERCASE_WORDS = 4
UPPERCASE_RATIO = 0.35
MAX_EXCLAMATIONS = 1

ALL_CAPS_WORD = re.compile(r"^[A-Z0-9]*[A-Z][A-Z0-9]*$")

SCHEME_URL_RE = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)

BARE_URL_RE = re.compile(
    r"(?:^|\s)((?:www\.)?[a-z0-9][a-z0-9\-]*"
    r"(?:\.[a-z0-9][a-z0-9\-]*)+"
    r"(?:/[^\s<>\"']*)?)",
    re.IGNORECASE,
)

PHONE_NUMBER_RE = re.compile(
    r"(?<!\d)(?:\+?\d[\d\s\-]?){7,15}\d(?!\d)"
)

SHORT_CODE_RE = re.compile(r"^\d{3,6}$")
MOBILE_NUMBER_RE = re.compile(r"^\+?\d{7,15}$")


# ==========================================================
# Small Helpers
# ==========================================================


def _risk_level(score):
    if score >= HIGH_MIN:
        return "HIGH"

    if score > LOW_MAX:
        return "MEDIUM"

    return "LOW"


def _find_phrases(text_lower, phrase_list):
    """
    Returns the subset of phrases (in list order) that appear in
    the given lowercased text. Phrases are matched as whole
    words; an empty token list is returned for unknown phrases.
    """
    found = []

    for phrase in phrase_list:
        pattern = r"(?<![a-z0-9])" + re.escape(phrase) + r"(?![a-z0-9])"

        if re.search(pattern, text_lower):
            found.append(phrase)

    return found


def _extract_urls(message):
    """
    Extracts candidate URLs from a message.
    Matches both explicit schemes and bare domain tokens.
    Returns a deduplicated list of (original, normalized) pairs.
    """
    candidates = []

    for match in SCHEME_URL_RE.finditer(message):
        candidates.append(match.group(0))

    for match in BARE_URL_RE.finditer(message):
        candidates.append(match.group(1))

    seen = set()

    urls = []

    for raw in candidates:
        raw = raw.strip().rstrip(".,!?;:)]}")

        if not raw:
            continue

        key = raw.lower()

        if key in seen:
            continue

        seen.add(key)

        urls.append(raw)

    return urls


def _classify_sender(sender):
    """
    Best-effort classification of the sender field.
    Returns a display label such as SHORT_CODE, MOBILE_NUMBER,
    ALPHANUMERIC or UNKNOWN.
    """
    value = (sender or "").strip()

    if not value:
        return "UNKNOWN"

    compact = value.replace(" ", "")

    if SHORT_CODE_RE.match(compact):
        return "SHORT_CODE"

    if MOBILE_NUMBER_RE.match(compact):
        return "MOBILE_NUMBER"

    return "ALPHANUMERIC"


def _sender_is_suspicious(sender, sender_type):
    """
    Flags sender fields that are unusual for legitimate services.
    Personal mobile numbers and prize/alert-style alphanumeric
    senders are treated as suspicious; short codes and empty
    fields are not.
    """
    if sender_type == "MOBILE_NUMBER":
        return True

    if sender_type == "ALPHANUMERIC":
        lowered = sender.lower()

        return any(
            token in lowered
            for token in SUSPICIOUS_SENDER_TOKENS
        )

    return False


def _uppercase_signals(message, words):
    """
    Returns True when the message looks aggressively
    caps-heavy, a common bulk-scam trait.
    """
    if not words:
        return False

    caps_words = 0

    for word in words:
        if ALL_CAPS_WORD.match(word):
            caps_words += 1

    if caps_words >= MIN_UPPERCASE_WORDS:
        return True

    ratio = caps_words / len(words)

    return ratio >= UPPERCASE_RATIO


def _exclamation_signal(message):
    return message.count("!") > MAX_EXCLAMATIONS


def _phrase_hits(text_lower, phrase_list):
    found = _find_phrases(text_lower, phrase_list)

    return found


# ==========================================================
# Verdict + Recommendation Generation
# ==========================================================


def _build_verdict(score, signals):
    """
    Generates a measured verdict. The detector reports levels of
    suspicion; it never claims a message is definitively from a
    scammer without strong evidence.
    """
    level = _risk_level(score)

    extra = []

    if signals.get("link_level"):
        extra.append(
            "The message contains a link classified as "
            + signals["link_level"].lower()
            + " risk."
        )

    if signals.get("requests_sensitive_data"):
        extra.append(
            "It asks for credentials, identity details or payment "
            "information."
        )

    if signals.get("money_bait"):
        extra.append(
            "It dangles a prize, reward or unexpected payment."
        )

    if signals.get("contains_threats"):
        extra.append(
            "It threatens negative consequences to force a response."
        )

    if level == "LOW":
        verdict = (
            "No major scam indicators were detected in this message."
        )
    elif level == "MEDIUM":
        verdict = (
            "This message shows some characteristics commonly found "
            "in scams. Treat it with caution before responding."
        )
    else:
        verdict = (
            "Multiple high-risk scam indicators were detected. Do "
            "not respond, tap links or share any personal information."
        )

    if extra:
        verdict = " ".join(extra) + " " + verdict

    return verdict


def _build_recommendation(score):
    level = _risk_level(score)

    if level == "LOW":
        return (
            "The message appears relatively safe based on the "
            "available checks. Still, never share OTPs, passwords or "
            "payment details via text."
        )

    if level == "MEDIUM":
        return (
            "Verify the sender through an official channel before "
            "responding, and never tap links or provide personal data "
            "to an unverified message."
        )

    return (
        "Do not reply, tap any links, call listed numbers, or share "
        "OTPs, PINs, passwords or card details. Report the message to "
        "your mobile carrier and the relevant service provider."
    )


# ==========================================================
# Main Scan Function
# ==========================================================


def scan_sms(sender, message):
    """
    Analyzes an SMS message (and optional sender field) for
    phishing / scam indicators.

    Pure offline heuristic analysis. Never fetches, resolves or
    opens links and never calls or verifies phone numbers.

    Returns:
        risk_score, risk_level, verdict, recommendation,
        indicators, checks, sender, sender_type,
        message_details, analysis
    """

    # ----------------------------------------------------------
    # Validation
    # ----------------------------------------------------------

    if not message or not isinstance(message, str) or not message.strip():

        return {
            "valid": False,
            "reason": "Please provide the SMS message to analyze.",
        }

    if len(message) > MAX_MESSAGE_CHARS:

        return {
            "valid": False,
            "reason": (
                "The message exceeds the maximum supported length of "
                + str(MAX_MESSAGE_CHARS)
                + " characters."
            ),
        }

    if sender is not None and not isinstance(sender, str):

        return {
            "valid": False,
            "reason": "The sender field must be plain text.",
        }

    # ----------------------------------------------------------
    # Text preparation
    # ----------------------------------------------------------

    sender_value = (sender or "").strip()

    text_lower = message.lower()

    words = re.findall(r"[a-zA-Z0-9']+", message)

    # ----------------------------------------------------------
    # Signal collection
    # ----------------------------------------------------------

    risk_score = 0

    indicators = []

    checks = []

    signals = {
        "link_level": None,
        "requests_sensitive_data": False,
        "money_bait": False,
        "contains_threats": False,
    }

    def add_check(check, risk, detail):
        checks.append(
            {
                "check": check,
                "risk": risk,
                "detail": detail,
            }
        )

    def add_indicator(text):
        indicators.append(text)

    # ----------------------------------------------------------
    # 1. Embedded links (offline URL structural scan)
    # ----------------------------------------------------------

    urls = _extract_urls(message)

    best_link = None

    if urls:

        best_score = -1

        for raw in urls:

            result = scan_url(raw)

            if result.get("valid") is not True:
                continue

            link_score = result["risk_score"]

            if link_score > best_score:
                best_score = link_score
                best_link = result

        if best_link is not None:

            signals["link_level"] = best_link["risk_level"]

            link_level = best_link["risk_level"]

            if link_level == "HIGH":
                risk_score += WEIGHTS["link_high"]
            elif link_level == "MEDIUM":
                risk_score += WEIGHTS["link_medium"]
            else:
                risk_score += WEIGHTS["link_low"]

            add_indicator(
                "Embedded link scored "
                + str(best_link["risk_score"])
                + "% ("
                + link_level
                + ") on the offline URL scanner."
            )

            add_check(
                "Embedded Link",
                link_level,
                best_link.get(
                    "normalized_url",
                    "Link present in message.",
                ),
            )

        else:

            add_check(
                "Embedded Link",
                "SAFE",
                "Link(s) present; none triggered structural flags.",
            )

    else:

        add_check(
            "Embedded Link",
            "SAFE",
            "No embedded links detected.",
        )

    # ----------------------------------------------------------
    # 2. Urgency / pressure
    # ----------------------------------------------------------

    urgency_hits = _phrase_hits(text_lower, URGENCY_PHRASES)

    if urgency_hits:

        urgency_weight = min(
            WEIGHTS["urgency"] * min(len(urgency_hits), 3),
            URGENCY_CAP,
        )

        risk_score += urgency_weight

        add_indicator(
            "Urgency or pressure tactics detected: "
            + ", ".join(urgency_hits)
            + "."
        )

        add_check(
            "Urgency / Pressure",
            "SUSPICIOUS",
            "Message rushes the receiver to act: "
            + ", ".join(urgency_hits)
            + ".",
        )

    else:

        add_check(
            "Urgency / Pressure",
            "SAFE",
            "No pressure tactics detected.",
        )

    # ----------------------------------------------------------
    # 3. Sensitive information requests
    # ----------------------------------------------------------

    sensitive_hits = _phrase_hits(text_lower, SENSITIVE_INFO_PHRASES)

    if sensitive_hits:

        sensitive_weight = min(
            WEIGHTS["sensitive_info"] * min(len(sensitive_hits), 3),
            SENSITIVE_INFO_CAP,
        )

        risk_score += sensitive_weight

        signals["requests_sensitive_data"] = True

        add_indicator(
            "Message asks for sensitive data: "
            + ", ".join(sensitive_hits)
            + "."
        )

        add_check(
            "Sensitive Data Request",
            "DANGEROUS",
            "Requests credentials / identity / payment details: "
            + ", ".join(sensitive_hits)
            + ".",
        )

    else:

        add_check(
            "Sensitive Data Request",
            "SAFE",
            "No sensitive data requested.",
        )

    # ----------------------------------------------------------
    # 4. Money / prize bait
    # ----------------------------------------------------------

    money_hits = _phrase_hits(text_lower, MONEY_BAIT_PHRASES)

    if money_hits:

        money_weight = min(
            WEIGHTS["money_bait"] * min(len(money_hits), 3),
            MONEY_BAIT_CAP,
        )

        risk_score += money_weight

        signals["money_bait"] = True

        add_indicator(
            "Money / prize bait detected: "
            + ", ".join(money_hits)
            + "."
        )

        add_check(
            "Money / Prize Bait",
            "SUSPICIOUS",
            "Promises rewards, prizes or unexpected payments.",
        )

    else:

        add_check(
            "Money / Prize Bait",
            "SAFE",
            "No money or prize bait detected.",
        )

    # ----------------------------------------------------------
    # 5. Brand / authority impersonation
    # ----------------------------------------------------------

    brand_hits = _phrase_hits(text_lower, IMPERSONATION_BRANDS)

    if brand_hits:

        brand_weight = min(
            WEIGHTS["impersonation"] * min(len(brand_hits), 2),
            IMPERSONATION_CAP,
        )

        risk_score += brand_weight

        add_indicator(
            "References a brand or authority often impersonated: "
            + ", ".join(brand_hits)
            + "."
        )

        add_check(
            "Brand / Authority Impersonation",
            "SUSPICIOUS",
            "Names a service or authority commonly spoofed in scams.",
        )

    else:

        add_check(
            "Brand / Authority Impersonation",
            "SAFE",
            "No commonly impersonated brands referenced.",
        )

    # ----------------------------------------------------------
    # 6. Threats / consequences
    # ----------------------------------------------------------

    threat_hits = _phrase_hits(text_lower, THREAT_PHRASES)

    if threat_hits:

        threat_weight = min(
            WEIGHTS["threats"] * min(len(threat_hits), 2),
            THREATS_CAP,
        )

        risk_score += threat_weight

        signals["contains_threats"] = True

        add_indicator(
            "Threatening consequences used to coerce action: "
            + ", ".join(threat_hits)
            + "."
        )

        add_check(
            "Threats / Consequences",
            "DANGEROUS",
            "Message threatens legal, financial or account actions.",
        )

    else:

        add_check(
            "Threats / Consequences",
            "SAFE",
            "No threatening language detected.",
        )

    # ----------------------------------------------------------
    # 7. Suspicious sender
    # ----------------------------------------------------------

    sender_type = _classify_sender(sender_value)

    sender_suspicious = _sender_is_suspicious(sender_value, sender_type)

    if sender_suspicious:

        risk_score += WEIGHTS["suspicious_sender"]

        if sender_type == "MOBILE_NUMBER":

            add_indicator(
                "Sender is a personal mobile number rather than an "
                "official short code."
            )

            add_check(
                "Sender Identity",
                "SUSPICIOUS",
                "Message originates from a mobile number.",
            )

        else:

            add_indicator(
                "Sender name is unusual for a legitimate service."
            )

            add_check(
                "Sender Identity",
                "SUSPICIOUS",
                "Unusual alphanumeric sender: "
                + (sender_value or "unknown")
                + ".",
            )

    else:

        add_check(
            "Sender Identity",
            "SAFE",
            "Sender looks like an official short code or is not "
            "provided.",
        )

    # ----------------------------------------------------------
    # 8. Language quality red flags
    # ----------------------------------------------------------

    language_flags = []

    if _uppercase_signals(message, words):
        language_flags.append("excessive capitalization")

    if _exclamation_signal(message):
        language_flags.append("multiple exclamation marks")

    greeting_hits = _phrase_hits(text_lower, GENERIC_GREETINGS)

    if greeting_hits:
        language_flags.append("generic greeting: " + greeting_hits[0])

    misspelling_hits = _phrase_hits(text_lower, COMMON_MISSPELLINGS)

    if misspelling_hits:
        language_flags.append(
            "scam-typical spelling: "
            + ", ".join(misspelling_hits[:2])
        )

    if language_flags:

        language_weight = min(
            WEIGHTS["language_quality"] * len(language_flags),
            LANGUAGE_CAP,
        )

        risk_score += language_weight

        add_indicator(
            "Language quality red flags: "
            + "; ".join(language_flags)
            + "."
        )

        add_check(
            "Language Quality",
            "SUSPICIOUS",
            "; ".join(language_flags) + ".",
        )

    else:

        add_check(
            "Language Quality",
            "SAFE",
            "Message language appears natural.",
        )

    # ----------------------------------------------------------
    # 9. Call to action / reply bait
    # ----------------------------------------------------------

    reply_hits = _phrase_hits(text_lower, REPLY_BAIT_PHRASES)

    if reply_hits:

        reply_weight = min(
            WEIGHTS["reply_bait"] * min(len(reply_hits), 2),
            REPLY_BAIT_CAP,
        )

        risk_score += reply_weight

        add_indicator(
            "Instructional call-to-action detected: "
            + ", ".join(reply_hits)
            + "."
        )

        add_check(
            "Call to Action",
            "SUSPICIOUS",
            "Tells the receiver to click, call or reply.",
        )

    else:

        add_check(
            "Call to Action",
            "SAFE",
            "No instructional call-to-action detected.",
        )

    # ----------------------------------------------------------
    # Final score
    # ----------------------------------------------------------

    risk_score = max(0, min(risk_score, 100))

    if not indicators:
        indicators.append(
            "No major suspicious indicators were detected."
        )

    has_phone = bool(
        PHONE_NUMBER_RE.search(
            SCHEME_URL_RE.sub(" ", message)
        )
    )

    return {
        "valid": True,
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "verdict": _build_verdict(risk_score, signals),
        "recommendation": _build_recommendation(risk_score),
        "indicators": indicators,
        "checks": checks,
        "sender": sender_value,
        "sender_type": sender_type,
        "message_details": {
            "characters": len(message),
            "words": len(words),
            "has_link": bool(urls),
            "has_phone": has_phone,
            "sender": sender_value or "Not provided",
            "sender_type": sender_type,
        },
        "analysis": {
            "has_link": bool(urls),
            "link_level": signals["link_level"],
            "uses_urgency": bool(urgency_hits),
            "requests_sensitive_data": signals["requests_sensitive_data"],
            "money_bait": signals["money_bait"],
            "impersonation": bool(brand_hits),
            "contains_threats": signals["contains_threats"],
            "suspicious_sender": sender_suspicious,
            "language_issues": bool(language_flags),
            "reply_bait": bool(reply_hits),
        },
        "link": (
            {
                "normalized_url": best_link["normalized_url"],
                "risk_score": best_link["risk_score"],
                "risk_level": best_link["risk_level"],
            }
            if best_link is not None
            else None
        ),
    }


# ==========================================================
# Module-level constants re-exported for convenience
# ==========================================================


def get_thresholds():
    """
    Returns the centralized risk thresholds so callers (and tests)
    always stay in sync with the analyzer.
    """
    return {
        "LOW_MAX": LOW_MAX,
        "HIGH_MIN": HIGH_MIN,
    }
