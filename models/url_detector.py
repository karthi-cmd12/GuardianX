# ==========================================================
# GuardianX URL Threat Analyzer
#
# Offline, static, heuristic URL security analysis engine.
# This module NEVER makes network requests: it does not
# follow redirects, download pages, run JavaScript or query
# external reputation services. It performs structural
# analysis only.
# ==========================================================

import ipaddress
import re
from urllib.parse import urlparse, parse_qs, urlunparse


# ==========================================================
# Configurable Signal Lists
# (kept together in one place so they are easy to extend)
# ==========================================================

# Common protected brand names used for lookalike detection.
# Add new brands here; display labels fall back to .capitalize().
BRAND_NAMES = [
    "paypal",
    "google",
    "microsoft",
    "facebook",
    "amazon",
    "apple",
    "netflix",
    "instagram",
    "whatsapp",
    "gmail",
    "outlook",
    "twitter",
    "linkedin",
    "github",
    "dropbox",
    "steam",
    "ebay",
    "snapchat",
    "chase",
    "wellsfargo",
    "paytm",
    "phonepe",
    "gpay",
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "kotak",
    "irctc",
    "flipkart",
    "myntra",
    "aadhaar",
]

BRAND_LABELS = {
    "paypal": "PayPal",
    "google": "Google",
    "microsoft": "Microsoft",
    "facebook": "Facebook",
    "amazon": "Amazon",
    "apple": "Apple",
    "netflix": "Netflix",
    "instagram": "Instagram",
    "whatsapp": "WhatsApp",
    "gmail": "Gmail",
    "outlook": "Outlook",
    "twitter": "Twitter",
    "linkedin": "LinkedIn",
    "github": "GitHub",
    "dropbox": "Dropbox",
    "steam": "Steam",
    "ebay": "eBay",
    "snapchat": "Snapchat",
    "chase": "Chase",
    "wellsfargo": "Wells Fargo",
    "paytm": "Paytm",
    "phonepe": "PhonePe",
    "gpay": "Google Pay",
    "sbi": "SBI",
    "hdfc": "HDFC",
    "icici": "ICICI",
    "axis": "Axis Bank",
    "kotak": "Kotak",
    "irctc": "IRCTC",
    "flipkart": "Flipkart",
    "myntra": "Myntra",
    "aadhaar": "Aadhaar",
}

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rb.gy",
    "cutt.ly",
    "tiny.cc",
    "shorte.st",
    "bc.vc",
    "adf.ly",
    "t2m.io",
    "soo.gd",
]

# Low-weight warning list only. Presence is NOT treated as
# malicious by itself.
SUSPICIOUS_TLDS = [
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "cfd",
    "link",
]

# These words alone must never make a URL malicious.
SUSPICIOUS_PATH_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "bank",
    "payment",
    "wallet",
    "confirm",
    "otp",
    "credential",
    "pay",
    "unlock",
    "validate",
    "authenticate",
]

# Parameter NAMES only. Values are never logged or displayed.
SENSITIVE_QUERY_PARAMS = [
    "password",
    "passwd",
    "pwd",
    "pass",
    "otp",
    "pin",
    "cvv",
    "card",
    "card_number",
    "cardnumber",
    "account",
    "token",
    "secret",
    "credential",
    "ssn",
    "aadhaar",
    "pan",
]


# ==========================================================
# Risk Weights
# (single location, easy to tune)
# ==========================================================

WEIGHTS = {
    "scheme_http": 15,
    "scheme_unsupported": 20,
    "ip_host": 20,
    "shortener": 15,
    "lookalike": 40,
    "suspicious_tld": 10,
    "sensitive_query": 20,
    "credential_trick_domain": 60,
    "credential_trick_plain": 20,
    "obfuscation_percent": 15,
    "obfuscation_hex_ip": 15,
    "obfuscation_decimal_ip": 15,
    "suspicious_path": 10,
    "long_url": 10,
    "excessive_subdomains": 10,
    "punycode": 15,
    "numeric_host": 10,
    "excessive_hyphens": 10,
    "unexpected_host_chars": 10,
    "excessive_query_params": 10,
    "deep_path": 10,
}

# Per-category caps so many tiny signals cannot reach 100 alone.
PATH_KEYWORD_CAP = 20
SENSITIVE_QUERY_CAP = 40


# ==========================================================
# Centralized Risk Thresholds
# ==========================================================

LOW_MAX = 29
HIGH_MIN = 70

MAX_HOST_DOTS = 3
MAX_SUBDOMAINS = 2
MAX_HYPHENS = 3
MAX_URL_LENGTH = 1000
MAX_QUERY_PARAMS = 5
MAX_PATH_DEPTH = 4

LOOKALIKE_SIM_THRESHOLD = 0.80
PERCENT_ENCODE_THRESHOLD = 3

HOSTNAME_CHARS = re.compile(r"^[a-z0-9._\-]+$")
DECIMAL_IP_RE = re.compile(r"^\d{7,10}$")
HEX_IP_RE = re.compile(r"(^|[.])0x[0-9a-f]+([.]|$)", re.IGNORECASE)


# ==========================================================
# URL Normalization
# ==========================================================


def _normalize_url(raw_url):
    """
    Returns a cleaned, normalized URL string suitable for
    static analysis, or an empty string if nothing usable
    remains.

    Performs safe, purely textual normalization:
      - strips surrounding whitespace and unusual whitespace
      - lowercases the scheme and hostname
      - removes trailing slashes (keeps a bare root "/")
      - never performs any network activity
    """
    if not raw_url or not isinstance(raw_url, str):
        return ""

    url = raw_url.strip()

    # Collapse all whitespace characters (accidental spacing).
    url = re.sub(r"\s+", "", url)

    if not url:
        return ""

    has_scheme = "://" in url

    if not has_scheme:
        url = "http://" + url

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()

    netloc = parsed.netloc.lower()

    path = parsed.path or "/"

    # Remove trailing slashes (but keep the root "/").
    while path != "/" and path.endswith("/"):
        path = path[:-1]

    query = parsed.query

    fragment = parsed.fragment

    normalized = urlunparse(
        (scheme, netloc, path, parsed.params, query, fragment)
    )

    return normalized


def _mask_sensitive_query(url):
    """
    Returns a version of the URL with sensitive query parameter
    VALUES masked, so raw secret values are never echoed back.
    Parameter names are preserved.
    """
    parsed = urlparse(url)

    if not parsed.query:
        return url

    pairs = parsed.query.split("&")

    masked = []

    for pair in pairs:
        if "=" in pair:
            key, _value = pair.split("=", 1)
        else:
            key, _value = pair, ""

        if key.lower() in SENSITIVE_QUERY_PARAMS:
            masked.append(key + "=***")
        else:
            masked.append(pair)

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            "&".join(masked),
            parsed.fragment,
        )
    )


def _extract_parts(url):
    """
    Parses a normalized URL into analysis parts.

    Returns a dict with: scheme, hostname, port, username,
    path, query_params, fragment, uses_https, has_userinfo.
    """
    parsed = urlparse(url)

    hostname = parsed.hostname

    if hostname is not None:
        hostname = hostname.strip("[]").lower()

    port = None

    try:
        port = parsed.port
    except ValueError:
        pass

    query_params = parse_qs(parsed.query, keep_blank_values=True)

    return {
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "port": port,
        "username": parsed.username,
        "path": parsed.path or "/",
        "query_params": query_params,
        "fragment": parsed.fragment,
        "uses_https": parsed.scheme.lower() == "https",
        "has_userinfo": parsed.username is not None,
    }


def _is_valid_parts(parts):
    """
    Returns True if the parsed parts represent a structurally
    usable URL for analysis.
    """
    hostname = parts["hostname"]

    if not hostname:
        return False

    if ":" in hostname:
        return _host_is_ip(hostname)

    return bool(HOSTNAME_CHARS.match(hostname))


# ==========================================================
# Small Helpers
# ==========================================================


def _host_is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _registrable_label(hostname):
    """Best-effort second-level label, e.g. 'paypa1' in 'www.paypa1.com'."""
    labels = hostname.split(".")

    if len(labels) >= 2:
        return labels[-2]

    return labels[-1] if labels else ""


def _tld_of(hostname):
    labels = hostname.split(".")

    return labels[-1].lower() if labels else ""


def _count_subdomains(hostname):
    """Counts subdomains, ignoring www and the registrable domain."""
    labels = hostname.split(".")

    if len(labels) <= 2:
        return 0

    subdomains = labels[:-2]

    return len([label for label in subdomains if label and label != "www"])


def _has_punycode(hostname):
    return any(label.startswith("xn--") for label in hostname.split("."))


def _levenshtein(a, b):
    """Standard Levenshtein edit distance (iterative DP)."""
    if a == b:
        return 0

    if not a:
        return len(b)

    if not b:
        return len(a)

    previous = list(range(len(b) + 1))

    for i, ca in enumerate(a, start=1):

        current = [i]

        for j, cb in enumerate(b, start=1):

            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (0 if ca == cb else 1)

            current.append(min(insert, delete, replace))

        previous = current

    return previous[-1]


def _similarity(a, b):
    """Normalized similarity in [0, 1] based on edit distance."""
    max_len = max(len(a), len(b))

    if max_len == 0:
        return 1.0

    return 1.0 - (_levenshtein(a, b) / max_len)


def _detect_lookalike(hostname):
    """
    Detects typo-squatting / lookalike domains.

    Returns a display label of the impersonated brand or None.

    - Never flags a domain whose registrable label equals the
      brand exactly (the real domain is allowed).
    - Uses normalized Levenshtein similarity on the main label.
    - Also flags hosts that embed a brand name as a whole token
      (e.g. 'paypal-login.com').
    """
    label = _registrable_label(hostname)

    labels = {part for part in re.split(r"[.\-]", hostname) if part}

    for brand in BRAND_NAMES:

        if label == brand:
            continue

        if label and _similarity(label, brand) >= LOOKALIKE_SIM_THRESHOLD:
            return BRAND_LABELS.get(brand, brand.capitalize())

        if brand in labels:
            return BRAND_LABELS.get(brand, brand.capitalize())

    return None


def _detect_shortener(hostname):
    for shortener in URL_SHORTENERS:
        if hostname == shortener or hostname.endswith("." + shortener):
            return shortener

    return None


def _detect_suspicious_tld(hostname):
    tld = _tld_of(hostname)

    if tld in SUSPICIOUS_TLDS:
        return tld

    return None


def _percent_encoding_count(url):
    return url.count("%")


# ==========================================================
# Risk Level Mapping
# ==========================================================


def _risk_level(score):
    if score >= HIGH_MIN:
        return "HIGH"

    if score > LOW_MAX:
        return "MEDIUM"

    return "LOW"


# ==========================================================
# Verdict + Recommendation Generation
# ==========================================================


def _build_verdict(score, signals):
    """
    Generates a measured verdict. The scanner never claims a URL
    is definitely malicious without reliable structural evidence;
    it reports levels of suspicion.
    """
    level = _risk_level(score)

    extra = []

    if signals.get("lookalike"):
        extra.append(
            "The domain may impersonate " + signals["lookalike"] + "."
        )

    if signals.get("credential_trick"):
        extra.append(
            "The URL hides a different destination behind a "
            "user-information section."
        )

    if level == "LOW":
        verdict = (
            "No major suspicious indicators were detected in this URL."
        )
    elif level == "MEDIUM":
        verdict = (
            "This URL contains some suspicious characteristics. "
            "Verify the destination before proceeding."
        )
    else:
        verdict = (
            "Multiple high-risk phishing indicators were detected. "
            "Avoid opening this URL unless you can independently "
            "verify the destination."
        )

    if extra:
        verdict = " ".join(extra) + " " + verdict

    return verdict


def _build_recommendation(score):
    level = _risk_level(score)

    if level == "LOW":
        return (
            "The URL appears relatively safe based on the available "
            "structural checks."
        )

    if level == "MEDIUM":
        return (
            "Verify the domain and destination before entering "
            "credentials or personal information."
        )

    return (
        "Do not open the link or provide credentials, OTPs, payment "
        "details, or other sensitive information."
    )


# ==========================================================
# Main Scan Function
# ==========================================================


def scan_url(raw_url):
    """
    Analyzes a URL string for phishing / scam indicators.

    Pure offline heuristic analysis. Never fetches, follows or
    opens the URL.

    Returns:
        risk_score, risk_level, verdict, recommendation,
        indicators, checks, normalized_url, hostname, scheme,
        analysis
    """

    # ----------------------------------------------------------
    # Validation
    # ----------------------------------------------------------

    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():

        return {
            "valid": False,
            "reason": "Please provide a URL to scan.",
        }

    normalized = _normalize_url(raw_url)

    if not normalized:

        return {
            "valid": False,
            "reason": "The URL is empty after normalization.",
        }

    parts = _extract_parts(normalized)

    if not _is_valid_parts(parts):

        return {
            "valid": False,
            "reason": (
                "The value provided is not a valid URL. "
                "Please enter a valid web address."
            ),
        }

    hostname = parts["hostname"]
    scheme = parts["scheme"]

    # ----------------------------------------------------------
    # Signal collection
    # ----------------------------------------------------------

    risk_score = 0

    indicators = []

    signals = {
        "lookalike": None,
        "credential_trick": False,
    }

    checks = []

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
    # 1. URL Scheme
    # ----------------------------------------------------------

    if scheme == "https":

        add_check(
            "URL Scheme",
            "SAFE",
            "URL uses HTTPS.",
        )

    elif scheme == "http":

        risk_score += WEIGHTS["scheme_http"]

        add_indicator("URL uses unencrypted HTTP instead of HTTPS.")

        add_check(
            "URL Scheme",
            "SUSPICIOUS",
            "URL uses unencrypted HTTP.",
        )

    else:

        risk_score += WEIGHTS["scheme_unsupported"]

        add_indicator(
            "Unsupported or unusual URL scheme detected: " + scheme + "."
        )

        add_check(
            "URL Scheme",
            "DANGEROUS",
            "Unsupported or unusual scheme: " + scheme + ".",
        )

    # ----------------------------------------------------------
    # 2. IP-address host
    # ----------------------------------------------------------

    is_ip = _host_is_ip(hostname)

    if is_ip:

        risk_score += WEIGHTS["ip_host"]

        add_indicator(
            "The host is a raw IP address: " + hostname + "."
        )

        add_check(
            "IP Address Host",
            "DANGEROUS",
            "Host is an IP address rather than a domain name.",
        )

    else:

        add_check(
            "IP Address Host",
            "SAFE",
            "Host is a domain name.",
        )

    # ----------------------------------------------------------
    # 3. Lookalike / typo-squatting domain
    # ----------------------------------------------------------

    lookalike = None if is_ip else _detect_lookalike(hostname)

    if lookalike:

        signals["lookalike"] = lookalike

        risk_score += WEIGHTS["lookalike"]

        add_indicator(
            "Lookalike domain detected; may impersonate "
            + lookalike
            + "."
        )

        add_check(
            "Lookalike Domain",
            "DANGEROUS",
            "Domain may impersonate " + lookalike + ".",
        )

    else:

        add_check(
            "Lookalike Domain",
            "SAFE",
            "No lookalike brand domain detected.",
        )

    # ----------------------------------------------------------
    # 4. Suspicious TLD
    # ----------------------------------------------------------

    suspicious_tld = _detect_suspicious_tld(hostname)

    if suspicious_tld:

        risk_score += WEIGHTS["suspicious_tld"]

        add_indicator(
            "Unusual or commonly abused top-level domain: ."
            + suspicious_tld
            + "."
        )

        add_check(
            "Suspicious TLD",
            "SUSPICIOUS",
            "Unusual or commonly abused TLD: ." + suspicious_tld + ".",
        )

    else:

        add_check(
            "Suspicious TLD",
            "SAFE",
            "No unusual top-level domain detected.",
        )

    # ----------------------------------------------------------
    # 5. URL shortener
    # ----------------------------------------------------------

    shortener = _detect_shortener(hostname)

    if shortener:

        risk_score += WEIGHTS["shortener"]

        add_indicator(
            "URL shortener detected: "
            + shortener
            + ". The final destination cannot be verified without "
            "resolving the link."
        )

        add_check(
            "URL Shortener",
            "SUSPICIOUS",
            "Shortened link: " + shortener + ".",
        )

    else:

        add_check(
            "URL Shortener",
            "SAFE",
            "No URL shortener detected.",
        )

    # ----------------------------------------------------------
    # 6. Punycode / IDN hostname
    # ----------------------------------------------------------

    is_punycode = _has_punycode(hostname)

    if is_punycode:

        risk_score += WEIGHTS["punycode"]

        add_indicator(
            "Punycode (IDN) encoded hostname detected."
        )

        add_check(
            "Punycode",
            "SUSPICIOUS",
            "Hostname uses punycode (IDN) encoding.",
        )

    else:

        add_check(
            "Punycode",
            "SAFE",
            "No punycode hostname encoding detected.",
        )

    # ----------------------------------------------------------
    # 7. Domain structure / hostname signals
    # ----------------------------------------------------------

    subdomain_count = _count_subdomains(hostname)

    hyphen_count = hostname.count("-")

    numeric_ratio = (
        sum(char.isdigit() for char in hostname) / max(len(hostname), 1)
        if hostname
        else 0.0
    )

    host_too_long = len(hostname) > 60

    too_many_subdomains = subdomain_count > MAX_SUBDOMAINS

    too_many_hyphens = (
        hyphen_count >= MAX_HYPHENS
        or any(len(label) >= 2 and label.count("-") >= 2
               for label in hostname.split("."))
    )

    numeric_heavy = numeric_ratio >= 0.4

    unexpected_chars = bool(
        re.search(r"[^a-z0-9.\-_]", hostname)
    )

    structure_flags = []

    if host_too_long:
        structure_flags.append("hostname is very long")

    if too_many_subdomains:
        structure_flags.append("excessive subdomains")

    if too_many_hyphens:
        structure_flags.append("excessive hyphens")

    if numeric_heavy:
        structure_flags.append("numeric-heavy hostname")

    if unexpected_chars:
        structure_flags.append("unexpected characters in hostname")

    if structure_flags:

        for flag in structure_flags:

            if flag == "excessive subdomains":
                risk_score += WEIGHTS["excessive_subdomains"]
            elif flag == "excessive hyphens":
                risk_score += WEIGHTS["excessive_hyphens"]
            elif flag == "numeric-heavy hostname":
                risk_score += WEIGHTS["numeric_host"]
            elif flag == "unexpected characters in hostname":
                risk_score += WEIGHTS["unexpected_host_chars"]
            # host_too_long contributes via URL Length check only

        add_indicator(
            "Suspicious hostname structure: "
            + ", ".join(structure_flags)
            + "."
        )

        add_check(
            "Domain Structure",
            "SUSPICIOUS",
            "Unusual hostname structure: "
            + ", ".join(structure_flags)
            + ".",
        )

    else:

        add_check(
            "Domain Structure",
            "SAFE",
            "Hostname structure appears normal.",
        )

    # ----------------------------------------------------------
    # 8. Suspicious path keywords
    # ----------------------------------------------------------

    path_lower = parts["path"].lower()

    found_path_keywords = []

    for keyword in SUSPICIOUS_PATH_KEYWORDS:

        if keyword in path_lower and keyword not in found_path_keywords:
            found_path_keywords.append(keyword)

    if found_path_keywords:

        path_weight = min(
            WEIGHTS["suspicious_path"] * len(found_path_keywords),
            PATH_KEYWORD_CAP,
        )

        risk_score += path_weight

        add_indicator(
            "Suspicious path keyword(s) detected: "
            + ", ".join(found_path_keywords)
            + "."
        )

        add_check(
            "Suspicious Path",
            "SUSPICIOUS",
            "Path contains sensitive keyword(s): "
            + ", ".join(found_path_keywords)
            + ".",
        )

    else:

        add_check(
            "Suspicious Path",
            "SAFE",
            "No suspicious path keywords detected.",
        )

    # ----------------------------------------------------------
    # 9. Sensitive query parameters (names only, values masked)
    # ----------------------------------------------------------

    sensitive_hits = sorted(
        {
            param.lower()
            for param in parts["query_params"]
            if param.lower() in SENSITIVE_QUERY_PARAMS
        }
    )

    if sensitive_hits:

        query_weight = min(
            WEIGHTS["sensitive_query"] * min(len(sensitive_hits), 2),
            SENSITIVE_QUERY_CAP,
        )

        risk_score += query_weight

        add_indicator(
            "Sensitive data requested in URL query: "
            + ", ".join(sensitive_hits)
            + "."
        )

        add_check(
            "Sensitive Query Parameters",
            "SUSPICIOUS",
            "Sensitive parameter(s) in query: "
            + ", ".join(sensitive_hits)
            + ".",
        )

    else:

        add_check(
            "Sensitive Query Parameters",
            "SAFE",
            "No sensitive query parameters detected.",
        )

    # ----------------------------------------------------------
    # 10. Credential / user-info trick
    # ----------------------------------------------------------

    if parts["has_userinfo"]:

        username = parts["username"] or ""

        signals["credential_trick"] = True

        if "." in username:

            risk_score += WEIGHTS["credential_trick_domain"]

            add_indicator(
                "Suspicious user-information section detected before "
                "the hostname; the visible domain may differ from the "
                "real destination."
            )

            add_check(
                "Credential Trick",
                "DANGEROUS",
                "User-info section placed before the hostname.",
            )

        else:

            risk_score += WEIGHTS["credential_trick_plain"]

            add_indicator(
                "URL contains user information before the hostname."
            )

            add_check(
                "Credential Trick",
                "SUSPICIOUS",
                "User-info section detected before the hostname.",
            )

    else:

        add_check(
            "Credential Trick",
            "SAFE",
            "No user-info section detected.",
        )

    # ----------------------------------------------------------
    # 11. Obfuscation detection
    # ----------------------------------------------------------

    obfuscation_flags = []

    if _percent_encoding_count(normalized) >= PERCENT_ENCODE_THRESHOLD:
        obfuscation_flags.append("heavy percent-encoding")

    if "%" in hostname:
        obfuscation_flags.append("encoded characters in hostname")

    if HEX_IP_RE.search(hostname):
        obfuscation_flags.append("hexadecimal IP representation")

    if DECIMAL_IP_RE.match(hostname):
        obfuscation_flags.append("decimal IP representation")

    if obfuscation_flags:

        risk_score += WEIGHTS["obfuscation_percent"]

        add_indicator(
            "URL obfuscation detected: "
            + ", ".join(obfuscation_flags)
            + "."
        )

        add_check(
            "URL Obfuscation",
            "SUSPICIOUS",
            "Obfuscation technique(s): "
            + ", ".join(obfuscation_flags)
            + ".",
        )

    else:

        add_check(
            "URL Obfuscation",
            "SAFE",
            "No obfuscation techniques detected.",
        )

    # ----------------------------------------------------------
    # 12. URL length / size indicators
    # ----------------------------------------------------------

    url_length = len(normalized)

    url_length_flags = []

    if url_length >= MAX_URL_LENGTH:
        url_length_flags.append("extremely long URL")

        risk_score += WEIGHTS["long_url"]

    query_count = len(parts["query_params"])

    if query_count > MAX_QUERY_PARAMS:
        url_length_flags.append("excessive query parameters")

        risk_score += WEIGHTS["excessive_query_params"]

    path_segments = [
        segment
        for segment in parts["path"].split("/")
        if segment
    ]

    if len(path_segments) > MAX_PATH_DEPTH:
        url_length_flags.append("excessive nested path segments")

        risk_score += WEIGHTS["deep_path"]

    if url_length_flags:

        add_indicator(
            "Unusually large URL structure: "
            + ", ".join(url_length_flags)
            + "."
        )

        add_check(
            "URL Length",
            "SUSPICIOUS",
            ", ".join(url_length_flags) + ".",
        )

    else:

        add_check(
            "URL Length",
            "SAFE",
            "URL length and structure within normal bounds.",
        )

    # ----------------------------------------------------------
    # Final score
    # ----------------------------------------------------------

    risk_score = max(0, min(risk_score, 100))

    if not indicators:
        indicators.append(
            "No major suspicious indicators were detected."
        )

    normalized_display = _mask_sensitive_query(normalized)

    return {
        "valid": True,
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "verdict": _build_verdict(risk_score, signals),
        "recommendation": _build_recommendation(risk_score),
        "indicators": indicators,
        "checks": checks,
        "normalized_url": normalized_display,
        "hostname": hostname,
        "scheme": scheme,
        "analysis": {
            "uses_https": parts["uses_https"],
            "is_ip_host": is_ip,
            "is_shortened": shortener is not None,
            "is_punycode": is_punycode,
            "is_lookalike": lookalike is not None,
            "has_credential_trick": signals["credential_trick"],
            "has_sensitive_params": bool(sensitive_hits),
        },
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
