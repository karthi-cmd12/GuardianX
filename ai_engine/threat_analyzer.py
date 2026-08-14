# ==========================================================
# GuardianX AI Threat Analyzer
# ==========================================================


from ai_engine.keywords import (
    PHISHING_KEYWORDS,
    SCAM_KEYWORDS,
    DATA_REQUEST_KEYWORDS,
    SUSPICIOUS_DOMAINS
)

from ai_engine.risk_score import (
    calculate_risk_score
)



# ==========================================================
# Main Analyzer Function
# ==========================================================


def analyze_message(message):

    message = message.lower()


    reasons = []

    keyword_hits = 0

    suspicious_links = 0

    data_requests = 0



    # --------------------------------------
    # Check phishing keywords
    # --------------------------------------

    for keyword in PHISHING_KEYWORDS:

        if keyword in message:

            keyword_hits += 1

            reasons.append(
                f"Suspicious keyword detected: {keyword}"
            )



    # --------------------------------------
    # Check scam keywords
    # --------------------------------------

    for keyword in SCAM_KEYWORDS:

        if keyword in message:

            keyword_hits += 1

            reasons.append(
                f"Possible scam pattern: {keyword}"
            )



    # --------------------------------------
    # Check sensitive information requests
    # --------------------------------------

    for keyword in DATA_REQUEST_KEYWORDS:

        if keyword in message:

            data_requests += 1

            reasons.append(
                f"Requests sensitive information: {keyword}"
            )



    # --------------------------------------
    # Check suspicious links/domains
    # --------------------------------------

    for domain in SUSPICIOUS_DOMAINS:

        if domain in message:

            suspicious_links += 1

            reasons.append(
                f"Suspicious link pattern detected: {domain}"
            )



    # --------------------------------------
    # Calculate Risk
    # --------------------------------------

    result = calculate_risk_score(
        keyword_hits,
        suspicious_links,
        data_requests
    )



    # --------------------------------------
    # Recommendation
    # --------------------------------------

    if result["threat_level"] == "SAFE":

        recommendation = (
            "This message appears safe. "
            "Continue with normal caution."
        )


    elif result["threat_level"] == "SUSPICIOUS":

        recommendation = (
            "Be careful. Verify the sender "
            "before taking any action."
        )


    else:

        recommendation = (
            "Do not click links or share "
            "personal information."
        )



    return {

        "risk_score": result["risk_score"],

        "threat_level": result["threat_level"],

        "reasons": reasons,

        "recommendation": recommendation

    }