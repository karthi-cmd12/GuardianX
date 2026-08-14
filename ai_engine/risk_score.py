# ==========================================================
# GuardianX AI Risk Score Engine
# ==========================================================


def calculate_risk_score(
    keyword_hits=0,
    suspicious_links=0,
    data_requests=0
):
    """
    Calculates cybersecurity risk score.

    Score Range:
    0 - 30   : SAFE
    31 - 70  : SUSPICIOUS
    71 - 100 : DANGEROUS
    """

    score = 0


    # Keyword detection weight

    score += keyword_hits * 5



    # Suspicious link weight

    score += suspicious_links * 20



    # Sensitive information request weight

    score += data_requests * 15



    # Limit maximum score

    if score > 100:

        score = 100



    # Determine threat level

    if score <= 30:

        threat_level = "SAFE"


    elif score <= 70:

        threat_level = "SUSPICIOUS"


    else:

        threat_level = "DANGEROUS"



    return {

        "risk_score": score,

        "threat_level": threat_level

    }