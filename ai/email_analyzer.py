def analyze_email(subject, sender):

    suspicious_keywords = [
        "urgent",
        "verify",
        "password",
        "payment",
        "click",
        "account suspended",
        "claim reward",
        "winner"
    ]

    score = 0
    threats = []

    text = (subject + " " + sender).lower()


    for word in suspicious_keywords:

        if word in text:
            score += 15
            threats.append(
                f"Suspicious keyword detected: {word}"
            )


    if "@" in sender:

        domain = sender.split("@")[-1]

        if domain not in [
            "google.com",
            "instagram.com",
            "spotify.com",
            "adobe.com"
        ]:

            score += 20

            threats.append(
                "Unknown sender domain"
            )


    if score >= 70:

        risk = "HIGH RISK"

    elif score >= 40:

        risk = "MEDIUM RISK"

    else:

        risk = "SAFE"


    return {

        "score": score,
        "risk": risk,
        "threats": threats

    }