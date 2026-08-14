import re


def analyze_email(sender, subject, body, links, attachments):
    """
    GuardianX AI Email Analyzer

    Detects:
    - Suspicious keywords
    - Fake sender domains
    - Suspicious URLs
    - Dangerous attachments
    - Email behavior patterns
    """


    sender = sender or ""
    subject = subject or ""
    body = body or ""

    links = links or []
    attachments = attachments or []


    text = (
        sender + " " +
        subject + " " +
        body
    ).lower()


    risk_score = 0

    indicators = []



    # =========================
    # Suspicious Keywords
    # =========================

    suspicious_words = [

        "urgent",
        "verify",
        "password",
        "login",
        "payment",
        "security",
        "account",
        "click",
        "bank",
        "invoice",
        "gift",
        "winner",
        "free",
        "confirm",
        "update",
        "limited time",
        "expired",
        "reset password",
        "otp",
        "credit card",
        "refund",
        "bitcoin",
        "crypto"

    ]


    for word in suspicious_words:

        if word in text:

            risk_score += 10

            indicators.append(
                f"Suspicious keyword found: {word}"
            )



    # =========================
    # Sender Reputation
    # =========================

    suspicious_domains = [

        "amaz0n",
        "paypa1",
        "micr0soft",
        "secure-login",
        "verify-account",
        "support-team",
        "bank-secure",
        "goog1e",
        "faceboook"

    ]


    sender_lower = sender.lower()

    sender_trust_score = 100


    for domain in suspicious_domains:

        if domain in sender_lower:

            risk_score += 30

            sender_trust_score -= 40

            indicators.append(
                "Fake or suspicious sender domain detected."
            )



    sender_trust_score = max(
        sender_trust_score,
        0
    )



    # =========================
    # URL Scanner
    # =========================


    suspicious_link_domains = [

        "bit.ly",
        "tinyurl",
        "t.co",
        "goo.gl",
        "amaz0n",
        "paypa1",
        "secure-login",
        "verify-account"

    ]


    extracted_urls = re.findall(
        r'https?://[^\s"\'>]+',
        body
    )


    all_links = list(
        set(
            links + extracted_urls
        )
    )



    link_results = []


    for url in all_links:


        link_status = {

            "url": url,

            "risk": "SAFE"

        }


        risk_score += 15


        for domain in suspicious_link_domains:


            if domain in url.lower():


                risk_score += 25


                link_status["risk"] = "DANGEROUS"


                indicators.append(
                    f"Suspicious URL detected: {domain}"
                )


        indicators.append(
            f"External link detected: {url}"
        )


        link_results.append(
            link_status
        )




    # =========================
    # Attachment Scanner
    # =========================


    dangerous_extensions = [

        ".exe",
        ".zip",
        ".rar",
        ".js",
        ".bat",
        ".scr",
        ".vbs",
        ".cmd",
        ".msi"

    ]


    attachment_results = []



    for attachment in attachments:


        if isinstance(attachment, dict):

            file_name = attachment.get(
                "name",
                "Unknown"
            )

        else:

            file_name = attachment



        file_lower = file_name.lower()


        attachment_status = {

            "name": file_name,

            "risk": "SAFE"

        }



        for ext in dangerous_extensions:


            if file_lower.endswith(ext):


                risk_score += 25


                attachment_status["risk"] = "DANGEROUS"


                indicators.append(
                    f"Dangerous attachment detected: {file_name}"
                )



        attachment_results.append(
            attachment_status
        )




    # =========================
    # Subject Behaviour
    # =========================


    if subject.isupper() and len(subject) > 10:


        risk_score += 10


        indicators.append(
            "Subject is entirely uppercase."
        )



    if subject.count("!") >= 3:


        risk_score += 10


        indicators.append(
            "Too many exclamation marks."
        )




    # =========================
    # Final Score
    # =========================


    risk_score = min(
        risk_score,
        100
    )



    # =========================
    # Risk Decision
    # =========================


    if risk_score >= 70:


        risk_level = "HIGH"

        verdict = (
            "High probability of phishing email."
        )

        recommendation = (
            "Delete this email immediately. "
            "Do not click links or open attachments."
        )



    elif risk_score >= 40:


        risk_level = "MEDIUM"

        verdict = (
            "This email appears suspicious."
        )

        recommendation = (
            "Verify sender identity before "
            "opening links or attachments."
        )



    else:


        risk_level = "LOW"

        verdict = (
            "This email appears safe."
        )

        recommendation = (
            "No major threat detected."
        )




    if not indicators:

        indicators.append(
            "No suspicious indicators detected."
        )


    # Remove duplicate messages

    indicators = list(
        dict.fromkeys(indicators)
    )



    return {


        "risk_score": risk_score,


        "risk_level": risk_level,


        "verdict": verdict,


        "recommendation": recommendation,


        "indicators": indicators,


        "attachments": attachment_results,


        "links": link_results,


        "sender_trust_score": sender_trust_score

    }