import re


def analyze_email(sender, subject, body, links, attachments):

    """
    GuardianX AI Email Analyzer

    Features:
    - Keyword detection
    - Sender reputation
    - URL scanner
    - Attachment scanner
    - Risk scoring
    """


    sender = sender or ""
    subject = subject or ""
    body = body or ""

    links = links or []
    attachments = attachments or []


    text = (
        sender +
        " " +
        subject +
        " " +
        body
    ).lower()


    risk_score = 0

    indicators = []



    # ==========================
    # Keyword Scanner
    # ==========================

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
        "winner",
        "free",
        "otp",
        "refund",
        "crypto",
        "confirm",
        "update"

    ]


    for word in suspicious_words:

        if word in text:

            risk_score += 10

            indicators.append(
                f"Suspicious keyword found: {word}"
            )



    # ==========================
    # Sender Reputation
    # ==========================

    sender_score = 100


    suspicious_sender_words = [

        "amaz0n",
        "paypa1",
        "micr0soft",
        "secure-login",
        "verify-account",
        "bank-secure",
        "support-team"

    ]


    for item in suspicious_sender_words:

        if item in sender.lower():

            sender_score -= 40

            risk_score += 30

            indicators.append(
                "Suspicious sender domain detected."
            )



    if sender_score < 0:

        sender_score = 0




    # ==========================
    # URL Scanner
    # ==========================


    url_results = []


    suspicious_urls = [

        "bit.ly",
        "tinyurl",
        "t.co",
        "goo.gl",
        "secure-login",
        "verify-account",
        "paypa1",
        "amaz0n"

    ]



    extracted_urls = re.findall(

        r'https?://[^\s]+',

        body

    )


    all_links = list(

        set(

            links + extracted_urls

        )

    )



    for url in all_links:


        url_data = {


            "url": url,

            "risk": "SAFE"

        }



        risk_score += 10



        for bad in suspicious_urls:


            if bad in url.lower():


                url_data["risk"] = "DANGEROUS"

                risk_score += 25


                indicators.append(

                    f"Suspicious URL detected: {url}"

                )



        url_results.append(url_data)




    # ==========================
    # Attachment Scanner
    # ==========================


    attachment_results = []



    dangerous_extensions = [

        ".exe",
        ".bat",
        ".cmd",
        ".scr",
        ".js",
        ".vbs",
        ".zip",
        ".rar"

    ]



    for attachment in attachments:


        if isinstance(attachment, dict):

            filename = attachment.get(
                "name",
                ""
            )

        else:

            filename = attachment



        result = {


            "name": filename,

            "risk": "SAFE"

        }



        for ext in dangerous_extensions:


            if filename.lower().endswith(ext):


                result["risk"] = "DANGEROUS"


                risk_score += 25


                indicators.append(

                    f"Dangerous attachment detected: {filename}"

                )



        attachment_results.append(result)




    # ==========================
    # Subject Behaviour
    # ==========================


    if subject.isupper() and len(subject) > 10:

        risk_score += 10

        indicators.append(

            "Subject contains excessive uppercase."

        )



    if subject.count("!") >= 3:

        risk_score += 10

        indicators.append(

            "Too many exclamation marks."

        )




    # Limit score

    risk_score = min(

        risk_score,

        100

    )




    # ==========================
    # Final Verdict
    # ==========================


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

            "Verify sender before taking action."

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




    return {


        "risk_score": risk_score,

        "risk_level": risk_level,

        "verdict": verdict,

        "recommendation": recommendation,

        "indicators": indicators,

        "attachments": attachment_results,

        "links": url_results,

        "sender_score": sender_score

    }