# ==========================================================
# GuardianX Password Security Analyzer
#
# Offline, deterministic, rule-based password strength
# analysis engine.
#
# SECURITY: This module NEVER stores, logs, displays or
# persists the analyzed password. It receives the password
# string, computes numeric character statistics and flags,
# and immediately discards the original value. No password
# value is ever included in the returned result dict.
# ==========================================================


# ==========================================================
# Configuration
# ==========================================================

# Maximum password length accepted by the analyzer. Used by
# the route to reject oversized input before analysis.
MAX_LENGTH = 512

# Recommended minimum password length.
MIN_LENGTH = 12

# Base criteria weights (kept together for easy tuning).
CRITERION_WEIGHT = 15

LENGTH_BONUS = {
    20: 25,
    16: 20,
    12: 12,
    8: 6,
}

PENALTY_COMMON = 45
PENALTY_REPEATED = 10
PENALTY_SEQUENCE = 12
PENALTY_SINGLE_CATEGORY = 15
PENALTY_TOO_SHORT = 15

# Strength level thresholds (score is 0-100).
VERY_STRONG_MIN = 80
STRONG_MIN = 60
MEDIUM_MIN = 40
WEAK_MIN = 20

SEQUENCE_RUN = 3
REPEAT_RUN = 3

# A run this long is treated as an excessive, highly guessable
# repetition (e.g. 'aaaaa' or '11111') and reported as a
# critical weakness.
EXCESSIVE_REPEAT_RUN = 5


# ==========================================================
# Character Pools (used for pattern detection)
# ==========================================================

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
KEYBOARD = "qwertyuiopasdfghjklzxcvbnm"


# ==========================================================
# Common Password List
# (curated subset; exact matches and case variations only)
# ==========================================================

COMMON_PASSWORDS = {
    "password",
    "password1",
    "password123",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "12345",
    "1234",
    "123123",
    "000000",
    "111111",
    "abc123",
    "qwerty",
    "qwerty123",
    "letmein",
    "admin",
    "admin123",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
    "princess",
    "football",
    "shadow",
    "sunshine",
    "starwars",
    "trustno1",
    "superman",
    "iloveyou",
    "1q2w3e4r",
    "access",
    "hello",
    "charlie",
}


# ==========================================================
# Guessable Word List
#
# Common words, first names and guessable bases that, when
# combined with trailing digits/symbols (e.g. "summer2024"),
# produce an easily guessable structure. Derived from the
# alphabetic cores of COMMON_PASSWORDS plus a small curated
# set of very common guessable words.
# ==========================================================

GUESSABLE_WORDS = {
    "".join(char for char in word.lower() if char.isalpha())
    for word in COMMON_PASSWORDS
    if len("".join(char for char in word.lower() if char.isalpha())) >= 4
}

GUESSABLE_WORDS.update({
    "summer", "winter", "spring", "autumn", "secret", "money",
    "love", "angel", "baby", "boss", "hunter", "tiger", "soccer",
    "hockey", "baseball", "basketball", "computer", "internet",
    "jordan", "michael", "jennifer", "jessica", "daniel",
    "matthew", "andrew", "joshua", "anthony", "charles",
    "william", "david", "robert", "richard", "thomas", "joseph",
    "jason", "kevin", "brian", "brandon", "justin", "samuel",
    "gregory", "patrick", "alexander", "jack", "amanda", "ashley",
    "jasmine", "sophia", "olivia", "emma",
})


# ==========================================================
# Small Helpers
# ==========================================================


def _position_map(chars):
    """Maps each character in a pool to its index."""
    return {char: index for index, char in enumerate(chars)}


def _longest_repeating_block(password):
    """
    Returns the smallest period (2 or more) with which the
    password repeats, e.g. 'abcabc' -> 3, '121212' -> 2,
    '123123' -> 3, 'abcabc12!A' -> 3 (leading block).
    Returns 0 when no repeating block exists. Pure single-
    character repetitions (e.g. 'aaaa') are skipped because
    they are already reported as repeated characters.
    Used to detect common patterns such as 'abcabc' or '123123'.
    """
    size = len(password)

    for period in range(2, size // 2 + 1):

        block = password[:period]

        if len(set(block)) == 1:
            continue

        if size % period == 0 and block * (size // period) == password:
            return period

        if password.startswith(block * 2):
            return period

    return 0


def _guessable_structure(password):
    """
    Detects an easily guessable structure: a common word or name
    with trailing digits/symbols appended (e.g. 'summer2024').
    Returns True when the alphabetic core (after stripping trailing
    digits/symbols) is a well-known guessable word.
    """
    lower = password.lower()

    stripped = lower.rstrip("0123456789!@#$%^&*_-+=?.,:;~")

    if len(stripped) < 4:
        return False

    return stripped in GUESSABLE_WORDS


def _longest_sequence_run(password, pool):
    """
    Returns the length of the longest ascending or descending
    consecutive run (in pool order) within the password.
    Used to detect predictable patterns such as 'abc' or '321'.
    """
    pos = _position_map(pool)

    longest = 1
    current = 1
    previous = None
    direction = 0

    for char in password:

        index = pos.get(char)

        if index is None:

            previous = None
            direction = 0
            current = 1

            continue

        if previous is not None:

            diff = index - previous

            if diff in (1, -1):

                if direction != 0 and direction != diff:
                    current = 2
                else:
                    current += 1

                direction = diff
                longest = max(longest, current)

            else:

                direction = 0
                current = 1

        previous = index

    return longest


def _longest_repeated_run(password):
    """
    Returns the length of the longest run of an identical
    character, e.g. 'aaa' in 'passaaaaord'.
    """
    longest = 1
    current = 1
    previous = None

    for char in password:

        if char == previous:

            current += 1
            longest = max(longest, current)

        else:

            current = 1

        previous = char

    return longest


def _count_character_types(password):
    """
    Counts uppercase, lowercase, digit and other (special)
    characters in the password. No password content is
    retained after these counts are computed.
    """
    uppercase = sum(1 for char in password if char.isupper())
    lowercase = sum(1 for char in password if char.islower())
    digits = sum(1 for char in password if char.isdigit())

    special = len(password) - uppercase - lowercase - digits

    return {
        "uppercase": uppercase,
        "lowercase": lowercase,
        "digits": digits,
        "special": special,
    }


def _categories_present(counts):
    categories = 0

    if counts["uppercase"]:
        categories += 1

    if counts["lowercase"]:
        categories += 1

    if counts["digits"]:
        categories += 1

    if counts["special"]:
        categories += 1

    return categories


# ==========================================================
# Strength Level Mapping
# ==========================================================


def _strength_level(score):
    if score >= VERY_STRONG_MIN:
        return "VERY_STRONG"

    if score >= STRONG_MIN:
        return "STRONG"

    if score >= MEDIUM_MIN:
        return "MEDIUM"

    if score >= WEAK_MIN:
        return "WEAK"

    return "VERY_WEAK"


STRENGTH_LABELS = {
    "VERY_WEAK": "Very Weak",
    "WEAK": "Weak",
    "MEDIUM": "Medium",
    "STRONG": "Strong",
    "VERY_STRONG": "Very Strong",
}


def _build_verdict(strength):
    if strength == "VERY_STRONG":
        return (
            "Excellent password. This password offers strong "
            "resistance to common guessing and cracking attacks."
        )

    if strength == "STRONG":
        return (
            "Strong password. Meets the core requirements for "
            "secure authentication."
        )

    if strength == "MEDIUM":
        return (
            "Medium strength. Increase length and character variety "
            "to reduce guessing risk."
        )

    if strength == "WEAK":
        return (
            "Weak password. Add length and a mix of character types "
            "to strengthen it."
        )

    return (
        "Very weak password. This password is easily guessed or "
        "cracked and should be changed immediately."
    )


def _build_security_recommendations(
    strength,
    length,
    counts,
    categories,
    is_common,
    longest_repeat,
    longest_seq,
    repeat_block_period,
    guessable,
):
    """
    Builds a severity-coded list of security recommendations.

    Recommendations are generated dynamically from the actual
    detected weaknesses (critical fixes first, then improvement
    warnings, then strength-level advice and best practices for
    strong/very strong passwords). No password content is ever
    included.

    Each item is a dict:
        {"text": str, "severity": "critical" | "warning" | "good"}
    """
    uppercase_ok = counts["uppercase"] > 0
    lowercase_ok = counts["lowercase"] > 0
    digits_ok = counts["digits"] > 0
    special_ok = counts["special"] > 0

    recommendations = []

    def add(text, severity):
        for existing in recommendations:
            if existing["text"] == text:
                return
        recommendations.append(
            {"text": text, "severity": severity}
        )

    # ------------------------------------------------------
    # Critical fixes (weakness-driven, shown first)
    # ------------------------------------------------------

    if length < 8:
        add("Use at least 12\u201316 characters.", "critical")

    if is_common:
        add(
            "Avoid common passwords and easily guessed phrases.",
            "critical",
        )

    if longest_seq >= SEQUENCE_RUN:
        add(
            "Avoid predictable patterns such as 123456, "
            "abcdef, or keyboard sequences.",
            "critical",
        )

    if longest_repeat >= EXCESSIVE_REPEAT_RUN:
        add(
            "Avoid excessive repeated characters such as "
            "aaaaa or 11111.",
            "critical",
        )

    if categories == 1:
        add(
            "Mix uppercase and lowercase letters, numbers and "
            "symbols instead of a single type.",
            "critical",
        )

    # ------------------------------------------------------
    # Improvement warnings (weakness-driven)
    # ------------------------------------------------------

    if not uppercase_ok:
        add("Add uppercase letters such as A, B, or C.", "warning")

    if not lowercase_ok:
        add("Include lowercase letters.", "warning")

    if not digits_ok:
        add(
            "Add numbers that are not predictable sequences.",
            "warning",
        )

    if not special_ok:
        add(
            "Add special characters such as !, @, #, or %.",
            "warning",
        )

    if (
        MIN_LENGTH > length >= 8
        and strength in ("VERY_WEAK", "WEAK")
    ):
        add(
            "Increase the password length to 12\u201316 characters.",
            "warning",
        )

    if (
        longest_repeat >= REPEAT_RUN
        and longest_repeat < EXCESSIVE_REPEAT_RUN
    ):
        add(
            "Avoid repeated characters such as aaa or 111.",
            "warning",
        )

    if repeat_block_period >= 2:
        add(
            "Avoid common repeating patterns such as abcabc "
            "or 123123.",
            "warning",
        )

    if guessable:
        add(
            "Avoid easily guessable structures such as a "
            "common word followed by digits.",
            "warning",
        )

    # ------------------------------------------------------
    # Strength-level advice (tailored to the analysis)
    # ------------------------------------------------------

    if strength == "VERY_WEAK":

        if not (uppercase_ok and lowercase_ok):
            add(
                "Add uppercase and lowercase letters.",
                "warning",
            )

        if not (digits_ok and special_ok):
            add(
                "Include numbers and special characters.",
                "warning",
            )

        if is_common or longest_seq >= SEQUENCE_RUN:
            add(
                "Avoid common words and predictable patterns.",
                "warning",
            )

    elif strength == "WEAK":

        if not uppercase_ok or not lowercase_ok:
            add(
                "Mix uppercase and lowercase letters.",
                "warning",
            )

        if not digits_ok:
            add("Include numbers.", "warning")

        if not special_ok:
            add("Add special characters.", "warning")

        if longest_seq >= SEQUENCE_RUN:
            add("Avoid predictable sequences.", "warning")

    elif strength == "MEDIUM":

        if length < 14:
            add(
                "Increase the password length to 14+ characters.",
                "warning",
            )

        if not (
            uppercase_ok
            and lowercase_ok
            and digits_ok
            and special_ok
        ):
            add(
                "Use a combination of letters, numbers and symbols.",
                "warning",
            )

        add(
            "Avoid using names, dates or common words.",
            "warning",
        )

    elif strength == "STRONG":

        add("Good password strength.", "good")

        if length < 16:
            add(
                "For better security, use 14\u201316+ characters.",
                "good",
            )

        add(
            "Avoid reusing this password on other websites.",
            "good",
        )

    elif strength == "VERY_STRONG":

        add("Excellent password strength.", "good")

        add("Keep it unique and don't reuse it.", "good")

        add(
            "Consider storing it in a trusted password manager.",
            "good",
        )

    return recommendations


SECURITY_MESSAGES = {
    "VERY_WEAK": (
        "This password is very weak and should be changed "
        "immediately."
    ),
    "WEAK": (
        "This password needs improvement before it can protect "
        "an account."
    ),
    "MEDIUM": (
        "This password is moderately strong but can be improved."
    ),
    "STRONG": "Good password strength.",
    "VERY_STRONG": "Excellent password strength.",
}


# ==========================================================
# Main Analyze Function
# ==========================================================


def analyze_password(raw_password):
    """
    Analyzes a password string and returns strength metrics.

    Pure offline heuristic analysis. The password value is
    never stored, logged, displayed or included in the result.

    Returns:
        valid, score, strength, strength_level, verdict,
        recommendations, weaknesses, checks, length, counts,
        variety
    """
    password = str(raw_password)

    length = len(password)

    # ------------------------------------------------------
    # Character statistics
    # ------------------------------------------------------

    counts = _count_character_types(password)

    categories = _categories_present(counts)

    unique_chars = len(set(password))

    unique_ratio = unique_chars / max(length, 1)

    longest_repeat = _longest_repeated_run(password)

    longest_seq = max(
        _longest_sequence_run(password, ALPHABET),
        _longest_sequence_run(password, DIGITS),
        _longest_sequence_run(password, KEYBOARD),
    )

    is_common = password.lower() in COMMON_PASSWORDS

    repeat_block_period = _longest_repeating_block(password)

    guessable = _guessable_structure(password)

    # ------------------------------------------------------
    # Requirement criteria
    # ------------------------------------------------------

    length_ok = length >= MIN_LENGTH
    uppercase_ok = counts["uppercase"] > 0
    lowercase_ok = counts["lowercase"] > 0
    digits_ok = counts["digits"] > 0
    special_ok = counts["special"] > 0

    criteria_met = sum(
        [
            length_ok,
            uppercase_ok,
            lowercase_ok,
            digits_ok,
            special_ok,
        ]
    )

    # ------------------------------------------------------
    # Weakness detection
    # ------------------------------------------------------

    weaknesses = []

    if length < MIN_LENGTH:
        weaknesses.append(
            "Short password ("
            + str(length)
            + " characters; at least "
            + str(MIN_LENGTH)
            + " recommended)."
        )

    if not uppercase_ok:
        weaknesses.append("No uppercase letters.")

    if not lowercase_ok:
        weaknesses.append("No lowercase letters.")

    if not digits_ok:
        weaknesses.append("No numbers.")

    if not special_ok:
        weaknesses.append("No special characters.")

    if categories == 1:
        weaknesses.append("Only one character type used.")

    if longest_repeat >= REPEAT_RUN:
        weaknesses.append(
            "Repeated characters detected (a run of "
            + str(longest_repeat)
            + " identical characters)."
        )

    if longest_seq >= SEQUENCE_RUN:
        weaknesses.append(
            "Predictable character sequence detected "
            "(such as abc or 123)."
        )

    if is_common:
        weaknesses.append(
            "This is a commonly used password that appears "
            "in public breach lists."
        )

    if repeat_block_period >= 2:
        weaknesses.append(
            "Common repeating pattern detected (such as "
            "abcabc or 123123)."
        )

    if longest_repeat >= EXCESSIVE_REPEAT_RUN:
        weaknesses.append(
            "Excessive repeated characters detected (a run of "
            + str(longest_repeat)
            + " identical characters)."
        )

    if guessable:
        weaknesses.append(
            "Easily guessable structure detected (a common "
            "word combined with digits or symbols)."
        )

    # ------------------------------------------------------
    # Score calculation
    # ------------------------------------------------------

    score = CRITERION_WEIGHT * criteria_met

    for threshold in sorted(LENGTH_BONUS, reverse=True):
        if length >= threshold:
            score += LENGTH_BONUS[threshold]
            break

    if length >= 8:
        score += int(round(5 * unique_ratio))

    if is_common:
        score -= PENALTY_COMMON

    if longest_repeat >= REPEAT_RUN:
        score -= PENALTY_REPEATED

    if longest_seq >= SEQUENCE_RUN:
        score -= PENALTY_SEQUENCE

    if categories == 1:
        score -= PENALTY_SINGLE_CATEGORY

    if length < 8:
        score -= PENALTY_TOO_SHORT

    if is_common:
        score = min(score, 15)

    score = max(0, min(score, 100))

    strength = _strength_level(score)

    # ------------------------------------------------------
    # Recommendations (derived from actual weaknesses only)
    # ------------------------------------------------------

    recommendations = []

    if is_common:
        recommendations.append(
            "Avoid common words, names and frequently used "
            "passwords like this one."
        )

    if length < MIN_LENGTH:
        recommendations.append(
            "Use at least "
            + str(MIN_LENGTH)
            + "-16 characters for a strong password."
        )

    if not (uppercase_ok and lowercase_ok and digits_ok and special_ok):
        recommendations.append(
            "Include a mix of uppercase letters, lowercase letters, "
            "numbers and special characters."
        )

    if categories == 1:
        recommendations.append(
            "Combine multiple character types instead of using "
            "a single type."
        )

    if longest_repeat >= REPEAT_RUN or longest_seq >= SEQUENCE_RUN:
        recommendations.append(
            "Avoid repeated characters and predictable sequences "
            "such as 'abc' or '123'."
        )

    if score < STRONG_MIN:
        recommendations.append(
            "Consider a passphrase or a password manager that "
            "generates a unique, random password for every account."
        )

    # ------------------------------------------------------
    # Requirement checklist
    # ------------------------------------------------------

    checks = [
        {
            "check": "At least " + str(MIN_LENGTH) + " characters",
            "met": length_ok,
            "detail": "Current length: " + str(length),
        },
        {
            "check": "Uppercase letter",
            "met": uppercase_ok,
            "detail": str(counts["uppercase"]) + " found"
            if uppercase_ok
            else "Missing",
        },
        {
            "check": "Lowercase letter",
            "met": lowercase_ok,
            "detail": str(counts["lowercase"]) + " found"
            if lowercase_ok
            else "Missing",
        },
        {
            "check": "Number",
            "met": digits_ok,
            "detail": str(counts["digits"]) + " found"
            if digits_ok
            else "Missing",
        },
        {
            "check": "Special character",
            "met": special_ok,
            "detail": str(counts["special"]) + " found"
            if special_ok
            else "Missing",
        },
    ]

    # ------------------------------------------------------
    # Structured analysis flags
    #
    # Additive only. Exposes booleans that are already
    # computed above so the frontend can build personalized
    # improvement suggestions without re-deriving them.
    # No password content is included.
    # ------------------------------------------------------

    flags = {
        "length_ok": length_ok,
        "uppercase_ok": uppercase_ok,
        "lowercase_ok": lowercase_ok,
        "digits_ok": digits_ok,
        "special_ok": special_ok,
        "single_category": categories == 1,
        "repeated": longest_repeat >= REPEAT_RUN,
        "predictable": longest_seq >= SEQUENCE_RUN,
        "common": is_common,
        "excessive_repeated": longest_repeat >= EXCESSIVE_REPEAT_RUN,
        "repeating_pattern": repeat_block_period >= 2,
        "guessable": guessable,
    }

    # ------------------------------------------------------
    # Result (never contains the password itself)
    # ------------------------------------------------------

    return {
        "valid": True,
        "score": score,
        "strength": STRENGTH_LABELS.get(strength, "Unknown"),
        "strength_level": strength,
        "verdict": _build_verdict(strength),
        "flags": flags,
        "security_message": SECURITY_MESSAGES.get(
            strength, SECURITY_MESSAGES["MEDIUM"]
        ),
        "security_recommendations": _build_security_recommendations(
            strength=strength,
            length=length,
            counts=counts,
            categories=categories,
            is_common=is_common,
            longest_repeat=longest_repeat,
            longest_seq=longest_seq,
            repeat_block_period=repeat_block_period,
            guessable=guessable,
        ),
        "recommendations": recommendations,
        "weaknesses": weaknesses,
        "checks": checks,
        "length": length,
        "counts": counts,
        "variety": {
            "unique_chars": unique_chars,
            "categories": categories,
            "repetitive": longest_repeat >= REPEAT_RUN,
            "longest_run": longest_repeat,
        },
    }
