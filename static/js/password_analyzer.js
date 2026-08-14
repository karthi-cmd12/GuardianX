/* ==========================================================
   GuardianX Password Analyzer JavaScript
   Live strength meter + full security analysis.
   NOTE: The password value is never logged to the console,
   stored in localStorage/sessionStorage, or inserted into
   the DOM. Only computed statistics are rendered.
   ========================================================== */


document.addEventListener(
    "DOMContentLoaded",
    function () {


    const analyzeForm =
    document.getElementById(
        "pwAnalyzeForm"
    );

    if(!analyzeForm){
        return;
    }

    const pwInput =
    document.getElementById(
        "pwInput"
    );

    const pwToggle =
    document.getElementById(
        "pwToggle"
    );

    const analyzeBtn =
    document.getElementById(
        "pwAnalyzeBtn"
    );

    const clearBtn =
    document.getElementById(
        "pwClearBtn"
    );

    const pwMeter =
    document.getElementById(
        "pwMeter"
    );

    const pwLiveBar =
    document.getElementById(
        "pwLiveBar"
    );

    const pwLivePercent =
    document.getElementById(
        "pwLivePercent"
    );

    const pwLiveLabel =
    document.getElementById(
        "pwLiveLabel"
    );

    const loadingState =
    document.getElementById(
        "pwLoading"
    );

    const errorBox =
    document.getElementById(
        "pwError"
    );

    const errorMessage =
    document.getElementById(
        "pwErrorMessage"
    );

    const emptyState =
    document.getElementById(
        "pwEmpty"
    );

    const resultCard =
    document.getElementById(
        "pwResult"
    );

    const scoreNum =
    document.getElementById(
        "pwScoreNum"
    );

    const ringFg =
    document.getElementById(
        "pwRingFg"
    );

    const strengthBadge =
    document.getElementById(
        "pwStrengthBadge"
    );

    const verdictEl =
    document.getElementById(
        "pwVerdict"
    );

    const lenEl =
    document.getElementById(
        "pwLen"
    );

    const upperEl =
    document.getElementById(
        "pwUpper"
    );

    const lowerEl =
    document.getElementById(
        "pwLower"
    );

    const digitsEl =
    document.getElementById(
        "pwDigits"
    );

    const specialEl =
    document.getElementById(
        "pwSpecial"
    );

    const uniqueEl =
    document.getElementById(
        "pwUnique"
    );

    const checksEl =
    document.getElementById(
        "pwChecks"
    );

    const weaknessesEl =
    document.getElementById(
        "pwWeaknesses"
    );

    const recommendationsEl =
    document.getElementById(
        "pwRecommendations"
    );

    const smartCard =
    document.getElementById(
        "pwSmartCard"
    );

    const smartMessage =
    document.getElementById(
        "pwSmartMessage"
    );

    const smartList =
    document.getElementById(
        "pwSmartList"
    );

    const smartTip =
    document.getElementById(
        "pwSmartTip"
    );

    const securityRecs =
    document.getElementById(
        "pwSecurityRecs"
    );

    const securityRecsList =
    document.getElementById(
        "pwRecSecList"
    );

    const securityRecsMessage =
    document.getElementById(
        "pwRecSecMessage"
    );

    const RING_CIRCUMFERENCE = 326.7;

    const reducedMotion =
    window.matchMedia &&
    window.matchMedia(
        "(prefers-reduced-motion: reduce)"
    ).matches;

    /* Strength scale — consistent with the existing
       GuardianX register-page strength meter. */

    const STRENGTH_STATES = [
        { min: 1, width: 20, label: "Very Weak", level: "is-very-weak" },
        { min: 2, width: 40, label: "Weak",      level: "is-weak" },
        { min: 3, width: 60, label: "Medium",    level: "is-medium" },
        { min: 4, width: 80, label: "Strong",    level: "is-strong" },
        { min: 5, width: 100, label: "Very Strong", level: "is-very-strong" }
    ];


    /* ======================================================
       Show / Hide Password
    ====================================================== */

    pwToggle.addEventListener(
        "click",
        function () {

            const show =
            pwInput.getAttribute("type") === "password";

            pwInput.setAttribute(
                "type",
                show ? "text" : "password"
            );

            const icon = pwToggle.querySelector("i");

            icon.classList.toggle(
                "fa-eye",
                !show
            );

            icon.classList.toggle(
                "fa-eye-slash",
                show
            );

        }
    );


    /* ======================================================
       Live Strength Meter (runs locally in the browser)
    ====================================================== */

    function updateLiveMeter() {

        const password = pwInput.value;

        let score = 0;

        if (password.length >= 12) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;

        pwLiveBar.className = "pw-meter-fill";

        pwLiveLabel.className = "pw-live-text";

        if (password.length === 0) {

            pwLiveBar.style.width = "0%";

            pwLivePercent.textContent = "0%";

            pwLiveLabel.textContent =
                "Enter a password to begin";

            pwMeter.setAttribute("aria-valuenow", "0");

            return;

        }

        const state =
        STRENGTH_STATES[score - 1] ||
        STRENGTH_STATES[0];

        pwLiveBar.classList.add(state.level);

        pwLiveBar.style.width = state.width + "%";

        pwLivePercent.textContent = state.width + "%";

        pwLiveLabel.textContent = state.label;

        pwLiveLabel.classList.add(
            "has-strength",
            state.level
        );

        pwMeter.setAttribute(
            "aria-valuenow",
            String(state.width)
        );

    }

    pwInput.addEventListener(
        "input",
        updateLiveMeter
    );


    /* ======================================================
       Helpers
    ====================================================== */

    function showError(message) {

        errorMessage.textContent = message;

        errorBox.classList.remove("d-none");

        loadingState.classList.add("d-none");

        emptyState.classList.remove("d-none");

        resultCard.classList.add("d-none");

    }

    function hideError() {

        errorBox.classList.add("d-none");

        errorMessage.textContent = "";

    }

    function resetResult() {

        hideError();

        resultCard.classList.remove(
            "is-very-weak",
            "is-weak",
            "is-medium",
            "is-strong",
            "is-very-strong"
        );

        scoreNum.textContent = "--";

        strengthBadge.textContent = "N/A";

        strengthBadge.className =
            "pw-strength-badge badge rounded-pill px-4 py-2 mt-3";

        ringFg.setAttribute(
            "stroke-dashoffset",
            String(RING_CIRCUMFERENCE)
        );

        verdictEl.textContent =
            "No password analyzed yet.";

        lenEl.textContent = "\u2014";
        upperEl.textContent = "\u2014";
        lowerEl.textContent = "\u2014";
        digitsEl.textContent = "\u2014";
        specialEl.textContent = "\u2014";
        uniqueEl.textContent = "\u2014";

        checksEl.innerHTML = "";
        weaknessesEl.innerHTML = "";
        recommendationsEl.innerHTML = "";

        smartCard.className = "pw-smart-card";

        smartMessage.innerHTML = "";
        smartList.innerHTML = "";
        smartTip.innerHTML = "";

        securityRecsList.innerHTML = "";

        securityRecsMessage.textContent =
            "Analyze a password to receive personalized " +
            "security recommendations.";

        emptyState.classList.remove("d-none");

        resultCard.classList.add("d-none");

    }

    function animateScore(target) {

        if (reducedMotion) {

            scoreNum.textContent = String(target);

            return;

        }

        const start = performance.now();

        const duration = 800;

        function step(now) {

            const progress =
                Math.min(1, (now - start) / duration);

            const eased =
                1 - Math.pow(1 - progress, 3);

            scoreNum.textContent =
                String(Math.round(target * eased));

            if (progress < 1) {

                requestAnimationFrame(step);

            }

        }

        requestAnimationFrame(step);

    }

    function addCheck(check) {

        const item =
        document.createElement("li");

        const met = Boolean(check.met);

        item.className =
            "pw-check-item " +
            (met ? "is-met" : "is-missed");

        const icon =
        document.createElement("i");

        icon.className =
            "fa-solid " +
            (met ? "fa-check" : "fa-xmark");

        const name =
        document.createElement("span");

        name.className = "pw-check-name";

        name.textContent =
            check.check || "Requirement";

        const detail =
        document.createElement("span");

        detail.className = "pw-check-detail";

        detail.textContent = check.detail || "";

        item.appendChild(icon);

        item.appendChild(name);

        item.appendChild(detail);

        checksEl.appendChild(item);

    }

    function addWeakness(text) {

        const item =
        document.createElement("li");

        item.className = "pw-weak-item";

        const icon =
        document.createElement("i");

        icon.className =
            "fa-solid fa-triangle-exclamation";

        item.appendChild(icon);

        item.appendChild(
            document.createTextNode(text)
        );

        weaknessesEl.appendChild(item);

    }

    function addRecommendation(text) {

        const item =
        document.createElement("li");

        item.className = "pw-rec-item";

        const icon =
        document.createElement("i");

        icon.className =
            "fa-solid fa-circle-check";

        item.appendChild(icon);

        item.appendChild(
            document.createTextNode(text)
        );

        recommendationsEl.appendChild(item);

    }

    /* ======================================================
       Smart Password Improvement Suggestions
       Built ONLY from the structured analysis result
       (score, strength_level, flags, variety). The raw
       password value is never inserted into these nodes.
    ====================================================== */

    const SMART_MESSAGES = {

        very_weak: {
            tone: "alert",
            prominent: true,
            title: "Your password needs improvement.",
            note:
                "Add length and character variety to make it " +
                "much harder to guess or crack."
        },

        weak: {
            tone: "alert",
            prominent: true,
            title: "Your password could be stronger.",
            note:
                "Apply the improvements below to " +
                "significantly raise its strength."
        },

        medium: {
            tone: "medium",
            title:
                "Your password has a reasonable foundation, " +
                "but it can be strengthened.",
            note:
                "Apply the missing improvements below to " +
                "reach strong protection."
        },

        strong: {
            tone: "good",
            title:
                "Good job! Your password meets most " +
                "security requirements.",
            note:
                "Consider using a longer passphrase for " +
                "additional protection."
        },

        very_strong: {
            tone: "success",
            title: "Excellent password strength!",
            note:
                "Your password meets the current GuardianX " +
                "strength checks.",
            tip:
                "Remember: use a unique password for every " +
                "important account."
        }

    };

    function buildSmartSuggestions(data) {

        const flags = data.flags || {};

        const suggestions = [];

        suggestions.push({
            text: "Use at least 12\u201316 characters",
            met: Boolean(flags.length_ok)
        });

        suggestions.push({
            text: "Add uppercase letters such as A, B, or C",
            met: Boolean(flags.uppercase_ok)
        });

        suggestions.push({
            text: "Include lowercase letters",
            met: Boolean(flags.lowercase_ok)
        });

        suggestions.push({
            text: "Add numbers that are not predictable sequences",
            met: Boolean(flags.digits_ok)
        });

        suggestions.push({
            text: "Add symbols such as !, @, #, or %",
            met: Boolean(flags.special_ok)
        });

        if (flags.single_category) {

            suggestions.push({
                text:
                    "Mix several character types instead of " +
                    "using a single type",
                met: false
            });

        }

        if (flags.repeated) {

            suggestions.push({
                text:
                    "Avoid repeated characters such as aaa " +
                    "or 111",
                met: false
            });

        }

        if (flags.predictable) {

            suggestions.push({
                text:
                    "Avoid predictable patterns such as " +
                    "123456, abcdef, or keyboard sequences",
                met: false
            });

        }

        if (flags.common) {

            suggestions.push({
                text:
                    "Avoid common passwords and easily " +
                    "guessed phrases",
                met: false
            });

        }

        return suggestions;

    }

    function renderSmartCard(data) {

        const rawLevel =
        (data.strength_level || "MEDIUM").toLowerCase();

        const level =
        rawLevel.replace(/_/g, "-");

        const msg =
        SMART_MESSAGES[rawLevel] ||
        SMART_MESSAGES.medium;

        smartCard.className =
            "pw-smart-card is-" + level;

        smartMessage.innerHTML = "";

        const banner =
        document.createElement("div");

        banner.className =
            "pw-smart-banner" +
            (msg.prominent ? " is-prominent" : "");

        const bannerIcon =
        document.createElement("i");

        if (msg.tone === "success") {

            bannerIcon.className =
                "fa-solid fa-circle-check";

        } else if (msg.tone === "alert") {

            bannerIcon.className =
                "fa-solid fa-triangle-exclamation";

        } else {

            bannerIcon.className =
                "fa-solid fa-shield-halved";

        }

        const bannerText =
        document.createElement("span");

        bannerText.textContent = msg.title;

        banner.appendChild(bannerIcon);

        banner.appendChild(bannerText);

        smartMessage.appendChild(banner);

        if (msg.note) {

            const note =
            document.createElement("p");

            note.className = "pw-smart-note";

            note.textContent = msg.note;

            smartMessage.appendChild(note);

        }

        smartList.innerHTML = "";

        buildSmartSuggestions(data).forEach(
            function (suggestion) {

                const item =
                document.createElement("li");

                item.className =
                    "pw-smart-item " +
                    (suggestion.met ? "is-met" : "is-missed");

                const itemIcon =
                document.createElement("i");

                itemIcon.className =
                    "fa-solid " +
                    (suggestion.met ?
                     "fa-check" :
                     "fa-triangle-exclamation");

                item.appendChild(itemIcon);

                item.appendChild(
                    document.createTextNode(
                        suggestion.text
                    )
                );

                smartList.appendChild(item);

            }
        );

        const tipText =
        msg.tip ||
        "Security tip: use a unique passphrase that is easy " +
        "for you to remember but difficult for others to guess.";

        smartTip.innerHTML = "";

        const tipIcon =
        document.createElement("i");

        tipIcon.className =
            "fa-solid fa-shield-halved";

        smartTip.appendChild(tipIcon);

        smartTip.appendChild(
            document.createTextNode(tipText)
        );

    }

    /* ======================================================
       Security Recommendations section
       Renders the backend security_recommendations list with
       severity colors (critical / warning / good). Only the
       returned texts are used; the raw password is never
       inserted into these nodes.
    ====================================================== */

    const SECURITY_REC_ICONS = {

        critical: "fa-triangle-exclamation",

        warning: "fa-circle-exclamation",

        good: "fa-circle-check"

    };

    function renderSecurityRecs(data) {

        const message =
        data.security_message ||
        "Analyze a password to receive personalized " +
        "security recommendations.";

        securityRecsMessage.textContent = message;

        securityRecsList.innerHTML = "";

        const items = Array.isArray(
            data.security_recommendations
        ) ? data.security_recommendations : [];

        if (items.length === 0) {

            const empty =
            document.createElement("li");

            empty.className =
                "pw-sec-rec-item is-none";

            const icon =
            document.createElement("i");

            icon.className =
                "fa-solid fa-circle-check";

            empty.appendChild(icon);

            empty.appendChild(
                document.createTextNode(
                    "No recommendations needed."
                )
            );

            securityRecsList.appendChild(empty);

            return;

        }

        items.forEach(
            function (recommendation) {

                const severity =
                (recommendation.severity === "critical" ||
                 recommendation.severity === "warning" ||
                 recommendation.severity === "good")
                    ? recommendation.severity
                    : "warning";

                const item =
                document.createElement("li");

                item.className =
                    "pw-sec-rec-item is-" + severity;

                const icon =
                document.createElement("i");

                icon.className =
                    "fa-solid " +
                    (SECURITY_REC_ICONS[severity] ||
                     SECURITY_REC_ICONS.warning);

                item.appendChild(icon);

                item.appendChild(
                    document.createTextNode(
                        recommendation.text || ""
                    )
                );

                securityRecsList.appendChild(item);

            }
        );

    }

    function renderResult(data) {

        const score =
        Math.max(0, Math.min(100, data.score || 0));

        const level =
        (data.strength_level || "MEDIUM").toLowerCase();

        const strength =
        data.strength || "Unknown";

        resultCard.classList.remove(
            "is-very-weak",
            "is-weak",
            "is-medium",
            "is-strong",
            "is-very-strong"
        );

        resultCard.classList.add("is-" + level);

        animateScore(score);

        requestAnimationFrame(
            function () {

                ringFg.setAttribute(
                    "stroke-dashoffset",
                    String(
                        RING_CIRCUMFERENCE -
                        (RING_CIRCUMFERENCE * score / 100)
                    )
                );

            }
        );

        strengthBadge.textContent = strength;

        verdictEl.textContent =
            data.verdict || "No verdict available.";

        lenEl.textContent =
            String(data.length);

        const counts = data.counts || {};

        upperEl.textContent =
            String(counts.uppercase || 0);

        lowerEl.textContent =
            String(counts.lowercase || 0);

        digitsEl.textContent =
            String(counts.digits || 0);

        specialEl.textContent =
            String(counts.special || 0);

        const variety = data.variety || {};

        uniqueEl.textContent =
            String(variety.unique_chars || 0);

        checksEl.innerHTML = "";

        weaknessesEl.innerHTML = "";

        recommendationsEl.innerHTML = "";

        if (Array.isArray(data.checks)) {

            data.checks.forEach(addCheck);

        }

        if (
            Array.isArray(data.weaknesses) &&
            data.weaknesses.length > 0
        ) {

            data.weaknesses.forEach(addWeakness);

        } else {

            const item =
            document.createElement("li");

            item.className =
                "pw-weak-item is-none";

            const icon =
            document.createElement("i");

            icon.className =
                "fa-solid fa-circle-check";

            item.appendChild(icon);

            item.appendChild(
                document.createTextNode(
                    "No major weaknesses detected."
                )
            );

            weaknessesEl.appendChild(item);

        }

        if (Array.isArray(data.recommendations)) {

            data.recommendations.forEach(
                addRecommendation
            );

        }

        renderSmartCard(data);

        renderSecurityRecs(data);

        emptyState.classList.add("d-none");

        resultCard.classList.remove("d-none");

        resultCard.scrollIntoView({
            behavior: reducedMotion ? "auto" : "smooth",
            block: "nearest"
        });

    }


    /* ======================================================
       Analyze Handler
    ====================================================== */

    analyzeForm.addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();

            const requestId =
            (crypto.randomUUID
                ? crypto.randomUUID()
                : "req-" + Date.now() + "-" +
                    Math.random().toString(16).slice(2));

            const password = pwInput.value;

            if (password.trim() === "") {

                showError(
                    "Please enter a password to analyze."
                );

                pwInput.focus();

                return;

            }

            hideError();

            emptyState.classList.add("d-none");

            resultCard.classList.add("d-none");

            loadingState.classList.remove("d-none");

            analyzeBtn.disabled = true;

            try {

                const response =
                await fetch(
                    "/password-analyzer/analyze",
                    {

                        method: "POST",

                        headers: {

                            "Content-Type":
                            "application/json"

                        },

                        body: JSON.stringify({

                            password: password,

                            requestId: requestId

                        })

                    }
                );

                if (response.status === 401) {

                    showError(
                        "Your session has expired. " +
                        "Please login and try again."
                    );

                    return;

                }

                if (
                    response.redirected &&
                    response.url.indexOf("/login") !== -1
                ) {

                    showError(
                        "Your session has expired. " +
                        "Please login and try again."
                    );

                    return;

                }

                let data;

                try {

                    data = await response.json();

                }

                catch (error) {

                    showError(
                        "The server returned an invalid " +
                        "response. Please try again."
                    );

                    return;

                }

                if (!response.ok) {

                    showError(
                        data.error ||
                        "Unable to analyze the password. " +
                        "Please try again."
                    );

                    return;

                }

                if (data.error) {

                    showError(data.error);

                    return;

                }

                renderResult(data);

            }

            catch (error) {

                showError(
                    "Network error. Please check your " +
                    "connection and try again."
                );

            }

            finally {

                loadingState.classList.add("d-none");

                analyzeBtn.disabled = false;

            }

        }
    );


    /* ======================================================
       Clear Handler
    ====================================================== */

    clearBtn.addEventListener(
        "click",
        function () {

            pwInput.value = "";

            pwInput.setAttribute("type", "password");

            const icon = pwToggle.querySelector("i");

            icon.classList.add("fa-eye");

            icon.classList.remove("fa-eye-slash");

            updateLiveMeter();

            resetResult();

            pwInput.focus();

        }
    );


    /* Initial state */

    resetResult();


});
