/* ==========================================================
   GuardianX SMS Scam Detector JavaScript
========================================================== */


document.addEventListener(
    "DOMContentLoaded",
    function () {


    const scanForm =
    document.getElementById(
        "smsScanForm"
    );

    const senderInput =
    document.getElementById(
        "senderInput"
    );

    const messageInput =
    document.getElementById(
        "messageInput"
    );

    const charCount =
    document.getElementById(
        "charCount"
    );

    const scanBtn =
    document.getElementById(
        "scanBtn"
    );

    const clearBtn =
    document.getElementById(
        "clearBtn"
    );

    const loadingState =
    document.getElementById(
        "loadingState"
    );

    const resultCard =
    document.getElementById(
        "resultCard"
    );

    const resultError =
    document.getElementById(
        "resultError"
    );

    const resultErrorMessage =
    document.getElementById(
        "resultErrorMessage"
    );

    const resultScore =
    document.getElementById(
        "resultScore"
    );

    const resultBadge =
    document.getElementById(
        "resultBadge"
    );

    const resultProgress =
    document.getElementById(
        "resultProgress"
    );

    const resultVerdict =
    document.getElementById(
        "resultVerdict"
    );

    const resultRecommendation =
    document.getElementById(
        "resultRecommendation"
    );

    const resultIndicators =
    document.getElementById(
        "resultIndicators"
    );

    const resultChecks =
    document.getElementById(
        "resultChecks"
    );

    const resultSender =
    document.getElementById(
        "resultSender"
    );

    const resultSenderType =
    document.getElementById(
        "resultSenderType"
    );

    const resultChars =
    document.getElementById(
        "resultChars"
    );

    const resultWords =
    document.getElementById(
        "resultWords"
    );

    const resultLinks =
    document.getElementById(
        "resultLinks"
    );

    const resultPhone =
    document.getElementById(
        "resultPhone"
    );

    const resultAnalysis =
    document.getElementById(
        "resultAnalysis"
    );


    /* ======================================================
       Helpers
    ====================================================== */


    function showError(message){


        resultErrorMessage.textContent =
        message;

        resultError.classList.remove(
            "d-none"
        );

        loadingState.classList.add(
            "d-none"
        );

        resultCard.classList.add(
            "d-none"
        );

    }


    function hideError(){


        resultError.classList.add(
            "d-none"
        );

        resultErrorMessage.textContent = "";

    }


    function clearResults(){


        hideError();

        resultScore.textContent =
        "\u2014";

        resultBadge.textContent = "N/A";

        resultBadge.className =
        "sms-result-badge badge rounded-pill px-4 py-2 mt-2";

        if(resultProgress){

            resultProgress.style.width = "0%";

        }

        if(resultSender){
            resultSender.textContent = "\u2014";
        }

        if(resultSenderType){
            resultSenderType.textContent = "\u2014";
        }

        if(resultChars){
            resultChars.textContent = "\u2014";
        }

        if(resultWords){
            resultWords.textContent = "\u2014";
        }

        if(resultLinks){
            resultLinks.textContent = "\u2014";
        }

        if(resultPhone){
            resultPhone.textContent = "\u2014";
        }

        if(resultAnalysis){
            resultAnalysis.innerHTML = "";
        }

        resultVerdict.textContent =
        "No SMS scanned yet.";

        resultRecommendation.textContent =
        "Paste a message above to begin the security check.";

        resultIndicators.innerHTML = "";

        resultChecks.innerHTML = "";

        resultCard.classList.add(
            "d-none"
        );

    }


    function setBadge(level){


        resultBadge.classList.remove(
            "bg-danger",
            "bg-warning",
            "bg-success",
            "text-dark"
        );

        if(level === "HIGH"){

            resultBadge.classList.add(
                "bg-danger"
            );

        }

        else if(level === "MEDIUM"){

            resultBadge.classList.add(
                "bg-warning",
                "text-dark"
            );

        }

        else{

            resultBadge.classList.add(
                "bg-success"
            );

        }

    }


    function addIndicator(text){


        const item =
        document.createElement("li");

        item.className = "sms-indicator-item";

        item.textContent = text;

        resultIndicators.appendChild(item);

    }


    function addCheck(check){


        const item =
        document.createElement("li");

        item.className = "sms-check-item";


        const name =
        document.createElement("span");

        name.className = "sms-check-name";

        name.textContent = check.check || "Check";


        const risk =
        document.createElement("span");

        risk.className =
        "badge rounded-pill sms-check-risk";

        risk.textContent = check.risk || "UNKNOWN";


        const riskLevel =
        (check.risk || "").toUpperCase();

        if(
            riskLevel === "DANGEROUS" ||
            riskLevel === "HIGH"
        ){

            risk.classList.add("bg-danger");

        }

        else if(
            riskLevel === "SUSPICIOUS" ||
            riskLevel === "MEDIUM"
        ){

            risk.classList.add(
                "bg-warning",
                "text-dark"
            );

        }

        else{

            risk.classList.add("bg-success");

        }


        const detail =
        document.createElement("span");

        detail.className = "sms-check-detail";

        detail.textContent = check.detail || "";


        item.appendChild(name);

        item.appendChild(risk);

        item.appendChild(detail);

        resultChecks.appendChild(item);

    }


    function renderAnalysisChips(analysis){


        if(!resultAnalysis){
            return;
        }

        resultAnalysis.innerHTML = "";

        function addChip(text, type){

            const chip = document.createElement("span");

            chip.className =
                "sms-chip " +
                (
                    type === "danger"
                        ? "sms-chip-danger"
                        : (type === "warn"
                            ? "sms-chip-warn"
                            : "sms-chip-ok")
                );

            chip.textContent = text;

            resultAnalysis.appendChild(chip);

        }

        if(!analysis || typeof analysis !== "object"){

            addChip("No analysis data", "warn");

            return;

        }

        if(analysis.link_level){

            addChip(
                "Link: " + analysis.link_level,
                analysis.link_level === "HIGH" ? "danger" : "warn"
            );

        }
        else if(analysis.has_link){

            addChip("Has link", "ok");

        }
        else{

            addChip("No link", "ok");

        }

        const flags = [
            ["uses_urgency", "Urgency"],
            ["requests_sensitive_data", "Asks sensitive data"],
            ["money_bait", "Money / prize bait"],
            ["impersonation", "Brand impersonation"],
            ["contains_threats", "Threats"],
            ["suspicious_sender", "Suspicious sender"],
            ["language_issues", "Language red flags"],
            ["reply_bait", "Reply bait"]
        ];

        let warnings = 0;

        flags.forEach(function(pair){

            if(analysis[pair[0]]){

                const dangerous = [
                    "requests_sensitive_data",
                    "contains_threats"
                ].indexOf(pair[0]) !== -1;

                addChip(
                    pair[1],
                    dangerous ? "danger" : "warn"
                );

                warnings += 1;

            }

        });

        if(warnings === 0 && !analysis.has_link){

            addChip("No major signals", "ok");

        }

    }


    function renderResult(data){


        resultScore.textContent =
        (data.risk_score || 0) + "%";

        resultBadge.textContent =
        data.risk_level || "UNKNOWN";

        setBadge(
            data.risk_level || "UNKNOWN"
        );

        if(resultSender){
            resultSender.textContent =
                (data.message_details && data.message_details.sender)
                    ? data.message_details.sender
                    : "Not provided";
        }

        if(resultSenderType){
            resultSenderType.textContent =
                data.sender_type || "UNKNOWN";
        }

        if(resultChars && data.message_details){
            resultChars.textContent =
                data.message_details.characters;
        }

        if(resultWords && data.message_details){
            resultWords.textContent =
                data.message_details.words;
        }

        if(resultLinks){
            resultLinks.textContent =
                (data.message_details && data.message_details.has_link)
                    ? "Detected"
                    : "None";
        }

        if(resultPhone){
            resultPhone.textContent =
                (data.message_details && data.message_details.has_phone)
                    ? "Yes"
                    : "No";
        }

        renderAnalysisChips(data.analysis);

        resultVerdict.textContent =
        data.verdict || "No verdict available.";

        resultRecommendation.textContent =
        data.recommendation ||
        "No recommendation available.";

        const score =
        Math.max(0, Math.min(100, data.risk_score || 0));

        if(resultProgress){

            requestAnimationFrame(
                function(){
                    resultProgress.style.width = score + "%";
                }
            );

        }

        resultIndicators.innerHTML = "";

        resultChecks.innerHTML = "";

        if(Array.isArray(data.indicators)){

            data.indicators.forEach(addIndicator);

        }

        if(Array.isArray(data.checks)){

            data.checks.forEach(addCheck);

        }

        resultCard.classList.remove(
            "d-none"
        );

    }


    /* ======================================================
       Character Counter
    ====================================================== */


    messageInput.addEventListener(
        "input",
        function(){

            charCount.textContent =
            messageInput.value.length;

        }
    );


    /* ======================================================
       Scan Handler
    ====================================================== */


    scanForm.addEventListener(
        "submit",
        async function(event){


            event.preventDefault();


            const requestId =
            (crypto.randomUUID
                ? crypto.randomUUID()
                : "req-" + Date.now() + "-" +
                    Math.random().toString(16).slice(2));


            const message = messageInput.value.trim();

            const sender = senderInput.value.trim();


            if(message === ""){


                showError(
                    "Please enter the SMS message to analyze."
                );

                messageInput.focus();

                return;

            }


            clearResults();

            loadingState.classList.remove(
                "d-none"
            );

            scanBtn.disabled = true;


            try{


                const response =
                await fetch(
                    "/sms-detector/scan",
                    {

                        method:"POST",

                        headers:{

                            "Content-Type":
                            "application/json"

                        },

                        body:JSON.stringify({

                            sender:sender,

                            message:message,

                            requestId:requestId

                        })

                    }

                );


                if(response.status === 401){

                    showError(
                        "Your session has expired. " +
                        "Please login and try again."
                    );

                    return;

                }


                if(
                    response.redirected &&
                    response.url.indexOf("/login") !== -1
                ){

                    showError(
                        "Your session has expired. " +
                        "Please login and try again."
                    );

                    return;

                }


                let data;

                try{

                    data = await response.json();

                }

                catch(error){

                    showError(
                        "The server returned an invalid " +
                        "response. Please try again."
                    );

                    return;

                }


                if(!response.ok){

                    showError(
                        data.error ||
                        "Unable to analyze the message. " +
                        "Please try again."
                    );

                    return;

                }


                if(data.error){

                    showError(data.error);

                    return;

                }


                renderResult(data);


            }


            catch(error){


                showError(
                    "Network error. Please check your " +
                    "connection and try again."
                );


            }


            finally{


                loadingState.classList.add(
                    "d-none"
                );

                scanBtn.disabled = false;

            }


        }
    );


    /* ======================================================
       Clear Handler
    ====================================================== */


    clearBtn.addEventListener(
        "click",
        function(){


            senderInput.value = "";

            messageInput.value = "";

            charCount.textContent = "0";

            clearResults();

            messageInput.focus();

        }
    );


});
