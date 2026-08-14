/* ==========================================================
   GuardianX URL Scanner JavaScript
========================================================== */


document.addEventListener(
    "DOMContentLoaded",
    function () {


    const scanForm =
    document.getElementById(
        "urlScanForm"
    );

    const urlInput =
    document.getElementById(
        "urlInput"
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

    const resultScheme =
    document.getElementById(
        "resultScheme"
    );

    const resultHostname =
    document.getElementById(
        "resultHostname"
    );

    const resultHostType =
    document.getElementById(
        "resultHostType"
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
        "url-result-badge badge rounded-pill px-4 py-2 mt-2";

        if(resultProgress){

            resultProgress.style.width = "0%";

        }

        if(resultScheme){
            resultScheme.textContent = "\u2014";
        }

        if(resultHostname){
            resultHostname.textContent = "\u2014";
        }

        if(resultHostType){
            resultHostType.textContent = "\u2014";
        }

        if(resultAnalysis){
            resultAnalysis.innerHTML = "";
        }

        resultVerdict.textContent =
        "No URL scanned yet.";

        resultRecommendation.textContent =
        "Enter a URL above to begin the security check.";

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

        item.className = "url-indicator-item";

        item.textContent = text;

        resultIndicators.appendChild(item);

    }


    function addCheck(check){


        const item =
        document.createElement("li");

        item.className = "url-check-item";


        const name =
        document.createElement("span");

        name.className = "url-check-name";

        name.textContent = check.check || "Check";


        const risk =
        document.createElement("span");

        risk.className =
        "badge rounded-pill url-check-risk";

        risk.textContent = check.risk || "UNKNOWN";


        const riskLevel =
        (check.risk || "").toUpperCase();

        if(riskLevel === "DANGEROUS"){

            risk.classList.add("bg-danger");

        }

        else if(riskLevel === "SUSPICIOUS"){

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

        detail.className = "url-check-detail";

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

        function addChip(text, warn){

            const chip = document.createElement("span");

            chip.className =
                "url-chip " +
                (warn ? "url-chip-warn" : "url-chip-ok");

            chip.textContent = text;

            resultAnalysis.appendChild(chip);

        }

        if(!analysis || typeof analysis !== "object"){

            addChip("No analysis data", true);

            return;

        }

        if(analysis.uses_https){
            addChip("HTTPS", false);
        } else {
            addChip("HTTP", true);
        }

        let warnings = 0;

        const flags = [
            ["is_ip_host", "IP Host"],
            ["is_shortened", "Shortener"],
            ["is_punycode", "Punycode"],
            ["is_lookalike", "Lookalike"],
            ["has_credential_trick", "Credential Trick"],
            ["has_sensitive_params", "Sensitive Params"]
        ];

        flags.forEach(function(pair){

            if(analysis[pair[0]]){

                addChip(pair[1], true);

                warnings += 1;

            }

        });

        if(warnings === 0){

            addChip("No major signals", false);

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

        if(resultScheme && data.scheme){
            resultScheme.textContent =
                String(data.scheme).toUpperCase();
        }

        if(resultHostname && data.hostname){
            resultHostname.textContent = data.hostname;
        }

        if(resultHostType){
            resultHostType.textContent =
                (data.analysis && data.analysis.is_ip_host)
                    ? "IP Address"
                    : "Domain";
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


            const url = urlInput.value.trim();


            if(url === ""){


                showError(
                    "Please enter a URL to scan."
                );

                urlInput.focus();

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
                    "/url-scanner/scan",
                    {

                        method:"POST",

                        headers:{

                            "Content-Type":
                            "application/json"

                        },

                        body:JSON.stringify({

                            url:url,

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
                        "Unable to scan the URL. " +
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


            urlInput.value = "";

            clearResults();

            urlInput.focus();

        }
    );


});


