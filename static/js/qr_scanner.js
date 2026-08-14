/* ==========================================================
   GuardianX QR Security Scanner JavaScript
========================================================== */


document.addEventListener(
    "DOMContentLoaded",
    function () {


    const scanCameraBtn =
    document.getElementById(
        "scanCameraBtn"
    );

    const stopCameraBtn =
    document.getElementById(
        "stopCameraBtn"
    );

    const cameraArea =
    document.getElementById(
        "cameraArea"
    );

    const cameraVideo =
    document.getElementById(
        "cameraVideo"
    );

    const cameraStatusText =
    document.getElementById(
        "cameraStatusText"
    );

    const qrFileInput =
    document.getElementById(
        "qrFileInput"
    );

    const uploadBtn =
    document.getElementById(
        "uploadBtn"
    );

    const uploadPreviewWrap =
    document.getElementById(
        "uploadPreviewWrap"
    );

    const uploadPreview =
    document.getElementById(
        "uploadPreview"
    );

    const decodedBox =
    document.getElementById(
        "decodedBox"
    );

    const decodedType =
    document.getElementById(
        "decodedType"
    );

    const decodedContent =
    document.getElementById(
        "decodedContent"
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

    const urlDetailsBox =
    document.getElementById(
        "urlDetailsBox"
    );

    const analysisBox =
    document.getElementById(
        "analysisBox"
    );

    const indicatorsBox =
    document.getElementById(
        "indicatorsBox"
    );

    const checksBox =
    document.getElementById(
        "checksBox"
    );

    const resultScheme =
    document.getElementById(
        "resultScheme"
    );

    const resultHostname =
    document.getElementById(
        "resultHostname"
    );

    const resultUrl =
    document.getElementById(
        "resultUrl"
    );

    const resultAnalysis =
    document.getElementById(
        "resultAnalysis"
    );

    const resetBtn =
    document.getElementById(
        "resetBtn"
    );

    const decodeCanvas =
    document.createElement("canvas");

    const decodeCtx =
    decodeCanvas.getContext("2d");

    let scanTimer = null;


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

    }


    function hideError(){


        resultError.classList.add(
            "d-none"
        );

        resultErrorMessage.textContent = "";

    }


    function disableControls(state){


        scanCameraBtn.disabled = state;

        stopCameraBtn.disabled = state;

        qrFileInput.disabled = state;

        uploadBtn.style.pointerEvents = state ? "none" : "";

        uploadBtn.style.opacity = state ? ".5" : "";

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

        item.className = "qr-indicator-item";

        item.textContent = text;

        resultIndicators.appendChild(item);

    }


    function addCheck(check){


        const item =
        document.createElement("li");

        item.className = "qr-check-item";


        const name =
        document.createElement("span");

        name.className = "qr-check-name";

        name.textContent = check.check || "Check";


        const risk =
        document.createElement("span");

        risk.className =
        "badge rounded-pill qr-check-risk";

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

        detail.className = "qr-check-detail";

        detail.textContent = check.detail || "";


        item.appendChild(name);

        item.appendChild(risk);

        item.appendChild(detail);

        resultChecks.appendChild(item);

    }


    function renderAnalysisChips(analysis){


        resultAnalysis.innerHTML = "";

        function addChip(text, type){

            const chip = document.createElement("span");

            chip.className =
                "qr-chip " +
                (
                    type === "danger"
                        ? "qr-chip-danger"
                        : (type === "warn"
                            ? "qr-chip-warn"
                            : "qr-chip-ok")
                );

            chip.textContent = text;

            resultAnalysis.appendChild(chip);

        }

        if(!analysis || typeof analysis !== "object"){

            addChip("No analysis data", "warn");

            return;

        }

        if(analysis.uses_https){
            addChip("HTTPS", "ok");
        } else {
            addChip("HTTP", "warn");
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

                addChip(pair[1], "warn");

                warnings += 1;

            }

        });

        if(warnings === 0){

            addChip("No major signals", "ok");

        }

    }


    function showDecodedContent(content){


        decodedContent.textContent = content || "";

        decodedBox.classList.remove(
            "d-none"
        );

    }


    function renderResult(data){


        const contentType =
        data.content_type || "TEXT";

        decodedType.textContent =
        contentType;

        resultScore.textContent =
        (data.risk_score || 0) + "%";

        resultBadge.textContent =
        data.risk_level || "UNKNOWN";

        setBadge(
            data.risk_level || "UNKNOWN"
        );

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

        if(contentType === "URL"){

            if(resultScheme && data.scheme){
                resultScheme.textContent =
                    String(data.scheme).toUpperCase();
            }

            if(resultHostname && data.hostname){
                resultHostname.textContent = data.hostname;
            }

            if(resultUrl && data.normalized_url){
                resultUrl.textContent = data.normalized_url;
            }

            renderAnalysisChips(data.analysis);

            if(Array.isArray(data.indicators)){

                data.indicators.forEach(addIndicator);

            }

            if(Array.isArray(data.checks)){

                data.checks.forEach(addCheck);

            }

            urlDetailsBox.classList.remove(
                "d-none"
            );

            analysisBox.classList.remove(
                "d-none"
            );

            indicatorsBox.classList.remove(
                "d-none"
            );

            checksBox.classList.remove(
                "d-none"
            );

        }

        else{

            urlDetailsBox.classList.add(
                "d-none"
            );

            analysisBox.classList.add(
                "d-none"
            );

            indicatorsBox.classList.add(
                "d-none"
            );

            checksBox.classList.add(
                "d-none"
            );

        }

        resultCard.classList.remove(
            "d-none"
        );

    }


    /* ======================================================
       Camera
    ====================================================== */


    function stopCamera(){


        if(scanTimer){

            clearInterval(scanTimer);

            scanTimer = null;

        }

        if(cameraVideo.srcObject){

            cameraVideo.srcObject.getTracks().forEach(
                function(track){
                    track.stop();
                }
            );

            cameraVideo.srcObject = null;

        }

        cameraArea.classList.add(
            "d-none"
        );

        stopCameraBtn.classList.add(
            "d-none"
        );

        scanCameraBtn.classList.remove(
            "d-none"
        );

        cameraStatusText.textContent =
        "Scanning for QR code...";

    }


    function handleCameraError(err){


        const name = (err && err.name) || "";

        if(
            name === "NotAllowedError" ||
            name === "PermissionDeniedError"
        ){

            showError(
                "Camera access was denied. You can still use the " +
                "Upload QR Image option below."
            );

        }

        else if(name === "NotFoundError"){

            showError(
                "No camera was found on this device. You can still " +
                "use the Upload QR Image option below."
            );

        }

        else if(name === "NotReadableError"){

            showError(
                "The camera is in use by another application. Close it " +
                "and try again, or use the Upload QR Image option."
            );

        }

        else{

            showError(
                "Unable to start the camera. You can still use the " +
                "Upload QR Image option below."
            );

        }

    }


    function scanFrame(){


        const width = cameraVideo.videoWidth;

        const height = cameraVideo.videoHeight;

        if(!width || !height){
            return;
        }

        const scale = Math.min(1, 640 / Math.max(width, height));

        decodeCanvas.width = Math.round(width * scale);

        decodeCanvas.height = Math.round(height * scale);

        decodeCtx.drawImage(
            cameraVideo,
            0,
            0,
            decodeCanvas.width,
            decodeCanvas.height
        );

        let imageData;

        try{

            imageData = decodeCtx.getImageData(
                0,
                0,
                decodeCanvas.width,
                decodeCanvas.height
            );

        }

        catch(error){

            return;

        }

        const code =
        jsQR(
            imageData.data,
            imageData.width,
            imageData.height
        );

        if(code && code.data){

            const content = String(code.data);

            stopCamera();

            onContentDecoded(content);

        }

    }


    function startCamera(){


        hideError();

        stopCamera();

        if(typeof jsQR === "undefined"){

            showError(
                "The QR decoding library failed to load. Please check " +
                "your connection and refresh the page."
            );

            return;

        }

        if(
            !navigator.mediaDevices ||
            !navigator.mediaDevices.getUserMedia
        ){

            showError(
                "Camera scanning is not supported by this browser. " +
                "You can still use the Upload QR Image option below."
            );

            return;
        }

        cameraArea.classList.remove(
            "d-none"
        );

        scanCameraBtn.classList.add(
            "d-none"
        );

        stopCameraBtn.classList.remove(
            "d-none"
        );

        navigator.mediaDevices.getUserMedia({

            video:{

                facingMode:"environment",

                width:{ideal:1280},

                height:{ideal:720}

            },

            audio:false

        }).then(function(stream){

            cameraVideo.srcObject = stream;

            cameraVideo.play().catch(function(){});

            scanTimer = setInterval(
                scanFrame,
                150
            );

        }).catch(function(err){

            handleCameraError(err);

            stopCamera();

        });

    }


    /* ======================================================
       Image Upload + Decode
    ====================================================== */


    function decodeImageFromSource(source, fallback){

        const image = new Image();

        image.onload = function(){

            const width = image.naturalWidth;

            const height = image.naturalHeight;

            if(!width || !height){

                showError(fallback);

                return;

            }

            const scale = Math.min(1, 1000 / Math.max(width, height));

            decodeCanvas.width = Math.round(width * scale);

            decodeCanvas.height = Math.round(height * scale);

            decodeCtx.drawImage(
                image,
                0,
                0,
                decodeCanvas.width,
                decodeCanvas.height
            );

            let imageData;

            try{

                imageData = decodeCtx.getImageData(
                    0,
                    0,
                    decodeCanvas.width,
                    decodeCanvas.height
                );

            }

            catch(error){

                showError(fallback);

                return;

            }

            let code;

            try{

                code =
                jsQR(
                    imageData.data,
                    imageData.width,
                    imageData.height
                );

            }

            catch(error){

                showError(fallback);

                return;

            }

            if(code && code.data){

                onContentDecoded(String(code.data));

            }

            else{

                showError(fallback);

            }

        };

        image.onerror = function(){

            showError(fallback);

        };

        image.src = source;

    }


    function handleUpload(file){


        hideError();

        if(!file){

            return;
        }

        const validTypes = [
            "image/png",
            "image/jpeg",
            "image/webp"
        ];

        if(validTypes.indexOf(file.type) === -1 && file.type !== ""){

            showError(
                "Unsupported file type. Please upload a PNG, JPG, " +
                "JPEG or WEBP image."
            );

            return;
        }

        const reader = new FileReader();

        reader.onload = function(event){

            uploadPreview.src = event.target.result;

            uploadPreviewWrap.classList.remove(
                "d-none"
            );

            decodeImageFromSource(
                event.target.result,
                "Could not detect a QR code in this image. Try a " +
                "clearer image or use the camera."
            );

        };

        reader.onerror = function(){

            showError(
                "Unable to read the selected image. Please try again."
            );

        };

        reader.readAsDataURL(file);

    }


    qrFileInput.addEventListener(
        "change",
        function(){

            handleUpload(qrFileInput.files[0]);

            qrFileInput.value = "";

        }
    );


    /* ======================================================
       Content Analysis
    ====================================================== */


    function onContentDecoded(content){


        showDecodedContent(content);

        decodedType.textContent = "ANALYZING";

        analyzeContent(content);

    }


    async function analyzeContent(content){


        const requestId =
        (crypto.randomUUID
            ? crypto.randomUUID()
            : "req-" + Date.now() + "-" +
                Math.random().toString(16).slice(2));


        loadingState.classList.remove(
            "d-none"
        );

        disableControls(true);


        try{


            const response =
            await fetch(
                "/qr-scanner/scan",
                {

                    method:"POST",

                    headers:{

                        "Content-Type":
                        "application/json"

                    },

                    body:JSON.stringify({

                        content:content,

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
                    "Unable to analyze the QR content. " +
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

            disableControls(false);

        }

    }


    /* ======================================================
       Clear / Reset
    ====================================================== */


    function clearResults(){


        hideError();

        stopCamera();

        resultScore.textContent =
        "\u2014";

        resultBadge.textContent = "N/A";

        resultBadge.className =
        "qr-result-badge badge rounded-pill px-4 py-2 mt-2";

        if(resultProgress){

            resultProgress.style.width = "0%";

        }

        if(resultScheme){
            resultScheme.textContent = "\u2014";
        }

        if(resultHostname){
            resultHostname.textContent = "\u2014";
        }

        if(resultUrl){
            resultUrl.textContent = "\u2014";
        }

        resultAnalysis.innerHTML = "";

        resultVerdict.textContent =
        "No QR code scanned yet.";

        resultRecommendation.textContent =
        "Scan a QR code above to begin the security check.";

        resultIndicators.innerHTML = "";

        resultChecks.innerHTML = "";

        urlDetailsBox.classList.add(
            "d-none"
        );

        analysisBox.classList.add(
            "d-none"
        );

        indicatorsBox.classList.remove(
            "d-none"
        );

        checksBox.classList.add(
            "d-none"
        );

        resultCard.classList.add(
            "d-none"
        );

        decodedBox.classList.add(
            "d-none"
        );

        decodedContent.textContent = "";

        decodedType.textContent = "UNKNOWN";

        uploadPreviewWrap.classList.add(
            "d-none"
        );

        uploadPreview.removeAttribute("src");

        cameraArea.classList.add(
            "d-none"
        );

    }


    resetBtn.addEventListener(
        "click",
        function(){

            clearResults();

            scanCameraBtn.classList.remove(
                "d-none"
            );

            stopCameraBtn.classList.add(
                "d-none"
            );

        }
    );


    /* ======================================================
       Event Wiring
    ====================================================== */


    scanCameraBtn.addEventListener(
        "click",
        startCamera
    );


    stopCameraBtn.addEventListener(
        "click",
        function(){

            stopCamera();

            hideError();

        }
    );


    cameraVideo.addEventListener(
        "loadedmetadata",
        function(){

            cameraVideo.play().catch(function(){});

        }
    );


});
