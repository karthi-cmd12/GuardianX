/* ==========================================================
   GuardianX Scan History JavaScript
   Loading, rendering, search, filters, details modal,
   delete + clear-all. All dynamic content is rendered with
   textContent / createElement (no unsafe innerHTML with
   user-controlled data).
========================================================== */


document.addEventListener(
    "DOMContentLoaded",
    function () {


    /* ======================================================
       Element Cache
    ====================================================== */

    const refreshBtn =
    document.getElementById(
        "shRefreshBtn"
    );

    const clearAllBtn =
    document.getElementById(
        "shClearAllBtn"
    );

    const searchInput =
    document.getElementById(
        "shSearch"
    );

    const typeSelect =
    document.getElementById(
        "shType"
    );

    const riskSelect =
    document.getElementById(
        "shRisk"
    );

    const dateInput =
    document.getElementById(
        "shDate"
    );

    const clearFiltersBtn =
    document.getElementById(
        "shClearFiltersBtn"
    );

    const errorBox =
    document.getElementById(
        "shError"
    );

    const errorMessage =
    document.getElementById(
        "shErrorMessage"
    );

    const loadingEl =
    document.getElementById(
        "shLoading"
    );

    const tableCard =
    document.querySelector(
        ".sh-table-card"
    );

    const tableWrap =
    document.querySelector(
        ".sh-table-wrap"
    );

    const tbody =
    document.getElementById(
        "shTbody"
    );

    const emptyEl =
    document.getElementById(
        "shEmpty"
    );

    const emptyTitle =
    document.getElementById(
        "shEmptyTitle"
    );

    const emptyText =
    document.getElementById(
        "shEmptyText"
    );

    const resultMeta =
    document.getElementById(
        "shResultMeta"
    );

    const countBadge =
    document.getElementById(
        "shCountBadge"
    );

    const statTotal =
    document.getElementById(
        "shStatTotal"
    );

    const statSafe =
    document.getElementById(
        "shStatSafe"
    );

    const statSuspicious =
    document.getElementById(
        "shStatSuspicious"
    );

    const statDangerous =
    document.getElementById(
        "shStatDangerous"
    );

    // Details modal
    const detailsModalEl =
    document.getElementById(
        "shDetailsModal"
    );

    const detailType =
    document.getElementById(
        "shDetailType"
    );

    const detailRisk =
    document.getElementById(
        "shDetailRisk"
    );

    const detailScore =
    document.getElementById(
        "shDetailScore"
    );

    const detailVerdict =
    document.getElementById(
        "shDetailVerdict"
    );

    const detailTarget =
    document.getElementById(
        "shDetailTarget"
    );

    const detailDate =
    document.getElementById(
        "shDetailDate"
    );

    // Clear-all confirmation modal
    const clearModalEl =
    document.getElementById(
        "shClearModal"
    );

    const confirmClearBtn =
    document.getElementById(
        "shConfirmClearBtn"
    );


    /* ======================================================
       Config + State
    ====================================================== */

    const TYPE_META = {
        Email:    { icon: "fa-envelope-circle-check", label: "Email" },
        URL:      { icon: "fa-link", label: "URL" },
        SMS:      { icon: "fa-comment-sms", label: "SMS" },
        QR:       { icon: "fa-qrcode", label: "QR" },
        Password: { icon: "fa-key", label: "Password" }
    };

    const state = {
        search: "",
        type: "",
        risk: "",
        date: "",
        loading: false
    };

    let debounceTimer = null;

    let detailsModal = null;

    let clearModal = null;

    let currentSettings = {
        detailed_results: true,
        risk_display: "level"
    };


    /* ======================================================
       Small Helpers
    ====================================================== */

    function typeMeta(scanType){
        return TYPE_META[scanType] || {
            icon: "fa-shield-halved",
            label: scanType || "Unknown"
        };
    }


    function riskClass(level){
        if(level === "HIGH"){
            return "sh-risk-high";
        }
        if(level === "MEDIUM"){
            return "sh-risk-medium";
        }
        return "sh-risk-low";
    }


    function makeIcon(classes){
        const icon = document.createElement("i");
        icon.className = classes;
        icon.setAttribute("aria-hidden", "true");
        return icon;
    }


    function showError(message){
        errorMessage.textContent = message;
        errorBox.classList.remove("d-none");
    }


    function hideError(){
        errorBox.classList.add("d-none");
        errorMessage.textContent = "";
    }


    function setLoading(active){
        state.loading = active;

        if(active){
            loadingEl.classList.remove("d-none");
            tableCard.classList.add("sh-table-hidden");
        }
        else{
            loadingEl.classList.add("d-none");
            tableCard.classList.remove("sh-table-hidden");
        }
    }


    function buildApiUrl(){
        const params = [];

        if(state.search){
            params.push("search=" + encodeURIComponent(state.search));
        }

        if(state.type){
            params.push("type=" + encodeURIComponent(state.type));
        }

        if(state.risk){
            params.push("risk=" + encodeURIComponent(state.risk));
        }

        if(state.date){
            params.push("date=" + encodeURIComponent(state.date));
        }

        params.push("limit=500");

        return "/history/data?" + params.join("&");
    }


    /* ======================================================
       Stats
    ====================================================== */

    function animateCount(el, target){
        const start = parseInt(
            el.getAttribute("data-count") || "0",
            10
        );

        const end = Math.max(0, parseInt(target, 10) || 0);

        const reduceMotion = window.matchMedia(
            "(prefers-reduced-motion: reduce)"
        ).matches;

        if(reduceMotion){
            el.textContent = String(end);
            el.setAttribute("data-count", String(end));
            return;
        }

        const duration = 600;

        const startTime = performance.now();

        function frame(now){
            const progress = Math.min((now - startTime) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            const value = Math.round(start + (end - start) * eased);

            el.textContent = String(value);

            if(progress < 1){
                requestAnimationFrame(frame);
            }
            else{
                el.setAttribute("data-count", String(end));
            }
        }

        requestAnimationFrame(frame);
    }


    function renderStats(stats){
        animateCount(statTotal, stats.total);
        animateCount(statSafe, stats.safe);
        animateCount(statSuspicious, stats.suspicious);
        animateCount(statDangerous, stats.dangerous);
    }


    /* ======================================================
       Row Building (safe DOM only)
    ====================================================== */

    function buildTypeCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Type");

        const meta = typeMeta(item.scan_type);

        const badge = document.createElement("span");
        badge.className = "sh-type-badge";
        badge.appendChild(makeIcon("fa-solid " + meta.icon));
        badge.appendChild(document.createTextNode(" " + meta.label));

        cell.appendChild(badge);

        return cell;
    }


    function buildRiskCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Risk");

        const pill = document.createElement("span");
        pill.className = "sh-risk-pill " + riskClass(item.risk_level);

        if (currentSettings.risk_display === "score") {
            pill.textContent = String(
                Math.max(0, Math.min(100, parseInt(item.risk_score, 10) || 0))
            );
            pill.title = item.risk_level || "UNKNOWN";
            pill.classList.add("sh-risk-score");
        } else {
            pill.textContent = item.risk_level || "UNKNOWN";
        }

        cell.appendChild(pill);

        return cell;
    }


    function buildTargetCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Target");

        const strong = document.createElement("strong");
        strong.className = "sh-target";
        strong.textContent = item.input_preview || "\u2014";

        cell.appendChild(strong);

        return cell;
    }


    function buildScoreCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Score");

        const score = Math.max(
            0,
            Math.min(100, parseInt(item.risk_score, 10) || 0)
        );

        cell.textContent = String(score);

        return cell;
    }


    function buildVerdictCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Verdict");

        const span = document.createElement("span");
        span.className = "sh-verdict";
        span.textContent = item.verdict || "\u2014";

        cell.appendChild(span);

        return cell;
    }


    function buildDateCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Date");

        const time = document.createElement("time");
        time.textContent = item.created_at_display || "\u2014";
        if(item.created_at){
            time.setAttribute("datetime", item.created_at);
        }

        cell.appendChild(time);

        return cell;
    }


    function buildActionCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Action");

        const group = document.createElement("div");
        group.className = "sh-row-actions";

        const viewBtn = document.createElement("button");
        viewBtn.type = "button";
        viewBtn.className = "gx-btn gx-btn-ghost gx-btn-sm sh-view-btn";
        viewBtn.setAttribute("data-action", "view");
        viewBtn.setAttribute("data-id", String(item.id));
        viewBtn.title = "View details";
        viewBtn.appendChild(makeIcon("fa-solid fa-eye"));
        viewBtn.appendChild(document.createTextNode(" View"));

        const deleteBtn = document.createElement("button");
        deleteBtn.type = "button";
        deleteBtn.className = "sh-delete-btn";
        deleteBtn.setAttribute("data-action", "delete");
        deleteBtn.setAttribute("data-id", String(item.id));
        deleteBtn.title = "Delete entry";
        deleteBtn.setAttribute("aria-label", "Delete scan history entry");
        deleteBtn.appendChild(makeIcon("fa-solid fa-trash"));

        group.appendChild(viewBtn);
        group.appendChild(deleteBtn);
        cell.appendChild(group);

        return cell;
    }


    function buildRow(item){
        const row = document.createElement("tr");
        row.className = "sh-row gx-animate-in";
        row.setAttribute("data-id", String(item.id));
        row.setAttribute("data-item", JSON.stringify(item));

        row.appendChild(buildTypeCell(item));
        row.appendChild(buildTargetCell(item));
        row.appendChild(buildRiskCell(item));
        row.appendChild(buildScoreCell(item));
        row.appendChild(buildVerdictCell(item));
        row.appendChild(buildDateCell(item));
        row.appendChild(buildActionCell(item));

        return row;
    }


    function renderRows(items){
        tbody.textContent = "";

        items.forEach(function(item){
            tbody.appendChild(buildRow(item));
        });
    }


    /* ======================================================
       Empty State
    ====================================================== */

    function showEmpty(hasFilters, total){
        if(total > 0){
            return;
        }

        if(hasFilters){
            emptyTitle.textContent = "No matching scans";
            emptyText.textContent =
                "No scan history matches your current filters. " +
                "Try adjusting or clearing the filters.";
        }
        else{
            emptyTitle.textContent = "No scans yet";
            emptyText.textContent =
                "Run a security scan and it will appear here automatically.";
        }

        emptyEl.classList.remove("d-none");
        tableWrap.classList.add("d-none");
    }


    /* ======================================================
       History Loading
    ====================================================== */

    function hasActiveFilters(){
        return Boolean(
            state.search || state.type || state.risk || state.date
        );
    }


    async function loadHistory(){

        if(state.loading){
            return;
        }

        hideError();

        setLoading(true);

        try{

            const response =
            await fetch(
                buildApiUrl(),
                {
                    headers:{
                        "Accept":"application/json"
                    }
                }
            );

            if(response.status === 401){
                showError(
                    "Your session has expired. " +
                    "Please login and try again."
                );
                setLoading(false);
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
                setLoading(false);
                return;
            }

            let data;

            try{
                data = await response.json();
            }
            catch(error){
                showError(
                    "The server returned an invalid response. " +
                    "Please try again."
                );
                setLoading(false);
                return;
            }

            if(!response.ok){
                showError(
                    data.error ||
                    "Unable to load your scan history. " +
                    "Please try again."
                );
                setLoading(false);
                return;
            }

            const items = Array.isArray(data.items) ? data.items : [];
            const total = parseInt(data.total, 10) || items.length;
            const stats = data.stats || {
                total: total,
                safe: 0,
                suspicious: 0,
                dangerous: 0
            };

            if (data.settings) {
                currentSettings = data.settings;
            }

            tableCard.classList.toggle(
                "sh-no-verdict",
                currentSettings.detailed_results === false
            );

            renderStats(stats);

            emptyEl.classList.add("d-none");
            tableWrap.classList.remove("d-none");

            renderRows(items);

            countBadge.textContent =
                total + (total === 1 ? " record" : " records");

            const filtersActive = hasActiveFilters();

            if(total === 0){
                showEmpty(filtersActive, 0);
            }
            else if(filtersActive){
                resultMeta.textContent =
                    "Showing " + items.length +
                    " of " + total + " record(s).";
            }
            else{
                resultMeta.textContent =
                    "Your most recent " + items.length +
                    " security scan(s).";
            }

        }
        catch(error){

            showError(
                "Network error. Please check your " +
                "connection and try again."
            );

        }
        finally{

            setLoading(false);

        }
    }


    /* ======================================================
       Details Modal
    ====================================================== */

    function openDetails(item){
        const meta = typeMeta(item.scan_type);

        detailType.textContent = meta.label;

        detailRisk.textContent = item.risk_level || "UNKNOWN";
        detailRisk.className =
            "sh-risk-pill " + riskClass(item.risk_level);

        detailScore.textContent =
            String(
                Math.max(
                    0,
                    Math.min(100, parseInt(item.risk_score, 10) || 0)
                )
            ) + " / 100";

        detailVerdict.textContent = item.verdict || "\u2014";

        detailTarget.textContent = item.input_preview || "\u2014";

        detailDate.textContent = item.created_at_display || "\u2014";

        if(detailsModal === null){
            detailsModal = new bootstrap.Modal(detailsModalEl);
        }

        detailsModal.show();
    }


    /* ======================================================
       Delete + Clear All
    ====================================================== */

    function showToast(message, isError){
        const toast = document.createElement("div");
        toast.className =
            "sh-toast " +
            (isError ? "sh-toast-error" : "sh-toast-success");
        toast.setAttribute("role", "status");
        toast.textContent = message;

        document.body.appendChild(toast);

        requestAnimationFrame(function(){
            toast.classList.add("sh-toast-visible");
        });

        setTimeout(function(){
            toast.classList.remove("sh-toast-visible");

            setTimeout(function(){
                if(toast.parentNode){
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, 2600);
    }


    async function deleteEntry(id){
        try{

            const response =
            await fetch(
                "/history/delete/" + encodeURIComponent(id),
                {
                    method:"POST",
                    headers:{
                        "Accept":"application/json"
                    }
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

            let data = null;

            try{
                data = await response.json();
            }
            catch(error){
                data = null;
            }

            if(!response.ok){
                showError(
                    (data && data.error) ||
                    "Unable to delete this entry. " +
                    "Please try again."
                );
                return;
            }

            showToast("Scan history entry deleted.");

            loadHistory();

        }
        catch(error){

            showError(
                "Network error. Please check your " +
                "connection and try again."
            );

        }
    }


    function openClearConfirm(){
        if(clearModal === null){
            clearModal = new bootstrap.Modal(clearModalEl);
        }

        clearModal.show();
    }


    async function clearAll(){
        try{

            const response =
            await fetch(
                "/history/clear",
                {
                    method:"POST",
                    headers:{
                        "Accept":"application/json"
                    }
                }
            );

            if(clearModal !== null){
                clearModal.hide();
            }

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

            let data = null;

            try{
                data = await response.json();
            }
            catch(error){
                data = null;
            }

            if(!response.ok){
                showError(
                    (data && data.error) ||
                    "Unable to clear your history. " +
                    "Please try again."
                );
                return;
            }

            const cleared = data && data.deleted ? data.deleted : 0;

            showToast(
                cleared + (cleared === 1
                    ? " record cleared."
                    : " records cleared.")
            );

            loadHistory();

        }
        catch(error){

            if(clearModal !== null){
                clearModal.hide();
            }

            showError(
                "Network error. Please check your " +
                "connection and try again."
            );

        }
    }


    /* ======================================================
       Filter Handlers
    ====================================================== */

    function applyFilters(){
        if(debounceTimer !== null){
            clearTimeout(debounceTimer);
        }

        debounceTimer = setTimeout(
            function(){
                debounceTimer = null;
                loadHistory();
            },
            300
        );
    }


    function clearFilters(){
        searchInput.value = "";
        typeSelect.value = "";
        riskSelect.value = "";
        dateInput.value = "";

        state.search = "";
        state.type = "";
        state.risk = "";
        state.date = "";

        loadHistory();
    }


    searchInput.addEventListener(
        "input",
        function(){
            state.search = searchInput.value.trim();
            applyFilters();
        }
    );


    typeSelect.addEventListener(
        "change",
        function(){
            state.type = typeSelect.value;
            loadHistory();
        }
    );


    riskSelect.addEventListener(
        "change",
        function(){
            state.risk = riskSelect.value;
            loadHistory();
        }
    );


    dateInput.addEventListener(
        "change",
        function(){
            state.date = dateInput.value;
            loadHistory();
        }
    );


    clearFiltersBtn.addEventListener(
        "click",
        clearFilters
    );


    refreshBtn.addEventListener(
        "click",
        loadHistory
    );


    clearAllBtn.addEventListener(
        "click",
        openClearConfirm
    );


    confirmClearBtn.addEventListener(
        "click",
        clearAll
    );


    /* ======================================================
       Table Action Delegation
    ====================================================== */

    tbody.addEventListener(
        "click",
        function(event){
            const target = event.target.closest(
                "[data-action]"
            );

            if(!target){
                return;
            }

            const id = target.getAttribute("data-id");

            if(!id){
                return;
            }

            const action = target.getAttribute("data-action");

            if(action === "view"){

                const row = target.closest("tr[data-item]");

                let data = null;

                if(row){
                    try{
                        data = JSON.parse(
                            row.getAttribute("data-item") || "null"
                        );
                    }
                    catch(error){
                        data = null;
                    }
                }

                if(data){
                    openDetails(data);
                }
            }
            else if(action === "delete"){

                deleteEntry(id);
            }
        }
    );


    /* ======================================================
       Boot
    ====================================================== */

    loadHistory();

});
