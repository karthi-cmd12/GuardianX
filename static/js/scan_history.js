/* ==========================================================
   GuardianX Security Scan History JavaScript
   Loading, rendering, search, filters, sort, pagination,
   details modal, delete + clear-all. All dynamic content is
   rendered with textContent / createElement (no unsafe
   innerHTML with user-controlled data).
========================================================== */


document.addEventListener(
    "DOMContentLoaded",
    function () {


    /* ======================================================
       Element Cache
    ====================================================== */

    const refreshBtn =
    document.getElementById(
        "sxhRefreshBtn"
    );

    const clearAllBtn =
    document.getElementById(
        "sxhClearAllBtn"
    );

    const searchInput =
    document.getElementById(
        "sxhSearch"
    );

    const typeSelect =
    document.getElementById(
        "sxhType"
    );

    const riskSelect =
    document.getElementById(
        "sxhRisk"
    );

    const sortSelect =
    document.getElementById(
        "sxhSort"
    );

    const clearFiltersBtn =
    document.getElementById(
        "sxhClearFiltersBtn"
    );

    const errorBox =
    document.getElementById(
        "sxhError"
    );

    const errorMessage =
    document.getElementById(
        "sxhErrorMessage"
    );

    const loadingEl =
    document.getElementById(
        "sxhLoading"
    );

    const tableCard =
    document.querySelector(
        ".sxh-table-card"
    );

    const tableWrap =
    document.querySelector(
        ".sxh-table-wrap"
    );

    const tbody =
    document.getElementById(
        "sxhTbody"
    );

    const emptyEl =
    document.getElementById(
        "sxhEmpty"
    );

    const emptyTitle =
    document.getElementById(
        "sxhEmptyTitle"
    );

    const emptyText =
    document.getElementById(
        "sxhEmptyText"
    );

    const resultMeta =
    document.getElementById(
        "sxhResultMeta"
    );

    const countBadge =
    document.getElementById(
        "sxhCountBadge"
    );

    const statTotal =
    document.getElementById(
        "sxhStatTotal"
    );

    const statSafe =
    document.getElementById(
        "sxhStatSafe"
    );

    const statSuspicious =
    document.getElementById(
        "sxhStatSuspicious"
    );

    const statHighRisk =
    document.getElementById(
        "sxhStatHighRisk"
    );

    const paginationEl =
    document.getElementById(
        "sxhPagination"
    );

    const prevBtn =
    document.getElementById(
        "sxhPrevBtn"
    );

    const nextBtn =
    document.getElementById(
        "sxhNextBtn"
    );

    const pageInfo =
    document.getElementById(
        "sxhPageInfo"
    );

    // Details modal
    const detailsModalEl =
    document.getElementById(
        "sxhDetailsModal"
    );

    const detailType =
    document.getElementById(
        "sxhDetailType"
    );

    const detailRisk =
    document.getElementById(
        "sxhDetailRisk"
    );

    const detailScore =
    document.getElementById(
        "sxhDetailScore"
    );

    const scoreLabel =
    document.getElementById(
        "sxhScoreLabel"
    );

    const detailTarget =
    document.getElementById(
        "sxhDetailTarget"
    );

    const detailVerdict =
    document.getElementById(
        "sxhDetailVerdict"
    );

    const detailIndicatorsRow =
    document.getElementById(
        "sxhDetailIndicatorsRow"
    );

    const detailIndicators =
    document.getElementById(
        "sxhDetailIndicators"
    );

    const detailRecommendationRow =
    document.getElementById(
        "sxhDetailRecommendationRow"
    );

    const detailRecommendation =
    document.getElementById(
        "sxhDetailRecommendation"
    );

    const detailDate =
    document.getElementById(
        "sxhDetailDate"
    );

    // Clear-all confirmation modal
    const clearModalEl =
    document.getElementById(
        "sxhClearModal"
    );

    const confirmClearBtn =
    document.getElementById(
        "sxhConfirmClearBtn"
    );


    /* ======================================================
       Config + State
    ====================================================== */

    const PER_PAGE = 10;

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
        sort: "newest",
        page: 1,
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
            return "sxh-risk-high";
        }
        if(level === "MEDIUM"){
            return "sxh-risk-medium";
        }
        return "sxh-risk-low";
    }


    function clampScore(value){
        return Math.max(
            0,
            Math.min(100, parseInt(value, 10) || 0)
        );
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
            tableCard.classList.add("sxh-table-hidden");
        }
        else{
            loadingEl.classList.add("d-none");
            tableCard.classList.remove("sxh-table-hidden");
        }
    }


    function buildApiUrl(){
        const params = [];

        params.push("per_page=" + PER_PAGE);

        if(state.page > 1){
            params.push("page=" + state.page);
        }

        if(state.search){
            params.push("search=" + encodeURIComponent(state.search));
        }

        if(state.type){
            params.push("type=" + encodeURIComponent(state.type));
        }

        if(state.risk){
            params.push("risk=" + encodeURIComponent(state.risk));
        }

        if(state.sort !== "newest"){
            params.push("sort=" + encodeURIComponent(state.sort));
        }

        return "/history/data?" + params.join("&");
    }


    function hasActiveFilters(){
        return Boolean(
            state.search || state.type || state.risk
        );
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
        animateCount(statHighRisk, stats.dangerous);
    }


    /* ======================================================
       Row Building (safe DOM only)
    ====================================================== */

    function buildTypeCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Type");

        const meta = typeMeta(item.scan_type);

        const badge = document.createElement("span");
        badge.className = "sxh-type-badge";
        badge.appendChild(makeIcon("fa-solid " + meta.icon));
        badge.appendChild(document.createTextNode(" " + meta.label));

        cell.appendChild(badge);

        return cell;
    }


    function buildRiskCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Risk");

        const pill = document.createElement("span");
        pill.className = "sxh-risk-pill " + riskClass(item.risk_level);
        pill.textContent = item.risk_level || "UNKNOWN";

        cell.appendChild(pill);

        return cell;
    }


    function buildScoreCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Score");

        const score = clampScore(item.risk_score);

        const span = document.createElement("span");
        span.className = "sxh-score";
        span.textContent = String(score) + "/100";

        cell.appendChild(span);

        return cell;
    }


    function buildVerdictCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Verdict");

        const span = document.createElement("span");
        span.className = "sxh-verdict";
        span.textContent = item.verdict || "\u2014";

        cell.appendChild(span);

        return cell;
    }


    function buildDateCell(item){
        const cell = document.createElement("td");
        cell.setAttribute("data-label", "Date / Time");

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
        group.className = "sxh-row-actions";

        const viewBtn = document.createElement("button");
        viewBtn.type = "button";
        viewBtn.className = "gx-btn gx-btn-ghost gx-btn-sm sxh-view-btn";
        viewBtn.setAttribute("data-action", "view");
        viewBtn.setAttribute("data-id", String(item.id));
        viewBtn.title = "View details";
        viewBtn.appendChild(makeIcon("fa-solid fa-eye"));
        viewBtn.appendChild(document.createTextNode(" View"));

        const deleteBtn = document.createElement("button");
        deleteBtn.type = "button";
        deleteBtn.className = "sxh-delete-btn";
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
        row.className = "sxh-row gx-animate-in";
        row.setAttribute("data-id", String(item.id));
        row.setAttribute("data-item", JSON.stringify(item));

        row.appendChild(buildTypeCell(item));
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
       Pagination
    ====================================================== */

    function renderPagination(data){
        const totalPages = parseInt(data.total_pages, 10) || 1;
        const page = parseInt(data.page, 10) || 1;

        if(totalPages <= 1 && page <= 1){
            paginationEl.classList.add("d-none");
            return;
        }

        paginationEl.classList.remove("d-none");

        pageInfo.textContent =
            "Page " + page + " of " + totalPages;

        prevBtn.disabled = page <= 1;
        nextBtn.disabled = page >= totalPages;
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
            emptyTitle.textContent = "No security scans yet";
            emptyText.textContent =
                "Your completed GuardianX scans will appear here.";
        }

        emptyEl.classList.remove("d-none");
        tableWrap.classList.add("d-none");
        paginationEl.classList.add("d-none");
    }


    /* ======================================================
       History Loading
    ====================================================== */

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

            if(data.settings){
                currentSettings = data.settings;
            }

            tableCard.classList.toggle(
                "sxh-no-verdict",
                currentSettings.detailed_results === false
            );

            renderStats(stats);

            renderPagination(data);

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
            "sxh-risk-pill sxh-modal-risk " + riskClass(item.risk_level);

        scoreLabel.textContent =
            item.scan_type === "Password"
                ? "Strength Score"
                : "Risk Score";

        detailScore.textContent =
            String(clampScore(item.risk_score)) + " / 100";

        detailTarget.textContent = item.input_preview || "\u2014";

        detailVerdict.textContent = item.verdict || "\u2014";

        detailDate.textContent = item.created_at_display || "\u2014";

        const details = item.details || {};

        const indicators = Array.isArray(details.indicators)
            ? details.indicators.filter(Boolean)
            : [];

        detailIndicators.textContent = "";

        indicators.forEach(function(indicator){
            const li = document.createElement("li");
            li.textContent = String(indicator);
            detailIndicators.appendChild(li);
        });

        detailIndicatorsRow.classList.toggle(
            "d-none",
            indicators.length === 0
        );

        const recommendation =
            typeof details.recommendation === "string"
                ? details.recommendation.trim()
                : "";

        detailRecommendation.textContent = recommendation;

        detailRecommendationRow.classList.toggle(
            "d-none",
            recommendation.length === 0
        );

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
            "sxh-toast " +
            (isError ? "sxh-toast-error" : "sxh-toast-success");
        toast.setAttribute("role", "status");
        toast.textContent = message;

        document.body.appendChild(toast);

        requestAnimationFrame(function(){
            toast.classList.add("sxh-toast-visible");
        });

        setTimeout(function(){
            toast.classList.remove("sxh-toast-visible");

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

            state.page = 1;

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
       Filter + Sort Handlers
    ====================================================== */

    function applyFilters(){
        if(debounceTimer !== null){
            clearTimeout(debounceTimer);
        }

        debounceTimer = setTimeout(
            function(){
                debounceTimer = null;
                state.page = 1;
                loadHistory();
            },
            300
        );
    }


    function clearFilters(){
        searchInput.value = "";
        typeSelect.value = "";
        riskSelect.value = "";
        sortSelect.value = "newest";

        state.search = "";
        state.type = "";
        state.risk = "";
        state.sort = "newest";
        state.page = 1;

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
            state.page = 1;
            loadHistory();
        }
    );


    riskSelect.addEventListener(
        "change",
        function(){
            state.risk = riskSelect.value;
            state.page = 1;
            loadHistory();
        }
    );


    sortSelect.addEventListener(
        "change",
        function(){
            state.sort = sortSelect.value;
            state.page = 1;
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


    prevBtn.addEventListener(
        "click",
        function(){
            if(state.page > 1){
                state.page -= 1;
                loadHistory();
            }
        }
    );


    nextBtn.addEventListener(
        "click",
        function(){
            state.page += 1;
            loadHistory();
        }
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
