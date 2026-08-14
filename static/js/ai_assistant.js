/* ==========================================================
   GuardianX AI Assistant Chat JavaScript
   Reuses the existing POST /analyze API.
   ========================================================== */

(function () {

    "use strict";

    const chatBody = document.getElementById("chatBody");
    const chatEmpty = document.getElementById("chatEmpty");
    const chatInput = document.getElementById("chatInput");
    const chatSendBtn = document.getElementById("chatSendBtn");


    // ==========================================================
    // Helpers
    // ==========================================================

    function escapeHtml(text) {

        const div = document.createElement("div");

        div.textContent = text;

        return div.innerHTML;

    }


    function scrollToBottom() {

        chatBody.scrollTop = chatBody.scrollHeight;

    }


    function addUserMessage(text) {

        chatBody.insertAdjacentHTML(
            "beforeend",
            '<div class="gx-msg gx-msg-user">' +
                '<div class="gx-msg-bubble">' + escapeHtml(text) + "</div>" +
            "</div>"
        );

        scrollToBottom();

    }


    function addTypingIndicator() {

        chatBody.insertAdjacentHTML(
            "beforeend",
            '<div class="gx-msg gx-msg-ai gx-msg-typing">' +
                '<span class="gx-msg-dot"></span>' +
                '<span class="gx-msg-dot"></span>' +
                '<span class="gx-msg-dot"></span>' +
            "</div>"
        );

        scrollToBottom();

    }


    function removeTypingIndicator() {

        const typing = chatBody.querySelector(".gx-msg-typing");

        if (typing) {
            typing.remove();
        }

    }


    function threatLevel(data) {

        return (data.threat_level || "").toUpperCase();

    }


    function badgeClass(level) {

        if (level === "DANGEROUS") {
            return "gx-badge-danger";
        }

        if (level === "SUSPICIOUS") {
            return "gx-badge-warning";
        }

        return "gx-badge-success";

    }


    function addAiResult(data) {

        const level = threatLevel(data);

        let reasonsHtml = "";

        (data.reasons || []).forEach(function (reason) {

            reasonsHtml +=
                '<li><i class="fa-solid fa-circle-exclamation"></i>' +
                escapeHtml(reason) +
                "</li>";

        });

        if (!reasonsHtml) {
            reasonsHtml = "<li>No specific indicators detected.</li>";
        }

        chatBody.insertAdjacentHTML(
            "beforeend",
            '<div class="gx-msg gx-msg-ai">' +
                '<div class="gx-msg-bubble gx-msg-result">' +
                    '<div class="gx-result-top">' +
                        '<span class="gx-badge ' + badgeClass(level) + '">' +
                            escapeHtml(level) +
                        "</span>" +
                        '<span class="gx-result-score">' +
                            escapeHtml(String(data.risk_score)) + '<small>%</small>' +
                        "</span>" +
                    "</div>" +
                    '<h4>Detection Reasons</h4>' +
                    '<ul class="gx-result-reasons">' + reasonsHtml + "</ul>" +
                    '<h4>Recommendation</h4>' +
                    '<p class="gx-result-recommendation">' +
                        escapeHtml(data.recommendation || "No recommendation available.") +
                    "</p>" +
                "</div>" +
            "</div>"
        );

        scrollToBottom();

    }


    function addAiError(message) {

        chatBody.insertAdjacentHTML(
            "beforeend",
            '<div class="gx-msg gx-msg-ai">' +
                '<div class="gx-msg-bubble gx-msg-error">' +
                    '<i class="fa-solid fa-triangle-exclamation"></i>' +
                    escapeHtml(message || "AI service unavailable.") +
                "</div>" +
            "</div>"
        );

        scrollToBottom();

    }


    // ==========================================================
    // Analysis
    // ==========================================================

    async function analyze() {

        const message = chatInput.value.trim();

        if (message === "") {

            chatInput.focus();

            return;

        }


        addUserMessage(message);

        chatInput.value = "";

        chatInput.style.height = "auto";


        chatSendBtn.disabled = true;

        chatSendBtn.querySelector("span").textContent = "Analyzing...";

        chatSendBtn.querySelector("i").className = "fa-solid fa-spinner fa-spin";


        addTypingIndicator();


        try {

            const response = await fetch("/analyze", {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({ message: message })

            });


            const data = await response.json();

            removeTypingIndicator();

            if (data.error) {
                addAiError(data.error);
            } else {
                addAiResult(data);
            }

        } catch (err) {

            removeTypingIndicator();

            addAiError("AI service unavailable.");

        } finally {

            chatSendBtn.disabled = false;

            chatSendBtn.querySelector("span").textContent = "Analyze";

            chatSendBtn.querySelector("i").className = "fa-solid fa-paper-plane";

            chatInput.focus();

        }

    }


    // ==========================================================
    // Events
    // ==========================================================

    document.addEventListener("DOMContentLoaded", function () {

        chatSendBtn.addEventListener("click", analyze);

        chatInput.addEventListener("keydown", function (e) {

            if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {

                e.preventDefault();

                analyze();

            }

        });


        // Suggestion chips fill and submit a sample message

        document.querySelectorAll(".gx-chip").forEach(function (chip) {

            chip.addEventListener("click", function () {

                chatInput.value = chip.getAttribute("data-fill") || "";

                chatInput.style.height = "auto";

                chatInput.style.height = chatInput.scrollHeight + "px";

                analyze();

            });

        });


        // Auto-grow the textarea

        chatInput.addEventListener("input", function () {

            chatInput.style.height = "auto";

            chatInput.style.height = chatInput.scrollHeight + "px";

        });

    });

})();
