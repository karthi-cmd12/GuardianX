/* ==========================================================
   GuardianX Settings JavaScript
   Category navigation, auto-saving toggles, clear history
   confirmation, and instant preference application
   (compact layout / reduced motion).
========================================================== */

(function () {

    "use strict";

    document.addEventListener("DOMContentLoaded", function () {

    /* ======================================================
       Element Cache
    ====================================================== */

    const navButtons = document.querySelectorAll(".st-nav-btn");
    const panels = document.querySelectorAll(".st-panel");

    const saveStatus = document.getElementById("stSaveStatus");
    const saveStatusText = document.getElementById("stSaveStatusText");

    const confirmClearBtn = document.getElementById("stConfirmClearBtn");
    const clearModalEl = document.getElementById("stClearModal");

    let saveTimer = null;
    let statusTimer = null;


    /* ======================================================
       Save Status Toast
    ====================================================== */

    function showSaveStatus(text, isError) {
        if (!saveStatus) {
            return;
        }

        saveStatus.classList.remove("st-save-error");

        if (isError) {
            saveStatus.classList.add("st-save-error");
        }

        saveStatusText.textContent = text;
        saveStatus.classList.add("show");

        clearTimeout(statusTimer);

        statusTimer = window.setTimeout(function () {
            saveStatus.classList.remove("show");
        }, 2600);
    }


    /* ======================================================
       Preference Collection
    ====================================================== */

    function collectSettings() {

        const settings = {};

        document.querySelectorAll("[data-setting]").forEach(function (el) {

            const key = el.getAttribute("data-setting");

            if (el.type === "checkbox") {
                settings[key] = el.checked;
            } else {
                settings[key] = el.value;
            }

        });

        return settings;
    }


    function applyPreferences(settings) {
        if (!settings) {
            return;
        }

        document.body.classList.toggle(
            "gx-compact",
            Boolean(settings.compact_mode)
        );

        const noMotion =
            Boolean(settings.reduced_motion) ||
            settings.animations_enabled === false;

        document.body.classList.toggle(
            "gx-no-motion",
            noMotion
        );
    }


    async function saveSettings(settings) {

        let response;

        try {
            response = await fetch("/settings/update", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify(settings)
            });
        } catch (error) {
            showSaveStatus("Unable to save settings. Try again.", true);
            return;
        }

        if (response.status === 401 ||
            (response.redirected && response.url.indexOf("/login") !== -1)) {
            showSaveStatus("Session expired. Redirecting to login...", true);
            window.setTimeout(function () {
                window.location.href = "/login";
            }, 1200);
            return;
        }

        let data = {};

        try {
            data = await response.json();
        } catch (error) {
            data = {};
        }

        if (data.ok === true && data.settings) {
            applyPreferences(data.settings);
            showSaveStatus("Settings saved.");
        } else {
            showSaveStatus(
                data.error || "Unable to save settings. Try again.",
                true
            );
        }
    }


    function syncSiblingCheckboxes(changed) {

        const key = changed.getAttribute("data-setting");
        const syncId = changed.getAttribute("data-sync");

        if (!syncId) {
            return;
        }

        const sibling = document.getElementById(syncId);

        if (sibling && sibling.type === "checkbox") {
            sibling.checked = changed.checked;
        }

        if (changed.checked !== false && !sibling) {
            return;
        }

        applyPreferences(collectSettings());
    }


    /* ======================================================
       Change Handler (auto-save with debounce)
    ====================================================== */

    document.querySelectorAll("[data-setting]").forEach(function (el) {

        el.addEventListener("change", function () {

            syncSiblingCheckboxes(el);

            clearTimeout(saveTimer);

            saveTimer = window.setTimeout(function () {
                saveSettings(collectSettings());
            }, 250);

        });

    });


    /* ======================================================
       Category Navigation
    ====================================================== */

    navButtons.forEach(function (btn) {

        btn.addEventListener("click", function () {

            const target = btn.getAttribute("data-target");

            navButtons.forEach(function (b) {
                b.classList.toggle("active", b === btn);
            });

            panels.forEach(function (panel) {
                panel.classList.toggle(
                    "active",
                    panel.id === "st-" + target
                );
            });

        });

    });


    /* ======================================================
       Clear History Confirmation
    ====================================================== */

    if (confirmClearBtn) {

        confirmClearBtn.addEventListener("click", async function () {

            confirmClearBtn.disabled = true;

            const original = confirmClearBtn.innerHTML;

            confirmClearBtn.innerHTML =
                '<i class="fa-solid fa-spinner fa-spin"></i> ' +
                (confirmClearBtn.getAttribute("data-loading") || "Deleting...");

            let response;

            try {
                response = await fetch("/history/clear", {
                    method: "POST",
                    headers: {
                        "Accept": "application/json"
                    }
                });
            } catch (error) {
                response = null;
            }

            confirmClearBtn.disabled = false;
            confirmClearBtn.innerHTML = original;

            const modal = bootstrap.Modal.getInstance(clearModalEl);

            if (modal) {
                modal.hide();
            }

            if (!response || response.status === 401 ||
                (response.redirected && response.url.indexOf("/login") !== -1)) {
                showSaveStatus("Session expired. Redirecting to login...", true);
                return;
            }

            if (response.ok) {
                showSaveStatus("Scan history cleared.");
                window.setTimeout(function () {
                    window.location.reload();
                }, 800);
            } else {
                showSaveStatus("Unable to clear scan history.", true);
            }
        });

    }


    /* ======================================================
       Apply Saved Preferences on Load
    ====================================================== */

    applyPreferences(collectSettings());

    });

})();
