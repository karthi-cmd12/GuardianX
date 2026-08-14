/* ==========================================================
   GuardianX Profile JavaScript
   Personal information form, change password flow,
   password visibility toggles, strength meter and
   loading / success / error states.
   Passwords are never logged or echoed to the console.
========================================================== */

(function () {

    "use strict";

    document.addEventListener("DOMContentLoaded", function () {

    /* ======================================================
       Element Cache
    ====================================================== */

    const profileForm = document.getElementById("pfProfileForm");
    const profileSubmit = document.getElementById("pfProfileSubmit");
    const profileMsg = document.getElementById("pfProfileMsg");

    const pwForm = document.getElementById("pfPwForm");
    const pwSubmit = document.getElementById("pfPwSubmit");
    const pwMsg = document.getElementById("pfPwMsg");

    const currentPw = document.getElementById("pfCurrentPw");
    const newPw = document.getElementById("pfNewPw");
    const confirmPw = document.getElementById("pfConfirmPw");

    const strengthBar = document.getElementById("pfStrengthBar");
    const strengthText = document.getElementById("pfStrengthText");

    const pwModalEl = document.getElementById("pfPwModal");


    /* ======================================================
       Small Helpers
    ====================================================== */

    function showFieldError(input, message) {

        const parent = input.closest(".pf-field") || input.parentElement;

        let error = parent.querySelector(".gx-form-error");

        if (!error) {
            error = document.createElement("small");
            error.className = "gx-form-error";
            parent.appendChild(error);
        }

        error.textContent = message;
        input.classList.add("is-invalid");
    }


    function clearFieldError(input) {

        const parent = input.closest(".pf-field") || input.parentElement;

        const error = parent.querySelector(".gx-form-error");

        if (error) {
            error.remove();
        }

        input.classList.remove("is-invalid");
    }


    function setMsg(el, type, text) {
        if (!el) {
            return;
        }

        el.classList.remove(
            "show",
            "pf-msg-success",
            "pf-msg-error"
        );

        if (!text) {
            return;
        }

        el.classList.add(
            "show",
            type === "error" ? "pf-msg-error" : "pf-msg-success"
        );

        el.textContent = text;
    }


    function setLoading(btn, active) {
        if (!btn) {
            return;
        }

        if (active) {
            btn.dataset.html = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML =
                '<i class="fa-solid fa-spinner fa-spin"></i> ' +
                (btn.getAttribute("data-loading") || "Processing...");
        } else {
            btn.disabled = false;
            if (btn.dataset.html) {
                btn.innerHTML = btn.dataset.html;
            }
        }
    }


    function applyPreferences(data) {
        if (!data) {
            return;
        }

        document.body.classList.toggle(
            "gx-compact",
            Boolean(data.compact_mode)
        );

        const noMotion =
            Boolean(data.reduced_motion) ||
            data.animations_enabled === false;

        document.body.classList.toggle(
            "gx-no-motion",
            noMotion
        );
    }


    async function postJSON(url, body) {

        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify(body)
        });

        if (response.status === 401 ||
            (response.redirected && response.url.indexOf("/login") !== -1)) {
            return { expired: true };
        }

        let data = {};

        try {
            data = await response.json();
        } catch (error) {
            data = {};
        }

        data.status = response.status;

        return data;
    }


    function handleExpired() {
        setMsg(
            profileMsg,
            "error",
            "Your session has expired. Redirecting to login..."
        );

        window.setTimeout(function () {
            window.location.href = "/login";
        }, 1200);
    }


    /* ======================================================
       Password Visibility Toggles
    ====================================================== */

    document.querySelectorAll(".pf-pw-toggle").forEach(function (btn) {

        btn.addEventListener("click", function () {

            const target = document.getElementById(
                btn.getAttribute("data-toggle-for")
            );

            if (!target) {
                return;
            }

            const show = target.getAttribute("type") === "password";

            target.setAttribute("type", show ? "text" : "password");

            const icon = btn.querySelector("i");

            if (icon) {
                icon.className = show
                    ? "fa-regular fa-eye-slash"
                    : "fa-regular fa-eye";
            }

            btn.setAttribute(
                "aria-label",
                show ? "Hide password" : "Show password"
            );
        });

    });


    /* ======================================================
       Password Strength Meter
    ====================================================== */

    function updateStrength(password) {

        if (!strengthBar || !strengthText) {
            return;
        }

        if (!password) {
            strengthBar.style.width = "0%";
            strengthText.textContent = "Password Strength";
            return;
        }

        let score = 0;

        if (password.length >= 12) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;

        const levels = [
            { max: 1, width: "20%", color: "#FF4D6D", label: "Very Weak" },
            { max: 2, width: "40%", color: "#FF8C42", label: "Weak" },
            { max: 3, width: "60%", color: "#FFC857", label: "Medium" },
            { max: 4, width: "80%", color: "#4CAF50", label: "Strong" },
            { max: 5, width: "100%", color: "#00E676", label: "Very Strong" }
        ];

        let matched = levels[levels.length - 1];

        for (const level of levels) {
            if (score <= level.max) {
                matched = level;
                break;
            }
        }

        strengthBar.style.width = matched.width;
        strengthBar.style.background = matched.color;
        strengthText.textContent = matched.label;
    }


    if (newPw) {
        newPw.addEventListener("input", function () {
            updateStrength(newPw.value);
            clearFieldError(newPw);
        });
    }


    /* ======================================================
       Personal Information Form
    ====================================================== */

    if (profileForm && profileSubmit) {

        const fullName = document.getElementById("pfFullName");
        const email = document.getElementById("pfEmail");
        const mobile = document.getElementById("pfMobile");

        profileForm.addEventListener("submit", async function (event) {

            event.preventDefault();

            setMsg(profileMsg, null, "");
            clearFieldError(fullName);
            clearFieldError(email);
            clearFieldError(mobile);

            setLoading(profileSubmit, true);

            const data = await postJSON(
                "/profile/update",
                {
                    full_name: fullName.value,
                    email: email.value,
                    mobile: mobile.value
                }
            );

            setLoading(profileSubmit, false);

            if (data.expired) {
                handleExpired();
                return;
            }

            if (data.status !== 200 || data.ok !== true) {
                setMsg(profileMsg, "error", data.error || "Unable to save your profile.");

                const errors = data.errors || {};

                if (errors.full_name) {
                    showFieldError(fullName, errors.full_name);
                }

                if (errors.email) {
                    showFieldError(email, errors.email);
                }

                if (errors.mobile) {
                    showFieldError(mobile, errors.mobile);
                }

                return;
            }

            setMsg(profileMsg, "success", data.message || "Profile updated successfully.");

            if (data.full_name) {
                fullName.value = data.full_name;
            }

            if (data.email !== undefined) {
                email.value = data.email;
            }

            if (data.mobile !== undefined) {
                mobile.value = data.mobile;
            }
        });

    }


    /* ======================================================
       Change Password Form
    ====================================================== */

    if (pwForm && pwSubmit) {

        const fields = [currentPw, newPw, confirmPw];

        fields.forEach(function (input) {
            if (input) {
                input.addEventListener("input", function () {
                    clearFieldError(input);
                });
            }
        });

        pwForm.addEventListener("submit", async function (event) {

            event.preventDefault();

            setMsg(pwMsg, null, "");

            fields.forEach(clearFieldError);

            if (newPw && confirmPw &&
                newPw.value !== confirmPw.value) {
                showFieldError(confirmPw, "Passwords do not match.");
                confirmPw.focus();
                return;
            }

            setLoading(pwSubmit, true);

            const data = await postJSON(
                "/profile/change-password",
                {
                    current_password: currentPw.value,
                    new_password: newPw.value,
                    confirm_password: confirmPw.value
                }
            );

            setLoading(pwSubmit, false);

            if (data.expired) {
                handleExpired();
                return;
            }

            if (data.status !== 200 || data.ok !== true) {
                setMsg(pwMsg, "error", data.error || "Unable to change your password.");

                const errors = data.errors || {};

                if (errors.current_password) {
                    showFieldError(currentPw, errors.current_password);
                }

                if (errors.new_password) {
                    showFieldError(newPw, errors.new_password);
                }

                if (errors.confirm_password) {
                    showFieldError(confirmPw, errors.confirm_password);
                }

                return;
            }

            setMsg(pwMsg, "success", data.message || "Password changed successfully.");

            pwForm.reset();
            updateStrength("");

            // Refresh account security status display.
            window.setTimeout(function () {
                window.location.reload();
            }, 1000);
        });

    }


    /* ======================================================
       Modal Reset
    ====================================================== */

    if (pwModalEl) {

        pwModalEl.addEventListener("hidden.bs.modal", function () {
            setMsg(pwMsg, null, "");
            pwForm.reset();
            updateStrength("");
            [currentPw, newPw, confirmPw].forEach(clearFieldError);
        });

    }


    /* ======================================================
       Apply Saved Preferences (compact / reduced motion)
    ====================================================== */

    const settingsEl = document.getElementById("pfSettingsData");

    if (settingsEl) {
        applyPreferences({
            compact_mode: settingsEl.getAttribute("data-compact") === "true",
            reduced_motion: settingsEl.getAttribute("data-reduced-motion") === "true",
            animations_enabled: settingsEl.getAttribute("data-animations") !== "false"
        });
    }

    });

})();
