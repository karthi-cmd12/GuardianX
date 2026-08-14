// ==========================================================
// GuardianX Login & Register JavaScript
// ==========================================================

document.addEventListener("DOMContentLoaded", function () {

    // ======================================================
    // Show / Hide Password
    // ======================================================

    const togglePassword = document.getElementById("togglePassword");
    const passwordInput = document.getElementById("password");

    if (togglePassword && passwordInput) {

        togglePassword.addEventListener("click", function () {

            const type =
                passwordInput.getAttribute("type") === "password"
                    ? "text"
                    : "password";

            passwordInput.setAttribute("type", type);

            const icon = this.querySelector("i");

            if (type === "password") {

                icon.classList.remove("fa-eye-slash");
                icon.classList.add("fa-eye");

            } else {

                icon.classList.remove("fa-eye");
                icon.classList.add("fa-eye-slash");

            }

        });

    }

    // ======================================================
    // Password Strength Meter
    // ======================================================

    const strengthBar = document.getElementById("passwordStrength");
    const strengthText = document.getElementById("strengthText");

    if (passwordInput && strengthBar && strengthText) {

        passwordInput.addEventListener("keyup", function () {

            const password = passwordInput.value;

            let score = 0;

            if (password.length >= 8) score++;
            if (/[A-Z]/.test(password)) score++;
            if (/[a-z]/.test(password)) score++;
            if (/[0-9]/.test(password)) score++;
            if (/[^A-Za-z0-9]/.test(password)) score++;

            switch (score) {

                case 0:
                case 1:
                    strengthBar.style.width = "20%";
                    strengthBar.style.background = "#FF4D6D";
                    strengthText.innerText = "Very Weak";
                    break;

                case 2:
                    strengthBar.style.width = "40%";
                    strengthBar.style.background = "#FF8C42";
                    strengthText.innerText = "Weak";
                    break;

                case 3:
                    strengthBar.style.width = "60%";
                    strengthBar.style.background = "#FFC857";
                    strengthText.innerText = "Medium";
                    break;

                case 4:
                    strengthBar.style.width = "80%";
                    strengthBar.style.background = "#4CAF50";
                    strengthText.innerText = "Strong";
                    break;

                case 5:
                    strengthBar.style.width = "100%";
                    strengthBar.style.background = "#00E676";
                    strengthText.innerText = "Very Strong";
                    break;

            }

            if (password.length === 0) {

                strengthBar.style.width = "0%";
                strengthText.innerText = "Password Strength";

            }

        });

    }

    // ======================================================
    // Confirm Password Validation (inline, no alerts)
    // ======================================================

    function showFieldError(input, message) {

        let error = input.parentElement.querySelector(".gx-form-error");

        if (!error) {

            error = document.createElement("small");

            error.className = "gx-form-error";

            input.parentElement.appendChild(error);

        }

        error.textContent = message;

        input.classList.add("is-invalid");

    }

    function clearFieldError(input) {

        const error = input.parentElement.querySelector(".gx-form-error");

        if (error) {
            error.remove();
        }

        input.classList.remove("is-invalid");

    }

    const registerForm = document.getElementById("registerForm");

    if (registerForm) {

        const confirmPassword =
            registerForm.querySelector("input[name='confirm_password']");

        registerForm.addEventListener("submit", function (event) {

            if (passwordInput && confirmPassword) {

                if (passwordInput.value !== confirmPassword.value) {

                    event.preventDefault();

                    showFieldError(
                        confirmPassword,
                        "Passwords do not match."
                    );

                    confirmPassword.focus();

                } else {

                    clearFieldError(confirmPassword);

                }

            }

        });

        if (confirmPassword) {

            confirmPassword.addEventListener("input", function () {

                clearFieldError(confirmPassword);

            });

        }

    }

    // ======================================================
    // Submit Loading State
    // ======================================================

    function bindLoading(formId, buttonId) {

        const form = document.getElementById(formId);

        const button = document.getElementById(buttonId);

        if (!form || !button) {
            return;
        }

        const originalHtml = button.innerHTML;

        form.addEventListener("submit", function (event) {

            if (!form.checkValidity()) {
                return;
            }

            button.disabled = true;

            button.innerHTML =
                '<i class="fa-solid fa-spinner fa-spin"></i> ' +
                button.getAttribute("data-loading") || "Processing...";

        });

        // Restore the button if the page stays (server-side errors).
        window.addEventListener("pageshow", function () {

            button.disabled = false;

            button.innerHTML = originalHtml;

        });

    }

    bindLoading("loginForm", "loginSubmitBtn");

    bindLoading("registerForm", "registerSubmitBtn");

});
