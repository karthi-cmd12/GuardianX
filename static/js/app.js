// ======================================
// GuardianX Main JavaScript
// ======================================

document.addEventListener("DOMContentLoaded", function () {

    // ======================================
    // Sidebar Dropdown
    // ======================================

    const dropdown = document.querySelector(".gx-dropdown");

    if (dropdown) {

        const mainLink = dropdown.querySelector(":scope > a");

        const submenu = dropdown.querySelector(".gx-submenu");

        const arrow = dropdown.querySelector(".gx-arrow");

        if (mainLink && submenu) {

            mainLink.addEventListener("click", function (e) {

                e.preventDefault();

                submenu.classList.toggle("show");

                if (arrow) {

                    arrow.classList.toggle("rotate");

                }

            });

        }

    }

});
