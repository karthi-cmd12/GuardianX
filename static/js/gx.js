// ==========================================================
// GuardianX Global Shell JavaScript (gx.js)
// Sidebar drawer, mobile overlay, page loader.
// ==========================================================

(function () {

    "use strict";


    // ==========================================================
    // Mobile Sidebar Drawer
    // ==========================================================

    function initDrawer() {

        const hamburger = document.querySelector(".gx-hamburger");
        const overlay = document.querySelector(".gx-overlay");
        const navLinks = document.querySelectorAll(".gx-sidebar .gx-menu-item a[href]");


        function open() {
            document.body.classList.add("sidebar-open");
        }


        function close() {
            document.body.classList.remove("sidebar-open");
        }


        if (hamburger) {
            hamburger.addEventListener("click", function () {
                document.body.classList.toggle("sidebar-open");
            });
        }


        if (overlay) {
            overlay.addEventListener("click", close);
        }


        navLinks.forEach(function (link) {
            link.addEventListener("click", close);
        });


        document.addEventListener("keydown", function (e) {
            if (e.key === "Escape") {
                close();
            }
        });

    }


    // ==========================================================
    // Page Loader
    // ==========================================================

    function initLoader() {

        window.addEventListener("load", function () {

            const loader = document.querySelector(".gx-loader");

            if (loader) {
                loader.classList.add("done");
            }

        });

    }


    // ==========================================================
    // Sidebar Collapse Toggle (desktop)
    // ==========================================================

    function initCollapse() {

        const btn = document.getElementById("sidebarCollapseBtn");

        if (!btn) {
            return;
        }

        const icon = btn.querySelector("i");

        function applyState() {

            const collapsed = document.body.classList.contains("gx-sidebar-collapsed");

            if (icon) {

                if (collapsed) {

                    icon.className = "fa-solid fa-angles-right";

                    btn.setAttribute("aria-label", "Expand sidebar");

                    btn.title = "Expand sidebar";

                } else {

                    icon.className = "fa-solid fa-angles-left";

                    btn.setAttribute("aria-label", "Collapse sidebar");

                    btn.title = "Collapse sidebar";

                }

            }

        }

        btn.addEventListener("click", function () {

            document.body.classList.toggle("gx-sidebar-collapsed");

            applyState();

        });

        applyState();

    }


    // ==========================================================
    // Init
    // ==========================================================

    document.addEventListener("DOMContentLoaded", function () {
        initDrawer();
        initCollapse();
        initLoader();
    });

})();
