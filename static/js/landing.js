// ==========================================================
// GuardianX Premium Landing (landing.js)
// Navbar state, mobile menu, scroll-reveal.
// Lightweight: no animation libraries.
// ==========================================================

(function () {
    "use strict";

    var prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // ==========================================================
    // Navbar scroll state
    // ==========================================================

    function initNavState() {
        var nav = document.getElementById("ldNav");
        if (!nav) return;

        var onScroll = function () {
            nav.classList.toggle("scrolled", window.scrollY > 24);
        };

        onScroll();
        window.addEventListener("scroll", onScroll, { passive: true });
    }

    // ==========================================================
    // Mobile menu
    // ==========================================================

    function initMobileMenu() {
        var hamburger = document.getElementById("ldHamburger");
        var collapse = document.getElementById("ldNavCollapse");
        if (!hamburger || !collapse) return;

        var setOpen = function (open) {
            collapse.classList.toggle("open", open);
            hamburger.setAttribute("aria-expanded", open ? "true" : "false");
            var icon = hamburger.querySelector("i");
            if (icon) {
                icon.className = open ? "fa-solid fa-xmark" : "fa-solid fa-bars";
            }
        };

        hamburger.addEventListener("click", function () {
            setOpen(!collapse.classList.contains("open"));
        });

        collapse.querySelectorAll("a").forEach(function (link) {
            link.addEventListener("click", function () {
                setOpen(false);
            });
        });

        document.addEventListener("click", function (e) {
            if (!collapse.contains(e.target) && !hamburger.contains(e.target)) {
                setOpen(false);
            }
        });

        document.addEventListener("keydown", function (e) {
            if (e.key === "Escape") setOpen(false);
        });
    }

    // ==========================================================
    // Scroll reveal (staggered per grid)
    // ==========================================================

    function initReveal() {
        var els = document.querySelectorAll(".ld-reveal");
        if (!els.length) return;

        if (prefersReduced || !("IntersectionObserver" in window)) {
            els.forEach(function (el) { el.classList.add("in-view"); });
            return;
        }

        var observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (!entry.isIntersecting) return;
                var el = entry.target;
                el.classList.add("in-view");
                observer.unobserve(el);
            });
        }, { threshold: 0.12, rootMargin: "0px 0px -8% 0px" });

        els.forEach(function (el) {
            observer.observe(el);
        });
    }

    // ==========================================================
    // Stagger siblings inside feature/step grids
    // ==========================================================

    function initStagger() {
        document.querySelectorAll(".ld-feature-grid, .ld-steps").forEach(function (grid) {
            Array.prototype.forEach.call(grid.children, function (child, index) {
                child.style.transitionDelay = (index % 3) * 0.08 + "s";
            });
        });
    }

    // ==========================================================
    // Init
    // ==========================================================

    document.addEventListener("DOMContentLoaded", function () {
        initNavState();
        initMobileMenu();
        initStagger();
        initReveal();
    });

})();
