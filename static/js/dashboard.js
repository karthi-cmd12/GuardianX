/* ==========================================================
   GuardianX Dashboard 2.0 - Security Command Center JS
   Animates real server-rendered values only (no fake data).
   Also wires notification clicks to the existing mark-read +
   navigate flow (reuses the notification service API).
   ========================================================== */

(function () {
    "use strict";

    function prefersReducedMotion() {
        return window.matchMedia &&
            window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    }

    /* ======================================================
       Time-Based Greeting
    ====================================================== */

    function initGreeting() {
        var greeting = document.getElementById("greeting");

        if (!greeting) {
            return;
        }

        var hour = new Date().getHours();

        var text = "Good evening";

        if (hour >= 5 && hour < 12) {
            text = "Good morning";
        } else if (hour >= 12 && hour < 17) {
            text = "Good afternoon";
        }

        greeting.textContent = text;
    }

    /* ======================================================
       Statistic Counters
       Animates the real values rendered by the server.
    ====================================================== */

    function initCounters() {
        var counters = document.querySelectorAll(
            ".cmd-card-value[data-count]"
        );

        if (prefersReducedMotion()) {
            return;
        }

        counters.forEach(function (counter) {
            var target = parseInt(
                counter.getAttribute("data-count"),
                10
            );

            if (isNaN(target) || target <= 0) {
                return;
            }

            var count = 0;
            var duration = 800;
            var start = performance.now();

            function tick(now) {
                var progress = Math.min((now - start) / duration, 1);
                var eased = 1 - Math.pow(1 - progress, 3);

                count = Math.round(target * eased);
                counter.textContent = count;

                if (progress < 1) {
                    requestAnimationFrame(tick);
                } else {
                    counter.textContent = target;
                }
            }

            requestAnimationFrame(tick);
        });
    }

    /* ======================================================
       Security Score
       Animates the real score into the score ring value.
    ====================================================== */

    function initScore() {
        var ring = document.querySelector(".cmd-score-ring");

        if (!ring) {
            return;
        }

        var score = parseInt(
            ring.getAttribute("data-score"),
            10
        );

        var valueEl = document.getElementById("cmdScoreValue");

        if (isNaN(score) || !valueEl) {
            return;
        }

        if (prefersReducedMotion()) {
            valueEl.textContent = score;
            return;
        }

        var count = 0;
        var duration = 1100;
        var start = performance.now();

        function tickScore(now) {
            var progress = Math.min((now - start) / duration, 1);
            var eased = 1 - Math.pow(1 - progress, 3);

            count = Math.round(score * eased);
            valueEl.textContent = count;

            if (progress < 1) {
                requestAnimationFrame(tickScore);
            } else {
                valueEl.textContent = score;
            }
        }

        requestAnimationFrame(tickScore);
    }

    /* ======================================================
       Notifications
       Clicking an alert marks it read (existing API) and then
       navigates to its destination - same behaviour as the
       global notification center.
    ====================================================== */

    function openNotification(notificationId, fallbackHref) {
        var url = "/notifications/" +
            encodeURIComponent(notificationId) +
            "/read";

        fetch(url, {
            method: "POST",
            headers: { "Accept": "application/json" }
        }).then(function (response) {
            if (!response.ok) {
                throw new Error("read failed");
            }
            return response.json();
        }).then(function (data) {
            window.location.href = (data && data.destination) || fallbackHref;
        }).catch(function () {
            window.location.href = fallbackHref;
        });
    }

    function initNotifications() {
        var items = document.querySelectorAll(".cmd-notif-item");

        items.forEach(function (item) {
            item.addEventListener("click", function (event) {
                var notificationId = item.getAttribute("data-notif-id");
                var fallbackHref = item.getAttribute("href") || "/dashboard";

                if (!notificationId) {
                    return;
                }

                event.preventDefault();
                openNotification(notificationId, fallbackHref);
            });
        });
    }

    /* ======================================================
       Init
    ====================================================== */

    document.addEventListener("DOMContentLoaded", function () {
        initGreeting();
        initCounters();
        initScore();
        initNotifications();
    });

})();
