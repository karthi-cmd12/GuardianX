/**
 * GuardianX - Notification Center
 *
 * Powers two surfaces:
 *  1. The global bell dropdown (rendered once, shared sidebar, base.html)
 *  2. The full Notification Center page (templates/notifications.html)
 *
 * Clicking any alert marks it read via a POST and then navigates the user
 * to the alert's destination. All DOM building uses textContent to avoid
 * injecting untrusted content.
 */
(function () {
    "use strict";

    var UNREAD_LIMIT = 6;

    var pageState = {
        reload: null,
        loading: false
    };

    var currentFilter = { severity: "", type: "", read: "" };

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    function isLoggedOut(response) {
        return response.status === 401 ||
            (response.redirected && response.url.indexOf("/login") !== -1);
    }

    function handleLogout() {
        window.location.href = "/login";
    }

    function fetchJSON(url, options) {
        return fetch(url, options).then(function (response) {
            if (isLoggedOut(response)) {
                handleLogout();
                var err = new Error("session expired");
                err.__logout = true;
                throw err;
            }
            return response;
        });
    }

    function badgeEl() {
        return document.getElementById("gxNotifBadge");
    }

    function setBadge(count) {
        var badge = badgeEl();
        if (!badge) return;
        count = Math.max(0, parseInt(count, 10) || 0);
        badge.textContent = count > 99 ? "99+" : String(count);
        badge.hidden = count === 0;
    }

    function severityClass(severity) {
        return "gx-notif-" + String(severity || "INFO").toLowerCase();
    }

    function iconName(notification) {
        return notification.icon || "bell";
    }

    function buildItem(notification, options) {
        options = options || {};

        var a = document.createElement("a");
        a.href = notification.destination || "/dashboard";
        a.className = "gx-notif-item";
        a.setAttribute("data-id", notification.id);
        a.setAttribute("role", "link");
        a.title = "Open: " + (notification.title || "Notification");
        a.classList.add(notification.is_read ? "is-read" : "is-unread");

        var icon = document.createElement("span");
        icon.className = "gx-notif-item-icon " + severityClass(notification.severity);
        var i = document.createElement("i");
        i.className = "fa-solid fa-" + iconName(notification);
        icon.appendChild(i);
        a.appendChild(icon);

        var body = document.createElement("span");
        body.className = "gx-notif-item-body";

        var title = document.createElement("strong");
        title.textContent = notification.title || "Alert";
        body.appendChild(title);

        var msg = document.createElement("span");
        msg.className = "gx-notif-item-msg";
        msg.textContent = notification.message || "";
        body.appendChild(msg);

        var meta = document.createElement("span");
        meta.className = "gx-notif-item-meta";
        var time = document.createElement("time");
        time.textContent = notification.time_ago || "";
        var type = document.createElement("span");
        type.textContent = notification.type_label || "Alert";
        meta.appendChild(time);
        meta.appendChild(type);
        body.appendChild(meta);

        a.appendChild(body);

        var dot = document.createElement("span");
        dot.className = "gx-notif-item-dot";
        a.appendChild(dot);

        if (options.allowDelete) {
            var del = document.createElement("button");
            del.type = "button";
            del.className = "gx-notif-item-delete";
            del.title = "Delete notification";
            del.setAttribute("aria-label", "Delete notification");
            var di = document.createElement("i");
            di.className = "fa-solid fa-trash";
            del.appendChild(di);
            del.addEventListener("click", function (e) {
                e.preventDefault();
                e.stopPropagation();
                deleteNotification(notification.id);
            });
            a.appendChild(del);
        }

        a.addEventListener("click", function (e) {
            e.preventDefault();
            openNotification(notification);
        });

        return a;
    }

    /**
     * Mark a notification read and navigate to its destination.
     * If the server call fails (deleted/invalid/offline) we still navigate
     * to the stored destination so the user is never stuck.
     */
    function openNotification(notification) {
        var fallback = notification.destination || "/dashboard";

        fetchJSON("/notifications/" + encodeURIComponent(notification.id) + "/read", {
            method: "POST",
            headers: { "Accept": "application/json" }
        }).then(function (response) {
            if (!response.ok) throw new Error("read failed");
            return response.json();
        }).then(function (data) {
            if (data && typeof data.unread_count === "number") {
                setBadge(data.unread_count);
            }
            window.location.href = (data && data.destination) || fallback;
        }).catch(function (err) {
            if (err && err.__logout) return;
            window.location.href = fallback;
        });
    }

    function deleteNotification(id) {
        fetchJSON("/notifications/" + encodeURIComponent(id) + "/delete", {
            method: "POST",
            headers: { "Accept": "application/json" }
        }).then(function (response) {
            if (!response.ok) throw new Error("delete failed");
            return response.json();
        }).then(function (data) {
            if (data && typeof data.unread_count === "number") {
                setBadge(data.unread_count);
            }
            if (pageState.reload) {
                pageState.reload();
            }
        }).catch(function (err) {
            if (err && err.__logout) return;
        });
    }

    function timeAgoFallback(isoString) {
        if (!isoString) return "";
        var then = new Date(isoString);
        if (isNaN(then.getTime())) return "";
        var seconds = Math.floor((Date.now() - then.getTime()) / 1000);
        if (seconds < 60) return "just now";
        var minutes = Math.floor(seconds / 60);
        if (minutes < 60) return minutes + "m ago";
        var hours = Math.floor(minutes / 60);
        if (hours < 24) return hours + "h ago";
        var days = Math.floor(hours / 24);
        if (days < 30) return days + "d ago";
        return then.toLocaleDateString();
    }

    /* ------------------------------------------------------------------ */
    /* Bell + dropdown (shared sidebar)                                    */
    /* ------------------------------------------------------------------ */

    function initBell() {
        var btn = document.getElementById("gxNotifBtn");
        var panel = document.getElementById("gxNotifPanel");
        if (!btn || !panel) return;

        var loaded = false;

        function open() {
            panel.hidden = false;
            btn.setAttribute("aria-expanded", "true");
            if (!loaded) {
                loaded = true;
                renderPanel();
            }
        }

        function close() {
            panel.hidden = true;
            btn.setAttribute("aria-expanded", "false");
        }

        function toggle() {
            if (panel.hidden) open();
            else close();
        }

        btn.addEventListener("click", function (e) {
            e.stopPropagation();
            toggle();
        });

        document.addEventListener("click", function (e) {
            var wrap = document.getElementById("gxNotif");
            if (wrap && !wrap.contains(e.target)) close();
        });

        document.addEventListener("keydown", function (e) {
            if (e.key === "Escape") close();
        });

        var markAll = document.getElementById("gxNotifMarkAllBtn");
        if (markAll) {
            markAll.addEventListener("click", function (e) {
                e.stopPropagation();
                markAllRead().then(function () {
                    loaded = false;
                    renderPanel();
                });
            });
        }

        refreshBadge();
    }

    function refreshBadge() {
        fetchJSON("/notifications/data?limit=1").then(function (response) {
            if (!response.ok) return null;
            return response.json();
        }).then(function (data) {
            if (data && typeof data.unread_count === "number") {
                setBadge(data.unread_count);
            }
        }).catch(function (err) {
            if (err && err.__logout) return;
        });
    }

    function renderPanel() {
        var list = document.getElementById("gxNotifList");
        if (!list) return;

        fetchJSON("/notifications/data?limit=" + UNREAD_LIMIT).then(function (response) {
            if (!response.ok) throw new Error("panel failed");
            return response.json();
        }).then(function (data) {
            var empty = document.getElementById("gxNotifEmpty");
            var subtitle = document.getElementById("gxNotifSubtitle");
            var items = (data && data.items) || [];

            setBadge(data.unread_count);

            if (subtitle) {
                subtitle.textContent = data.unread_count > 0
                    ? data.unread_count + " unread alert" + (data.unread_count === 1 ? "" : "s")
                    : "No new alerts";
            }

            list.innerHTML = "";
            items.forEach(function (n) {
                n.time_ago = timeAgoFallback(n.created_at);
                list.appendChild(buildItem(n));
            });

            if (empty) empty.hidden = items.length > 0;
        }).catch(function (err) {
            if (err && err.__logout) return;
        });
    }

    function markAllRead() {
        return fetchJSON("/notifications/read-all", {
            method: "POST",
            headers: { "Accept": "application/json" }
        }).then(function (response) {
            if (!response.ok) throw new Error("mark all failed");
            setBadge(0);
        }).catch(function (err) {
            if (err && err.__logout) throw err;
        });
    }

    /* ------------------------------------------------------------------ */
    /* Notification Center page                                            */
    /* ------------------------------------------------------------------ */

    function initPage() {
        var listEl = document.getElementById("ntList");
        if (!listEl) return;

        var severity = document.getElementById("ntSeverity");
        var type = document.getElementById("ntType");
        var read = document.getElementById("ntRead");
        var loading = document.getElementById("ntLoading");
        var errorBox = document.getElementById("ntError");
        var errorMsg = document.getElementById("ntErrorMessage");

        function showError(message) {
            if (errorMsg) errorMsg.textContent = message || "Something went wrong.";
            if (errorBox) errorBox.classList.remove("d-none");
        }

        function hideError() {
            if (errorBox) errorBox.classList.add("d-none");
        }

        function setLoading(isLoading) {
            pageState.loading = isLoading;
            if (loading) loading.classList.toggle("d-none", !isLoading);
        }

        function load() {
            setLoading(true);
            hideError();

            var qs = [];
            if (currentFilter.severity) qs.push("severity=" + encodeURIComponent(currentFilter.severity));
            if (currentFilter.type) qs.push("type=" + encodeURIComponent(currentFilter.type));
            if (currentFilter.read) qs.push("read=" + encodeURIComponent(currentFilter.read));
            var url = "/notifications/data" + (qs.length ? "?" + qs.join("&") : "");

            fetchJSON(url).then(function (response) {
                if (!response.ok) throw new Error("load failed");
                return response.json();
            }).then(function (data) {
                renderPage(data);
                setLoading(false);
            }).catch(function (err) {
                setLoading(false);
                if (err && err.__logout) return;
                showError("Could not load notifications. Please try again.");
            });
        }

        function renderPage(data) {
            var items = (data && data.items) || [];

            setBadge(data.unread_count);

            var statTotal = document.getElementById("ntStatTotal");
            var statUnread = document.getElementById("ntStatUnread");
            var statHigh = document.getElementById("ntStatHigh");
            var statCritical = document.getElementById("ntStatCritical");
            if (statTotal) { statTotal.textContent = data.total; statTotal.setAttribute("data-count", data.total); }
            if (statUnread) { statUnread.textContent = data.unread_count; statUnread.setAttribute("data-count", data.unread_count); }
            if (statHigh) { statHigh.textContent = data.high_count; statHigh.setAttribute("data-count", data.high_count); }
            if (statCritical) { statCritical.textContent = data.critical_count; statCritical.setAttribute("data-count", data.critical_count); }

            var badge = document.getElementById("ntCountBadge");
            if (badge) badge.textContent = items.length + " alert" + (items.length === 1 ? "" : "s");

            var meta = document.getElementById("ntResultMeta");
            if (meta) {
                meta.textContent = data.total > 0
                    ? "Showing " + items.length + " of " + data.total + " alert" + (data.total === 1 ? "" : "s")
                    : "No alerts yet.";
            }

            listEl.innerHTML = "";
            items.forEach(function (n) {
                n.time_ago = timeAgoFallback(n.created_at);
                listEl.appendChild(buildItem(n, { allowDelete: true }));
            });

            var empty = document.getElementById("ntEmpty");
            if (empty) {
                var hasFilter = currentFilter.severity || currentFilter.type || currentFilter.read;
                empty.hidden = items.length > 0;
                document.getElementById("ntEmptyTitle").textContent =
                    items.length === 0 && data.total > 0
                        ? "No matching alerts"
                        : "No alerts yet";
                document.getElementById("ntEmptyText").textContent =
                    items.length === 0 && data.total > 0
                        ? "Try clearing the filters to see all of your alerts."
                        : "Security alerts will appear here automatically when a scan finds something suspicious.";
            }
        }

        function reload() {
            load();
        }

        pageState.reload = reload;

        function wireSelect(select) {
            if (!select) return;
            select.addEventListener("change", function () {
                currentFilter.severity = severity ? severity.value : "";
                currentFilter.type = type ? type.value : "";
                currentFilter.read = read ? read.value : "";
                load();
            });
        }

        wireSelect(severity);
        wireSelect(type);
        wireSelect(read);

        var clearFilters = document.getElementById("ntClearFiltersBtn");
        if (clearFilters) {
            clearFilters.addEventListener("click", function () {
                if (severity) severity.value = "";
                if (type) type.value = "";
                if (read) read.value = "";
                currentFilter = { severity: "", type: "", read: "" };
                load();
            });
        }

        var refresh = document.getElementById("ntRefreshBtn");
        if (refresh) {
            refresh.addEventListener("click", load);
        }

        var markAllBtn = document.getElementById("ntMarkAllBtn");
        if (markAllBtn) {
            markAllBtn.addEventListener("click", function () {
                markAllRead().then(load);
            });
        }

        var clearAllBtn = document.getElementById("ntClearAllBtn");
        if (clearAllBtn) {
            clearAllBtn.addEventListener("click", function () {
                fetchJSON("/notifications/clear", {
                    method: "POST",
                    headers: { "Accept": "application/json" }
                }).then(function (response) {
                    if (!response.ok) throw new Error("clear failed");
                    setBadge(0);
                    load();
                }).catch(function (err) {
                    if (err && err.__logout) return;
                    showError("Could not clear notifications. Please try again.");
                });
            });
        }

        load();
    }

    /* ------------------------------------------------------------------ */
    /* Boot                                                                */
    /* ------------------------------------------------------------------ */

    document.addEventListener("DOMContentLoaded", function () {
        initBell();
        initPage();
    });
})();
