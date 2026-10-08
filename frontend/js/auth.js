/* ============================================================
   CodeShield AI — Google sign-in header UI (vanilla JS)
   - On load, asks GET /api/v1/auth/me and renders either the
     "Sign in with Google" button or the signed-in user chip.
   - Sign-in is a plain redirect to /api/v1/auth/google/login;
     logout POSTs /api/v1/auth/logout and re-renders.
   ============================================================ */
"use strict";

(function () {
  const GOOGLE_G_LOGO =
    '<svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">' +
    '<path fill="#FFC107" d="M43.6 20.1H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3l5.7-5.7C34.3 6.1 29.4 4 24 4 13 4 4 13 4 24s9 20 20 20 20-9 20-20c0-1.3-.1-2.7-.4-3.9z"/>' +
    '<path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.9 1.2 8 3l5.7-5.7C34.3 6.1 29.4 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/>' +
    '<path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z"/>' +
    '<path fill="#1976D2" d="M43.6 20.1H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C36.9 39.2 44 34 44 24c0-1.3-.1-2.7-.4-3.9z"/>' +
    "</svg>";

  function escapeHtml(value) {
    return String(value === null || value === undefined ? "" : value).replace(
      /[&<>"']/g,
      (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  function renderSignedOut(area) {
    area.innerHTML =
      '<a href="/api/v1/auth/google/login" class="google-signin-btn">' +
      GOOGLE_G_LOGO +
      "<span>Sign in with Google</span>" +
      "</a>";
  }

  function renderSignedIn(area, user) {
    const name = escapeHtml(user.name || user.email || "Account");
    const picture = user.picture
      ? '<img src="' + escapeHtml(user.picture) + '" alt="" class="user-avatar" referrerpolicy="no-referrer">'
      : '<span class="user-avatar user-avatar-fallback" aria-hidden="true">👤</span>';
    area.innerHTML =
      '<span class="user-chip">' +
      picture +
      '<span class="user-name">' + name + "</span>" +
      '<button type="button" id="logout-btn" class="logout-btn" title="Sign out">Sign out</button>' +
      "</span>";
    const btn = document.getElementById("logout-btn");
    if (btn) {
      btn.addEventListener("click", async () => {
        try {
          await fetch("/api/v1/auth/logout", { method: "POST" });
        } catch (e) {
          /* ignore network errors; still re-render as signed out */
        }
        renderSignedOut(area);
      });
    }
  }

  async function init() {
    const area = document.getElementById("auth-area");
    if (!area) return;
    try {
      const res = await fetch("/api/v1/auth/me");
      if (res.ok) {
        const data = await res.json();
        if (data && data.user) {
          renderSignedIn(area, data.user);
          return;
        }
      }
    } catch (e) {
      /* backend unreachable or signed out — show the button */
    }
    renderSignedOut(area);

    // Surface OAuth failures (e.g. user denied consent) gently.
    const params = new URLSearchParams(window.location.search);
    if (params.get("auth") === "error") {
      params.delete("auth");
      const clean = window.location.pathname + (params.toString() ? "?" + params.toString() : "");
      window.history.replaceState(null, "", clean);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
