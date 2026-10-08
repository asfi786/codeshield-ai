/* ============================================================
   CodeShield AI — authentication UI (vanilla JS)
   - Injects the Sign-in / Register modal (shared by every page).
   - Header shows "Sign in" button or the user chip (avatar + logout).
   - On the home page, the analyzer form is gated: logged-out
     visitors see a locked panel with a sign-in CTA instead.
   Exposes: window.CodeShieldAuth.refresh() / .openModal()
   ============================================================ */
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);

  const GOOGLE_G_LOGO =
    '<svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">' +
    '<path fill="#FFC107" d="M43.6 20.1H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3l5.7-5.7C34.3 6.1 29.4 4 24 4 13 4 4 13 4 24s9 20 20 20 20-9 20-20c0-1.3-.1-2.7-.4-3.9z"/>' +
    '<path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.9 1.2 8 3l5.7-5.7C34.3 6.1 29.4 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/>' +
    '<path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z"/>' +
    '<path fill="#1976D2" d="M43.6 20.1H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C36.9 39.2 44 34 44 24c0-1.3-.1-2.7-.4-3.9z"/>' +
    "</svg>";

  const MODAL_HTML =
    '<div id="auth-modal" class="modal-backdrop hidden" role="dialog" aria-modal="true" aria-labelledby="auth-modal-title">' +
    '<div class="glass modal-card">' +
    '<button id="auth-modal-close" type="button" class="modal-close" aria-label="Close">✕</button>' +
    '<h2 id="auth-modal-title" class="text-2xl font-bold text-center">Welcome</h2>' +
    '<p class="text-slate-400 text-sm text-center mt-1">Sign in to analyze GitHub repositories.</p>' +
    '<div class="auth-tabs" role="tablist">' +
    '<button type="button" id="tab-signin" class="auth-tab active" role="tab">Sign in</button>' +
    '<button type="button" id="tab-register" class="auth-tab" role="tab">Create account</button>' +
    "</div>" +
    '<a href="/api/v1/auth/google/login" class="google-signin-btn google-signin-btn-block">' +
    GOOGLE_G_LOGO + "<span>Continue with Google</span></a>" +
    '<div class="auth-divider"><span>or</span></div>' +
    '<form id="signin-form" novalidate>' +
    '<label class="auth-label">Email' +
    '<input id="signin-email" type="email" class="input-glass w-full mt-1" autocomplete="email" placeholder="you@example.com" /></label>' +
    '<label class="auth-label">Password' +
    '<input id="signin-password" type="password" class="input-glass w-full mt-1" autocomplete="current-password" placeholder="••••••••" /></label>' +
    '<p id="signin-error" class="hidden text-sm text-red-400 mt-2" role="alert"></p>' +
    '<button type="submit" class="btn-primary w-full mt-4">Sign in</button>' +
    "</form>" +
    '<form id="register-form" class="hidden" novalidate>' +
    '<label class="auth-label">Name' +
    '<input id="register-name" type="text" class="input-glass w-full mt-1" autocomplete="name" placeholder="Your name" /></label>' +
    '<label class="auth-label">Email' +
    '<input id="register-email" type="email" class="input-glass w-full mt-1" autocomplete="email" placeholder="you@example.com" /></label>' +
    '<label class="auth-label">Password <span class="text-slate-500 font-normal">(min 8 characters)</span>' +
    '<input id="register-password" type="password" class="input-glass w-full mt-1" autocomplete="new-password" placeholder="••••••••" /></label>' +
    '<p id="register-error" class="hidden text-sm text-red-400 mt-2" role="alert"></p>' +
    '<button type="submit" class="btn-primary w-full mt-4">Create free account</button>' +
    "</form>" +
    "</div></div>";

  let currentUser = null;

  /* ---------------- modal ---------------- */

  function ensureModal() {
    if (!$("auth-modal")) {
      document.body.insertAdjacentHTML("beforeend", MODAL_HTML);
      wireModal();
    }
  }

  function openModal(tab) {
    ensureModal();
    setTab(tab === "register" ? "register" : "signin");
    $("auth-modal").classList.remove("hidden");
    document.body.style.overflow = "hidden";
  }

  function closeModal() {
    const modal = $("auth-modal");
    if (!modal) return;
    modal.classList.add("hidden");
    document.body.style.overflow = "";
  }

  function setTab(which) {
    const signin = which === "signin";
    $("tab-signin").classList.toggle("active", signin);
    $("tab-register").classList.toggle("active", !signin);
    $("signin-form").classList.toggle("hidden", !signin);
    $("register-form").classList.toggle("hidden", signin);
    hideError("signin-error");
    hideError("register-error");
  }

  function showError(id, message) {
    const el = $(id);
    if (!el) return;
    el.textContent = message;
    el.classList.remove("hidden");
  }

  function hideError(id) {
    const el = $(id);
    if (!el) return;
    el.classList.add("hidden");
    el.textContent = "";
  }

  function wireModal() {
    $("auth-modal-close").addEventListener("click", closeModal);
    $("auth-modal").addEventListener("click", (e) => {
      if (e.target.id === "auth-modal") closeModal();
    });
    document.addEventListener("keydown", (e) => {
      const modal = $("auth-modal");
      if (e.key === "Escape" && modal && !modal.classList.contains("hidden")) closeModal();
    });
    $("tab-signin").addEventListener("click", () => setTab("signin"));
    $("tab-register").addEventListener("click", () => setTab("register"));

    $("signin-form").addEventListener("submit", (e) => {
      e.preventDefault();
      const email = $("signin-email").value.trim();
      const password = $("signin-password").value;
      if (!email || !password) {
        showError("signin-error", "Please enter your email and password.");
        return;
      }
      submitJson("/api/v1/auth/login", { email, password }, "signin-error", e.target.querySelector("button[type=submit]"));
    });

    $("register-form").addEventListener("submit", (e) => {
      e.preventDefault();
      const name = $("register-name").value.trim();
      const email = $("register-email").value.trim();
      const password = $("register-password").value;
      if (!name) {
        showError("register-error", "Please enter your name.");
        return;
      }
      if (!email || email.indexOf("@") < 0) {
        showError("register-error", "Please enter a valid email address.");
        return;
      }
      if (password.length < 8) {
        showError("register-error", "Password must be at least 8 characters.");
        return;
      }
      submitJson("/api/v1/auth/register", { name, email, password }, "register-error", e.target.querySelector("button[type=submit]"));
    });
  }

  /* ---------------- header + gating ---------------- */

  function escapeHtml(value) {
    return String(value === null || value === undefined ? "" : value).replace(
      /[&<>"']/g,
      (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  function renderAuth() {
    const area = $("auth-area");
    const form = $("analyze-form");
    const locked = $("auth-required-panel");
    if (!area) return;

    if (currentUser) {
      const name = escapeHtml(currentUser.name || currentUser.email || "Account");
      const picture = currentUser.picture
        ? '<img src="' + escapeHtml(currentUser.picture) + '" alt="" class="user-avatar" referrerpolicy="no-referrer">'
        : '<span class="user-avatar user-avatar-fallback" aria-hidden="true">👤</span>';
      area.innerHTML =
        '<span class="user-chip">' + picture +
        '<span class="user-name">' + name + "</span>" +
        '<button type="button" id="logout-btn" class="logout-btn" title="Sign out">Sign out</button></span>';
      const btn = $("logout-btn");
      if (btn) btn.addEventListener("click", logout);
      if (form) form.classList.remove("hidden");
      if (locked) locked.classList.add("hidden");
    } else {
      area.innerHTML =
        '<button type="button" id="header-signin-btn" class="google-signin-btn">' +
        "<span>Sign in</span></button>";
      const btn = $("header-signin-btn");
      if (btn) btn.addEventListener("click", () => openModal("signin"));
      if (form) form.classList.add("hidden");
      if (locked) locked.classList.remove("hidden");
    }
  }

  async function refresh() {
    try {
      const res = await fetch("/api/v1/auth/me");
      if (res.ok) {
        const data = await res.json();
        currentUser = data && data.user ? data.user : null;
      } else {
        currentUser = null;
      }
    } catch (e) {
      currentUser = null;
    }
    renderAuth();

    try {
      const params = new URLSearchParams(window.location.search);
      if (params.get("auth") === "error") {
        params.delete("auth");
        const clean = window.location.pathname + (params.toString() ? "?" + params.toString() : "");
        window.history.replaceState(null, "", clean);
      }
    } catch (e) {
      /* ignore */
    }
  }

  async function logout() {
    try {
      await fetch("/api/v1/auth/logout", { method: "POST" });
    } catch (e) {
      /* ignore; still render signed out */
    }
    currentUser = null;
    renderAuth();
  }

  async function submitJson(url, body, errorId, submitBtn) {
    hideError(errorId);
    submitBtn.disabled = true;
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showError(errorId, data.detail || "Something went wrong. Please try again.");
        return;
      }
      currentUser = data.user || null;
      closeModal();
      renderAuth();
    } catch (e) {
      showError(errorId, "Network error. Please check your connection and try again.");
    } finally {
      submitBtn.disabled = false;
    }
  }

  /* ---------------- init ---------------- */

  function init() {
    const ctaSignin = $("cta-signin-btn");
    if (ctaSignin) ctaSignin.addEventListener("click", () => openModal("signin"));
    const ctaRegister = $("cta-register-btn");
    if (ctaRegister) ctaRegister.addEventListener("click", () => openModal("register"));
    refresh();
  }

  window.CodeShieldAuth = { refresh, openModal };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
