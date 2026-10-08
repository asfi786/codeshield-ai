/* ============================================================
   CodeShield AI — authentication UI (vanilla JS)
   - Sign-in / Register modal with tabs + Continue with Google.
   - Header shows "Sign in" button or the user chip (avatar + logout).
   - The analyzer form is gated: logged-out visitors see a locked
     panel with a sign-in CTA instead.
   Exposes: window.CodeShieldAuth.refresh()
   ============================================================ */
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);

  let currentUser = null;

  /* ---------------- modal ---------------- */

  function openModal(tab) {
    const modal = $("auth-modal");
    if (!modal) return;
    setTab(tab === "register" ? "register" : "signin");
    modal.classList.remove("hidden");
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

    // Surface OAuth failures (e.g. user denied consent) gently.
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

  /* ---------------- wiring ---------------- */

  function init() {
    const modal = $("auth-modal");
    if (modal) {
      $("auth-modal-close").addEventListener("click", closeModal);
      modal.addEventListener("click", (e) => {
        if (e.target === modal) closeModal();
      });
      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && !modal.classList.contains("hidden")) closeModal();
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
