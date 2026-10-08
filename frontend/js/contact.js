/* ============================================================
   CodeShield AI — contact form -> WhatsApp
   Builds a pre-filled WhatsApp message and opens it in a new tab.
   ============================================================ */
"use strict";

(function () {
  function init() {
    const form = document.getElementById("contact-form");
    if (!form) return;

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const name = document.getElementById("contact-name").value.trim();
      const email = document.getElementById("contact-email").value.trim();
      const message = document.getElementById("contact-message").value.trim();
      const err = document.getElementById("contact-error");

      if (!name || !message) {
        err.textContent = "Please add your name and a message.";
        err.classList.remove("hidden");
        return;
      }
      err.classList.add("hidden");

      const text =
        "Hi Asfund, I'm " + name +
        (email ? " (" + email + ")" : "") +
        ".\n\n" + message;
      window.open(
        "https://wa.me/923116530234?text=" + encodeURIComponent(text),
        "_blank",
        "noopener"
      );
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
