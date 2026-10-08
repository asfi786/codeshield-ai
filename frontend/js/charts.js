/* ============================================================
   CodeShield AI — Chart.js visualizations (dark theme)
   Exposes window.CodeShieldCharts.render(result).
   Safe to call before Chart.js loads: shows a fallback message.
   ============================================================ */
"use strict";

window.CodeShieldCharts = (function () {
  let langChart = null;
  let sevChart = null;

  const PALETTE = [
    "#38bdf8", "#818cf8", "#a78bfa", "#f472b6", "#fb923c",
    "#facc15", "#34d399", "#2dd4bf", "#f87171", "#94a3b8",
  ];

  const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
  const SEVERITY_COLORS = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#22c55e",
    info: "#3b82f6",
  };

  function $(id) {
    return document.getElementById(id);
  }

  function applyDarkDefaults() {
    if (typeof Chart === "undefined") return;
    Chart.defaults.color = "#cbd5e1";
    Chart.defaults.borderColor = "rgba(255, 255, 255, 0.08)";
    Chart.defaults.font.family = "Inter, ui-sans-serif, system-ui, sans-serif";
    Chart.defaults.font.size = 12;
  }

  function toggleEmpty(canvasId, emptyId, isEmpty) {
    const canvas = $(canvasId);
    const empty = $(emptyId);
    if (canvas) canvas.style.display = isEmpty ? "none" : "";
    if (empty) empty.classList.toggle("hidden", !isEmpty);
  }

  function renderLanguageDonut(languages) {
    if (langChart) {
      langChart.destroy();
      langChart = null;
    }
    // Backend shape: { Python: { files: 12, loc: 42000 }, ... } (also accepts { Python: 42000 })
    const entries = Object.entries(languages || {})
      .map(([k, v]) => [k, Number(v && typeof v === "object" ? v.loc : v) || 0])
      .filter(([, v]) => v > 0)
      .sort((a, b) => b[1] - a[1]);

    if (entries.length === 0 || typeof Chart === "undefined") {
      toggleEmpty("chart-languages", "languages-empty", true);
      return;
    }
    toggleEmpty("chart-languages", "languages-empty", false);

    // Top 8 languages + "Other" bucket keeps the donut readable.
    const top = entries.slice(0, 8);
    const rest = entries.slice(8);
    const labels = top.map(([k]) => k);
    const data = top.map(([, v]) => v);
    if (rest.length > 0) {
      labels.push("Other");
      data.push(rest.reduce((sum, [, v]) => sum + v, 0));
    }

    langChart = new Chart($("chart-languages"), {
      type: "doughnut",
      data: {
        labels,
        datasets: [
          {
            data,
            backgroundColor: labels.map((_, i) => PALETTE[i % PALETTE.length]),
            borderColor: "#0a0e1a",
            borderWidth: 3,
            hoverOffset: 8,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "65%",
        plugins: {
          legend: { position: "bottom", labels: { boxWidth: 12, boxHeight: 12, padding: 14 } },
          tooltip: {
            callbacks: {
              label: (ctx) =>
                " " + ctx.label + ": " + Number(ctx.parsed).toLocaleString("en-US") + " LOC",
            },
          },
        },
      },
    });
  }

  function renderSeverityBar(summary) {
    if (sevChart) {
      sevChart.destroy();
      sevChart = null;
    }
    const counts = SEVERITY_ORDER.map((sev) => Number((summary || {})[sev]) || 0);
    const total = counts.reduce((a, b) => a + b, 0);

    if (total === 0 || typeof Chart === "undefined") {
      toggleEmpty("chart-severity", "severity-empty", true);
      return;
    }
    toggleEmpty("chart-severity", "severity-empty", false);

    sevChart = new Chart($("chart-severity"), {
      type: "bar",
      data: {
        labels: SEVERITY_ORDER.map((s) => s.charAt(0).toUpperCase() + s.slice(1)),
        datasets: [
          {
            data: counts,
            backgroundColor: SEVERITY_ORDER.map((s) => SEVERITY_COLORS[s]),
            borderRadius: 8,
            borderSkipped: false,
            maxBarThickness: 56,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: {
            beginAtZero: true,
            ticks: { stepSize: 1, precision: 0 },
          },
        },
      },
    });
  }

  /**
   * Render (or re-render) both charts from an analysis result.
   * Expected shape:
   *   result.architecture.metrics.languages = { Python: { files: 12, loc: 42000 }, ... }
   *   result.security.summary = { critical, high, medium, low, info }
   * Missing sections degrade gracefully to empty states.
   */
  function render(result) {
    applyDarkDefaults();
    const arch = (result && result.architecture) || {};
    const metrics = arch.metrics || {};
    const sec = (result && result.security) || {};
    renderLanguageDonut(metrics.languages);
    renderSeverityBar(sec.summary);
  }

  return { render };
})();
