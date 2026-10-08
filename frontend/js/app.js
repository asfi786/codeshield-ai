/* ============================================================
   CodeShield AI — main application logic (vanilla JS)
   Views: hero / loading / results / error
   Depends on: window.CodeShieldAPI (js/api.js),
               window.CodeShieldCharts (js/charts.js)
   ============================================================ */
"use strict";

const $ = (id) => document.getElementById(id);
const API = () => window.CodeShieldAPI;

/* ---------------- View manager ---------------- */
const VIEWS = ["hero", "loading", "results", "error"];

function showView(name) {
  VIEWS.forEach((v) => $("view-" + v).classList.toggle("hidden", v !== name));
  window.scrollTo({ top: 0, behavior: "smooth" });
}

/* ---------------- Helpers ---------------- */

/** Escape every string injected into HTML (XSS safety for finding data). */
function escapeHtml(value) {
  return String(value === null || value === undefined ? "" : value).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

/** Accept "owner/repo" shorthand and expand it to a full GitHub URL. */
function normalizeRepoUrl(input) {
  const t = String(input || "").trim();
  if (/^[\w.\-]+\/[\w.\-]+$/.test(t)) return "https://github.com/" + t;
  return t;
}

function gradeFor(score) {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 50) return "D";
  return "F";
}

function scoreColor(score) {
  if (score >= 80) return "#34d399";
  if (score >= 60) return "#facc15";
  if (score >= 40) return "#fb923c";
  return "#f87171";
}

function formatStars(n) {
  n = Number(n) || 0;
  if (n >= 1000) return "★ " + (n / 1000).toFixed(1).replace(/\.0$/, "") + "k";
  return "★ " + n;
}

/* ---------------- Score rings ---------------- */
const RING_C = 2 * Math.PI * 54;

function initRings() {
  ["ring-security", "ring-architecture", "ring-overall"].forEach((id) => {
    const el = $(id);
    el.style.strokeDasharray = String(RING_C);
    el.style.strokeDashoffset = String(RING_C);
  });
}

/** Animate a ring to `score` (0-100). Returns the clamped score. */
function setRing(ringId, scoreId, score) {
  const s = Math.max(0, Math.min(100, Number(score) || 0));
  const ring = $(ringId);
  $(scoreId).textContent = String(Math.round(s));
  // Double rAF so the CSS transition on stroke-dashoffset actually runs,
  // including on repeat renders ("Analyze another" -> new results).
  requestAnimationFrame(() =>
    requestAnimationFrame(() => {
      ring.style.strokeDashoffset = String(RING_C * (1 - s / 100));
    })
  );
  return s;
}

/* ---------------- Animated counters ---------------- */
function animateCounter(el, target, format) {
  const fmt = format || ((v) => Math.round(v).toLocaleString("en-US"));
  const dur = 1100;
  const start = performance.now();
  function frame(now) {
    const t = Math.min(1, (now - start) / dur);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = fmt(target * eased);
    if (t < 1) requestAnimationFrame(frame);
    else el.textContent = fmt(target);
  }
  requestAnimationFrame(frame);
}

/* ---------------- Progress bar (smooth tween) ---------------- */
let displayedPct = 0;
let pctRaf = 0;

function setProgress(pct) {
  if (pct === null || pct === undefined) return;
  pct = Math.max(0, Math.min(100, Number(pct) || 0));
  const from = displayedPct;
  if (pctRaf) cancelAnimationFrame(pctRaf);
  const start = performance.now();
  const dur = 450;
  function frame(now) {
    const t = Math.min(1, (now - start) / dur);
    displayedPct = from + (pct - from) * t;
    $("progress-bar").style.width = displayedPct + "%";
    $("progress-pct").textContent = Math.round(displayedPct) + "%";
    if (t < 1) pctRaf = requestAnimationFrame(frame);
  }
  pctRaf = requestAnimationFrame(frame);
}

function resetLoading(url) {
  if (pctRaf) cancelAnimationFrame(pctRaf);
  displayedPct = 0;
  $("progress-bar").style.width = "0%";
  $("progress-pct").textContent = "0%";
  $("loading-stage").textContent = "Connecting…";
  $("loading-repo").textContent = url;
}

/* ---------------- Best practices ---------------- */
function renderBestPractices(checks) {
  const grid = $("best-practices-grid");
  const items = Array.isArray(checks) ? checks : [];
  if (items.length === 0) {
    grid.innerHTML =
      '<div class="glass bp-card"><p class="text-sm text-slate-400">No best-practice data returned.</p></div>';
    return;
  }
  grid.innerHTML = items
    .map((c) => {
      const passed = !!c.passed;
      const bonus =
        passed && c.bonus !== undefined && c.bonus !== null
          ? "+" + escapeHtml(c.bonus)
          : passed
            ? "done"
            : "missing";
      return (
        '<div class="glass bp-card">' +
        '<div class="bp-icon ' +
        (passed ? "bp-pass" : "bp-fail") +
        '">' +
        (passed ? "✓" : "✗") +
        "</div>" +
        '<div class="flex-1 min-w-0">' +
        '<div class="flex items-center justify-between gap-2">' +
        '<p class="font-semibold text-sm">' +
        escapeHtml(c.name || c.check || "Check") +
        "</p>" +
        '<span class="bp-bonus ' +
        (passed ? "text-green-400" : "text-slate-500") +
        '">' +
        bonus +
        "</span>" +
        "</div>" +
        (c.description
          ? '<p class="text-xs text-slate-500 mt-1">' + escapeHtml(c.description) + "</p>"
          : "") +
        "</div></div>"
      );
    })
    .join("");
}

/* ---------------- Findings ---------------- */
const SEV_WEIGHT = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
let allFindings = [];
let activeFilter = "all";

function sevKey(s) {
  return String(s || "info").toLowerCase();
}

function findingRowHtml(f, i) {
  const sev = sevKey(f.severity);
  const loc = f.file
    ? escapeHtml(f.file) + (f.line !== null && f.line !== undefined ? ":" + escapeHtml(f.line) : "")
    : "—";
  const detailId = "finding-detail-" + i;
  let html =
    '<tr class="finding-row" data-detail="' +
    detailId +
    '" tabindex="0" aria-expanded="false">' +
    '<td><span class="badge badge-' +
    sev +
    '">' +
    escapeHtml(sev) +
    "</span></td>" +
    '<td class="font-medium text-slate-200">' +
    escapeHtml(f.title || "Untitled finding") +
    "</td>" +
    '<td class="finding-loc">' +
    loc +
    "</td>" +
    '<td class="text-slate-400">' +
    escapeHtml(f.category || "—") +
    "</td></tr>";
  html +=
    '<tr id="' +
    detailId +
    '" class="finding-detail-row hidden"><td colspan="4"><div class="finding-detail">' +
    (f.description ? "<p>" + escapeHtml(f.description) + "</p>" : "<p>No description.</p>") +
    (f.cwe ? '<p class="mt-2"><span class="badge badge-info">' + escapeHtml(f.cwe) + "</span></p>" : "") +
    (f.snippet
      ? '<pre class="finding-snippet"><code>' + escapeHtml(f.snippet) + "</code></pre>"
      : "") +
    "</div></td></tr>";
  return html;
}

function renderFindings() {
  const body = $("findings-body");
  const list = allFindings
    .filter((f) => activeFilter === "all" || sevKey(f.severity) === activeFilter)
    .sort(
      (a, b) => (SEV_WEIGHT[sevKey(a.severity)] ?? 5) - (SEV_WEIGHT[sevKey(b.severity)] ?? 5)
    );

  $("findings-count").textContent =
    allFindings.length + (allFindings.length === 1 ? " finding" : " findings");

  document.querySelectorAll("#severity-filters .filter-pill").forEach((pill) => {
    const sev = pill.dataset.severity;
    if (!pill.dataset.label) pill.dataset.label = pill.textContent.trim();
    const n =
      sev === "all"
        ? allFindings.length
        : allFindings.filter((f) => sevKey(f.severity) === sev).length;
    pill.textContent = pill.dataset.label + " (" + n + ")";
  });

  $("findings-empty").classList.toggle("hidden", list.length > 0);
  body.innerHTML = list.map((f, i) => findingRowHtml(f, i)).join("");
}

function toggleFindingRow(row) {
  const detail = document.getElementById(row.dataset.detail);
  if (!detail) return;
  const nowHidden = detail.classList.toggle("hidden");
  row.setAttribute("aria-expanded", String(!nowHidden));
}

/* ---------------- Recommendations ---------------- */
function renderRecommendations(recs) {
  const list = $("recommendations-list");
  const items = Array.isArray(recs) ? recs : [];
  list.innerHTML =
    items.length === 0
      ? '<div class="glass rec-card"><span aria-hidden="true">✅</span><p>No recommendations — this repository looks solid.</p></div>'
      : items
          .map(
            (r) =>
              '<div class="glass rec-card"><span aria-hidden="true">💡</span><p>' +
              escapeHtml(r) +
              "</p></div>"
          )
          .join("");
}

/* ---------------- Full results render ---------------- */
function renderResults(result, repoUrl) {
  const repo = result.repo || {};
  const fullName =
    repo.owner && repo.name
      ? repo.owner + "/" + repo.name
      : repo.full_name || repoUrl;

  $("result-repo-name").textContent = fullName;
  $("result-repo-desc").textContent = repo.description || "No description provided.";
  $("result-repo-stars").textContent = formatStars(repo.stars ?? repo.stargazers_count);
  $("result-repo-link").href = repo.url || repo.html_url || repoUrl;

  setRing("ring-security", "score-security", result.security && result.security.score);
  setRing("ring-architecture", "score-architecture", result.architecture && result.architecture.score);

  const overallScore = result.overall_score ?? (result.overall || {}).score;
  const ovScore = setRing("ring-overall", "score-overall", overallScore);
  const color = scoreColor(ovScore);
  $("ring-overall").style.stroke = color;
  const gradeEl = $("grade-letter");
  gradeEl.textContent = result.grade || (result.overall || {}).grade || gradeFor(ovScore);
  gradeEl.style.color = color;
  gradeEl.style.borderColor = color;

  const metrics = (result.architecture && result.architecture.metrics) || {};
  const findings = (result.security && result.security.findings) || [];
  animateCounter($("metric-files"), Number(metrics.total_files ?? metrics.files) || 0);
  animateCounter($("metric-dirs"), Number(metrics.total_dirs ?? metrics.directories) || 0);
  animateCounter($("metric-loc"), Number(metrics.total_loc ?? metrics.lines_of_code) || 0);
  animateCounter($("metric-findings"), Array.isArray(findings) ? findings.length : 0);
  animateCounter($("metric-langs"), Object.keys(metrics.languages || {}).length);
  animateCounter($("metric-frameworks"), (metrics.frameworks || []).length);
  animateCounter(
    $("metric-duration"),
    Number(result.scan_duration_seconds ?? result.duration_seconds) || 0,
    (v) => v.toFixed(1) + "s"
  );

  window.CodeShieldCharts.render(result);
  renderBestPractices((result.architecture || {}).best_practices);

  allFindings = Array.isArray(findings) ? findings : [];
  activeFilter = "all";
  document
    .querySelectorAll("#severity-filters .filter-pill")
    .forEach((p) => p.classList.toggle("active", p.dataset.severity === "all"));
  renderFindings();

  renderRecommendations(result.recommendations);
  $("summary-text").textContent = result.summary || "No summary available.";
}

/* ---------------- Analysis flow ---------------- */
let abortController = null;

async function startAnalysis(rawUrl) {
  const url = normalizeRepoUrl(rawUrl);
  const token = $("github-token").value;
  const deepScan = $("deep-scan").checked;

  resetLoading(url);
  showView("loading");
  $("analyze-btn").disabled = true;

  abortController = new AbortController();
  try {
    const data = await API().analyzeRepo(url, token, deepScan, abortController.signal);
    let result;
    if (data.result) {
      // Sync mode (serverless): the full report came back inline.
      setProgress(100);
      $("loading-stage").textContent = "Report ready";
      result = data.result;
    } else {
      result = await API().pollJob(
        data.job_id,
        (p) => {
          if (p.progress !== null && p.progress !== undefined) setProgress(p.progress);
          if (p.stage) $("loading-stage").textContent = p.stage;
        },
        { signal: abortController.signal }
      );
    }
    renderResults(result, url);
    showView("results");
  } catch (err) {
    if (err && err.message === "cancelled") {
      showView("hero");
    } else {
      $("error-message").textContent =
        err && err.message ? err.message : "Something went wrong.";
      showView("error");
    }
  } finally {
    $("analyze-btn").disabled = false;
    abortController = null;
  }
}

/* ---------------- Wiring ---------------- */
$("analyze-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const input = $("repo-url");
  const errEl = $("form-error");
  const value = input.value.trim();
  if (!value) {
    errEl.textContent = "Please enter a GitHub repository URL (or owner/repo).";
    errEl.classList.remove("hidden");
    input.focus();
    return;
  }
  errEl.classList.add("hidden");
  startAnalysis(value);
});

$("cancel-scan-btn").addEventListener("click", () => {
  if (abortController) abortController.abort();
  else showView("hero");
});

$("try-again-btn").addEventListener("click", () => showView("hero"));
$("analyze-another-btn").addEventListener("click", () => showView("hero"));
$("print-btn").addEventListener("click", () => window.print());

document.querySelectorAll(".example-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    $("repo-url").value = chip.dataset.repo;
    $("form-error").classList.add("hidden");
    $("repo-url").focus();
    $("analyze-form").scrollIntoView({ behavior: "smooth", block: "center" });
  });
});

document.querySelectorAll("#severity-filters .filter-pill").forEach((pill) => {
  pill.addEventListener("click", () => {
    document
      .querySelectorAll("#severity-filters .filter-pill")
      .forEach((p) => p.classList.remove("active"));
    pill.classList.add("active");
    activeFilter = pill.dataset.severity;
    renderFindings();
  });
});

$("findings-body").addEventListener("click", (e) => {
  const row = e.target.closest(".finding-row");
  if (row) toggleFindingRow(row);
});
$("findings-body").addEventListener("keydown", (e) => {
  if (e.key !== "Enter" && e.key !== " ") return;
  const row = e.target.closest(".finding-row");
  if (row) {
    e.preventDefault();
    toggleFindingRow(row);
  }
});

/* ---------------- Init ---------------- */
initRings();
showView("hero");
