/* ============================================================
   CodeShield AI — API client
   Same-origin: the FastAPI backend serves this frontend from "/",
   so API_BASE stays empty and all calls are relative.
   ============================================================ */
"use strict";

const API_BASE = "";

/**
 * Low-level fetch wrapper.
 * - Relative paths are resolved against the same origin.
 * - Network failures become a friendly Error.
 * - Non-2xx responses surface the server's detail/error message.
 * - An AbortError is normalized to Error("cancelled") so the UI
 *   can distinguish user cancellation from real failures.
 */
async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(API_BASE + path, options);
  } catch (err) {
    if (err && err.name === "AbortError") throw new Error("cancelled");
    throw new Error(
      "Cannot reach the analysis server. Please make sure the backend is running and try again."
    );
  }

  let data = null;
  try {
    data = await res.json();
  } catch (_ignored) {
    /* non-JSON body (e.g. proxy error page) — handled below */
  }

  if (!res.ok) {
    const msg =
      (data && (data.detail || data.error || data.message)) ||
      "Request failed with status " + res.status;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return data;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Start an analysis job.
 * POST /api/v1/analyze  { repo_url, github_token?, deep_scan? }
 * -> { job_id }  (202 Accepted)
 */
async function analyzeRepo(repoUrl, token, deepScan, signal) {
  const body = { repo_url: repoUrl, deep_scan: !!deepScan };
  if (token && token.trim()) body.github_token = token.trim();

  const data = await request("/api/v1/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal,
  });

  if (!data || !data.job_id) {
    throw new Error("Server did not return a job id. Please try again.");
  }
  return data;
}

/**
 * Fetch the current state of a job.
 * GET /api/v1/jobs/{jobId}
 * -> { job_id, status, progress (0-100), stage, result?, error? }
 */
async function getJob(jobId, signal) {
  return request("/api/v1/jobs/" + encodeURIComponent(jobId), { signal });
}

/**
 * Validate that a URL points at a reachable GitHub repo.
 * GET /api/v1/github/validate?url=...
 * -> { valid, owner, repo, private }
 */
async function validateRepo(url) {
  return request("/api/v1/github/validate?url=" + encodeURIComponent(url));
}

const COMPLETED_STATES = ["completed", "done", "success", "finished"];
const FAILED_STATES = ["failed", "error"];

/**
 * Poll a job until it completes or fails.
 *
 * @param {string} jobId
 * @param {(p:{progress:number|null, stage:string, status:string})=>void} onProgress
 * @param {{interval?:number, timeout?:number, signal?:AbortSignal}} opts
 * @returns {Promise<object>} resolves with the analysis result object
 * @throws {Error} on job failure, timeout, or abort ("cancelled")
 */
function pollJob(jobId, onProgress, opts = {}) {
  const { interval = 2000, timeout = 600000, signal } = opts;

  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    let timer = null;
    let done = false;

    const finish = (fn, arg) => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      fn(arg);
    };

    if (signal) {
      if (signal.aborted) {
        finish(reject, new Error("cancelled"));
        return;
      }
      signal.addEventListener("abort", () => finish(reject, new Error("cancelled")), {
        once: true,
      });
    }

    async function tick() {
      if (done) return;
      if (signal && signal.aborted) {
        finish(reject, new Error("cancelled"));
        return;
      }
      if (Date.now() - startedAt > timeout) {
        finish(
          reject,
          new Error(
            "Analysis timed out after " +
              Math.round(timeout / 60000) +
              " minutes. The repository may be too large — try again with Deep scan off."
          )
        );
        return;
      }

      try {
        const job = await getJob(jobId, signal);
        const status = String(job.status || "").toLowerCase();

        let progress = Number(job.progress);
        if (!Number.isFinite(progress)) progress = null;
        else progress = Math.max(0, Math.min(100, progress));

        if (typeof onProgress === "function") {
          onProgress({ progress, stage: job.stage || "", status });
        }

        if (COMPLETED_STATES.includes(status)) {
          finish(resolve, job.result !== undefined ? job.result : job);
          return;
        }
        if (FAILED_STATES.includes(status)) {
          finish(reject, new Error(job.error || "Analysis failed on the server."));
          return;
        }
      } catch (err) {
        if (err && err.message === "cancelled") {
          finish(reject, err);
          return;
        }
        // Transient network blip: keep polling instead of failing the scan.
        if (typeof onProgress === "function") {
          onProgress({ progress: null, stage: "Reconnecting…", status: "running" });
        }
      }

      timer = setTimeout(tick, interval);
    }

    tick();
  });
}

window.CodeShieldAPI = { API_BASE, analyzeRepo, getJob, validateRepo, pollJob };
