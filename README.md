# 🛡️ CodeShield AI

**GitHub Repository Architecture & Security Auditor** — paste any public GitHub repo URL and get a professional security + architecture audit in seconds: secret detection, vulnerability patterns, language/framework analysis, best-practice scoring, and an overall A+–F grade — all in a sleek glassmorphism dashboard.

Built with **FastAPI** (async backend) + **Tailwind CSS** glassmorphism frontend (vanilla JS, Chart.js).

## ✨ Features

- **Secret scanning** — 9 detection patterns (AWS keys, GitHub tokens, private keys, JWTs, DB connection strings, hardcoded passwords, Slack webhooks…)
- **Vulnerability detection** — 9 patterns (SQL/command injection, `eval`/`exec`, pickle/YAML deserialization, disabled SSL verification, XSS via `innerHTML`, debug mode, insecure randomness…)
- **Architecture analysis** — file/dir/LOC metrics, 40+ language detection, 17 framework detection, directory depth
- **Best-practice checklist** — README, LICENSE, tests, CI/CD, Docker, docs, `.gitignore`
- **Scoring** — Security (100 − severity penalties) + Architecture (50 + bonuses); overall = 55% security + 45% architecture; letter grade A+–F
- **Async job pipeline** — analysis runs in the background; the UI polls live progress (no request timeouts on large repos)
- **Beautiful UI** — animated score rings, counters, language donut, severity bar chart, severity-filterable findings table, print-friendly report export
- **Production hardening** — per-IP rate limiting, file-count caps, binary/large-file skipping, optional GitHub token for 5000 req/hour

## 🚀 Quickstart

### Option A — Docker (recommended)

```bash
cp .env.example .env          # optional: add your GITHUB_TOKEN
docker compose up --build
# open http://localhost:8000
```

### Option B — Local Python

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
# open http://localhost:8000
```

Interactive API docs: http://localhost:8000/docs

## 🔌 API Reference

| Method | Route | Description |
|---|---|---|
| GET | `/api/v1/health` | `{ status, version, timestamp }` |
| GET | `/api/v1/github/validate?url=...` | `{ valid, owner, repo, private }` |
| POST | `/api/v1/analyze` | Start audit → `202 { job_id, status: "queued" }` |
| GET | `/api/v1/jobs/{job_id}` | Poll → `{ job_id, status, progress, stage, result?, error? }` |

`POST /api/v1/analyze` body:

```json
{ "repo_url": "https://github.com/owner/repo", "github_token": "optional", "deep_scan": false }
```

Job `status`: `queued` → `running` → `completed` | `failed`. On `completed`, `result` holds the full `AnalysisResponse`.

> **Note:** the original spec described a synchronous `POST /analyze`. This build uses async jobs (202 + polling) so large repositories never hit HTTP timeouts — the recommended production pattern.

## 📊 Scoring

**Security** — starts at 100, subtract per finding: Critical −20, High −12, Medium −5, Low −2, Info −0.5 (clamped 0–100).

**Architecture** — starts at 50, add bonuses: README +10, LICENSE +5, tests +10, CI/CD +8, Docker +5, docs +5, `.gitignore` +3 (capped at 100).

**Overall** = 0.55 × Security + 0.45 × Architecture → grade A+ (90+) · A (80+) · B (70+) · C (60+) · D (50+) · F (<50).

## ⚙️ Configuration

All via environment (see `.env.example`): `GITHUB_TOKEN`, `DEBUG`, `ALLOWED_ORIGINS`, `MAX_FILES` (default 120), `MAX_FILES_DEEP` (default 300), `ANALYZE_MODE` (`async` default / `sync`), `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `SESSION_SECRET`.

**User accounts & sign-in**: visitors register with name/email/password (stored as peppered PBKDF2 hashes, one private JSON blob per user in Vercel Blob) or use "Sign in with Google". Sessions are stateless signed JWT cookies (30 days). The analyzer (`POST /api/v1/analyze`) requires sign-in. For Google sign-in, create an OAuth 2.0 client at https://console.cloud.google.com/apis/credentials (Web application) with redirect URI `<your-origin>/api/v1/auth/google/callback`, then set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`. Without those, the Google button shows a clean "not configured" message; email/password works regardless.

`ANALYZE_MODE=async` (default): `POST /analyze` returns `202 { job_id }` and the analysis runs in the background — for Docker, Render, VPS. `ANALYZE_MODE=sync`: the analysis runs inside the request and the full report is returned directly — required on serverless hosts (Vercel) where background tasks do not survive the response. The frontend handles both automatically.

Without a token, GitHub allows 60 API requests/hour — one medium repo ≈ 50 requests. Add a token (free, no scopes needed for public repos) for 5000/hour.

## 🏗️ Project Structure

```
codeshield_ai/
├── backend/
│   ├── requirements.txt
│   ├── Dockerfile
│   └── app/
│       ├── main.py                 ← FastAPI app, CORS, static frontend
│       ├── config.py               ← pydantic-settings
│       ├── api/routes/             ← health, github, analysis, jobs
│       ├── core/                   ← github_client, security_scanner,
│       │                             architecture_analyzer, report_generator,
│       │                             pipeline, job_manager, rate_limit
│       ├── models/schemas.py       ← Pydantic models
│       └── utils/helpers.py        ← URL parsing, grading, languages
├── frontend/
│   ├── index.html
│   ├── css/styles.css              ← glassmorphism + animations + print
│   └── js/                         ← api.js, app.js, charts.js
├── docker-compose.yml
├── .env.example
└── README.md
```

## 🌐 Deployment

Any host that runs Docker/Python works. Free options:

- **Vercel** (serverless, free): the repo ships `server.py` (Vercel's Python framework entrypoint — it detects the FastAPI `app` and routes every request to it, exactly like local) + `vercel.json`, which sets `ANALYZE_MODE=sync`. No rewrites needed; the app's own static mounts serve the frontend. Just deploy the repo. Hobby functions allow up to 300s per request.
- **Render** (free web service): connect repo → it picks up `render.yaml` (Docker blueprint) automatically. Free tier sleeps after 15 min idle (first request wakes it, ~50s cold start). Uses the default `async` job mode.
- **Hugging Face Spaces** (Docker SDK): free, same Dockerfile works.
- **VPS**: `docker compose up -d --build`.

Set `GITHUB_TOKEN` in the host's environment variables for the higher API quota.

## 📄 License

MIT — see `LICENSE`.
