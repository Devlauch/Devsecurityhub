# DevSecurityHub

A self-hosted web app that connects Jenkins, GitHub, and an AI key to run automated security scans on any Git repository — then surfaces findings in a clean dashboard with real-time pipeline tracking, cross-tool correlation, and AI-powered remediation guidance.

---

## What it does

1. Connect your Jenkins instance (URL + API token) from the Settings page.
2. Optionally connect SonarQube — credentials are pushed directly into Jenkins as global env vars.
3. Start a scan by giving a repo URL and branch. The app generates a `Jenkinsfile.security`, creates the Jenkins job, triggers a build, and streams live progress.
4. **Two tools run per scan category** — Gitleaks + TruffleHog for secrets, SonarQube + Semgrep for SAST, Trivy FS + OWASP Dependency-Check for dependencies, Trivy image + Grype for containers.
5. When the build finishes, all scan artifacts are fetched from Jenkins, stored in Postgres, merged and deduplicated, then enriched with OSV.dev advisory data (free, no key required).
6. The **Correlated** tab cross-references all tool outputs by file path and promotes multi-tool hits to highest priority.
7. An optional AI key generates a structured analysis: risk score, ranked findings, specific fix suggestions, and per-scanner summaries.

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 (CRA), inline styles, GitHub dark theme |
| Backend | Node.js 20 + Express |
| Database | PostgreSQL 16 (schema auto-applied on startup) |
| CI engine | Jenkins (Pipeline / Workflow Job plugin) |
| CVE enrichment | OSV.dev API (free, no key) |
| AI analysis | Groq / Gemini / Claude / OpenAI (bring your own key) |
| Container | Docker + docker-compose |

---

## Quick start

```bash
# 1. copy env file
cp .env.example .env
# edit JWT_SECRET and DB_PASSWORD

# 2. start everything
docker compose up -d

# Frontend → http://localhost:4501
# Backend  → http://localhost:4500
```

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes | Secret used to sign JWTs |
| `DB_PASSWORD` | Yes | Postgres password (default user: `devsechub`) |
| `PORT` | No | Backend port (default `4500`) |

SonarQube credentials are **not** stored in `.env` — they are pushed directly into Jenkins via the Settings UI.

---

## Project structure

```
devsecurityhub/
├── backend/
│   └── src/
│       ├── index.js                    # Express app entry, schema init
│       ├── db/
│       │   ├── index.js                # pg Pool wrapper
│       │   └── schema.sql              # All table definitions
│       ├── middleware/
│       │   └── auth.js                 # JWT verify middleware
│       ├── routes/
│       │   ├── auth.js                 # Register / Login
│       │   ├── jenkins.js              # Jenkins connect + SonarQube push
│       │   ├── scans.js                # Scan CRUD + SSE poll + reports
│       │   ├── settings.js             # AI key management
│       │   └── github.js               # GitHub PAT connect
│       └── services/
│           ├── jenkins.service.js      # Axios client for Jenkins REST API
│           ├── jenkinsfile.js          # Generates pipeline Groovy + job XML
│           ├── ai.service.js           # Structured AI analysis (multi-provider)
│           ├── osv.service.js          # OSV.dev CVE enrichment (free)
│           ├── correlator.service.js   # Cross-tool finding correlation
│           └── github.service.js       # GitHub API (push Jenkinsfile)
├── frontend/
│   └── src/
│       ├── App.js                      # Routes + sidebar nav
│       ├── api/client.js               # Axios with JWT header
│       └── pages/
│           ├── LoginPage.js
│           ├── DashboardPage.js        # Stat cards, active pipelines, scan table
│           ├── NewScanPage.js          # Repo URL, branch, AI pre-analysis
│           ├── ScanDetailPage.js       # Pipeline tracker, 7 tabs, correlated view
│           ├── ReportsPage.js          # Aggregated reports across all scans
│           └── SettingsPage.js
├── docker-compose.yml
└── .env.example
```

---

## Database schema

```
users               → id, name, email, password_hash, ai_api_key
github_connections  → user_id, token, login
jenkins_connections → user_id, url, username, token
sonar_connections   → user_id, url, token
scans               → user_id, repo_url, branch, job_name, status, last_build,
                       detected_lang, has_dockerfile, pre_analysis, jenkinsfile_pushed
scan_reports        → scan_id, type, content
                       types: gitleaks | trufflehog | semgrep | semgrep-sast |
                              owasp | dependency-check | trivy | trivy-image |
                              grype | checkov | ai_summary
```

`scan_reports` has a unique constraint on `(scan_id, type)` so reports are never duplicated.

---

## API reference

### Auth  `POST /api/auth/register` · `POST /api/auth/login`

All other routes require `Authorization: Bearer <jwt>`.

---

### Jenkins  `/api/jenkins`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/connect` | Save Jenkins URL + credentials, test connection |
| GET | `/status` | Returns `{ connected, url, username }` |
| DELETE | `/disconnect` | Remove saved connection |
| POST | `/sonar` | Push SonarQube config to Jenkins global env vars |

---

### Scans  `/api/scans`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/` | Create scan → generate Jenkinsfile → create job → trigger build |
| GET | `/` | List all scans for the authenticated user |
| GET | `/:id` | Get single scan |
| POST | `/:id/rerun` | Rerun (clears old reports, re-triggers build) |
| POST | `/:id/stop` | Stop running build |
| DELETE | `/:id` | Delete scan + Jenkins job |
| GET | `/:id/status/poll` | SSE stream — fires every 5 s until build finishes |
| GET | `/:id/reports/:type` | Fetch raw stored report by type |
| GET | `/:id/reports/secrets` | Merged Gitleaks + TruffleHog secrets report |
| GET | `/:id/reports/sast` | Merged SonarQube + Semgrep SAST report |
| GET | `/:id/reports/dependencies` | Merged Trivy FS + OWASP DC dependency report |
| GET | `/:id/reports/container` | Merged Trivy image + Grype container report |
| GET | `/:id/reports/correlated` | Cross-tool correlation report (no key required) |
| GET | `/:id/reports/ai` | Generate (and cache) structured AI analysis |

---

### Settings  `/api/settings`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Returns `{ aiKeySet, aiProvider }` |
| POST | `/ai-key` | Save AI API key (Groq / Gemini / Claude / OpenAI) |
| DELETE | `/ai-key` | Remove AI key |

---

## Jenkins pipeline — stages

The generated `Jenkinsfile.security` runs up to 10 stages (two tools per scan category):

| # | Stage | Runs when | Output artifact |
|---|-------|-----------|----------------|
| 1 | Checkout | Always | — |
| 2 | Setup Tools | Always (caches binaries) | — |
| 3 | Secrets Scan (Gitleaks) | Always | `gitleaks-report.json` |
| 4 | Secrets Scan (TruffleHog) | Always | `trufflehog-report.jsonl` |
| 5 | SAST (SonarQube) | Always (skipped if env vars not set) | `sonarqube-report.json` |
| 6 | SAST (Semgrep) | Always | `semgrep-sast-report.json` |
| 7 | Dependency Scan (Trivy FS) | Always | `trivy-fs-report.json` |
| 8 | Dependency Scan (OWASP DC) | Always | `owasp-dc-report.json` |
| 9 | IaC Scan (Checkov) | Always | `checkov-report.json` |
| 10 | Container Scan (Trivy + Grype) | Only if Dockerfile present | `trivy-image-report.json`, `grype-report.json`, `trivy-report.txt` |

All stages use `catchError` so one tool failure does not abort the rest.

Each scan category runs **two independent open-source scanners**. Results are merged server-side and deduplicated — findings confirmed by both tools show a `✓ CONFIRMED` badge.

---

## OSV enrichment

After every scan completes, the `owasp` (Trivy FS) report is enriched automatically:

1. All `CVE-*` IDs are extracted from the Trivy JSON output.
2. A single batch POST to `https://api.osv.dev/v1/querybatch` (free, no API key) returns advisory details for up to 50 CVEs.
3. Each vulnerability entry gains: `summary`, `details`, `cvssScore`, `fixed` version, and `references` (advisory links).
4. The enriched JSON replaces the original in `scan_reports`.

The Dependencies tab shows an **"Enriched with OSV.dev"** banner and renders the additional data inline.

---

## Finding correlator

`GET /api/scans/:id/reports/correlated` runs the correlator service on all stored reports:

1. Parses findings from Gitleaks, SonarQube, Trivy FS, and Checkov.
2. Groups all findings by normalized file path.
3. Any file flagged by 2+ tools has its effective severity bumped (MEDIUM → HIGH, HIGH → CRITICAL).
4. Returns findings sorted: multi-tool hits first, then by worst severity.

The **🔗 Correlated** tab (first tab on the scan detail page) shows:
- Summary cards: total findings, critical files, multi-tool hits
- Tool breakdown counts
- Per-file finding list with MULTI-TOOL badge on cross-tool hits

---

## AI analysis

`GET /api/scans/:id/reports/ai` generates a **structured JSON** analysis:

```json
{
  "riskLevel": "CRITICAL|HIGH|MEDIUM|LOW",
  "riskScore": 0–100,
  "headline": "one-sentence overall assessment",
  "topFindings": [
    { "severity": "...", "tool": "...", "issue": "...", "fix": "..." }
  ],
  "immediateActions": ["action 1", "action 2", "action 3"],
  "byTool": {
    "secrets": "...", "sast": "...", "dependencies": "...", "container": "..."
  }
}
```

The prompt includes the correlated findings summary so the LLM can identify cross-tool patterns. The result is cached in `scan_reports` with `type='ai_summary'` after first generation.

### Supported providers

| Key prefix | Provider | Model used |
|-----------|---------|-----------|
| `gsk_` | Groq | llama-3.3-70b-versatile |
| `AIza` | Google Gemini | gemini-1.5-flash |
| `sk-ant-` | Anthropic Claude | claude-haiku-4-5 |
| `sk-` | OpenAI | gpt-4o-mini |

---

## UI pages

| Page | Path | Description |
|------|------|-------------|
| Dashboard | `/dashboard` | Stat cards, active pipelines (animated), completed scans table |
| New Scan | `/scans/new` | Repo URL + branch input, AI pre-scan analysis |
| Scan Detail | `/scans/:id` | 7-stage pipeline tracker, 7-tab report view |
| Reports | `/reports` | Aggregated findings across all scans by type |
| Settings | `/settings` | Jenkins, SonarQube, GitHub, AI key configuration |

### Scan Detail tabs

| Tab | Description |
|-----|-------------|
| 🔗 Correlated | Cross-tool correlation — multi-tool hits ranked first |
| 🔑 Secrets | Merged Gitleaks + TruffleHog — deduplicated by detector type + file |
| 🔍 SAST | Merged SonarQube + Semgrep — deduplicated by file + line proximity (±3 lines) |
| 📦 Dependencies | Merged Trivy FS + OWASP DC — deduplicated by CVE ID, enriched with OSV |
| 🐳 Container | Merged Trivy image + Grype — deduplicated by CVE ID (Dockerfile-only) |
| 🏗️ IaC | Checkov Dockerfile/compose misconfigurations |
| ✨ AI Summary | Structured risk card, top findings with fix suggestions, immediate actions |

Findings confirmed by both tools in the same category show a **✓ CONFIRMED** badge. Source tool badges (Gitleaks, TruffleHog, SonarQube, Semgrep, Trivy, Grype) are shown per finding.

---

## SonarQube setup

1. Run SonarQube locally or point to an existing instance.
2. In SonarQube → **My Account → Security → Generate Token**.
3. In DevSecurityHub → **Settings → SonarQube**:
   - Enter the SonarQube URL (e.g., `http://host.docker.internal:9000`)
   - Enter the token → click **Push to Jenkins**
4. All future scans automatically include SAST analysis.

> Jenkins must have the **Script Security** and **Workflow Job** plugins. The Groovy script API requires an admin-level API token.

---

## Docker compose services

```
db       — postgres:16   port 5432,  volume: pgdata
backend  — node:20       port 4500,  depends on db
frontend — nginx:alpine  port 4501,  proxies /api → backend:4500
```

Jenkins runs separately. When Jenkins is on the host machine, use `http://host.docker.internal:8080` as the Jenkins URL in Settings.
