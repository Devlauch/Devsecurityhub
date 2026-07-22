# DevSecurityHub

A self-hosted web app that wires your Jenkins, GitHub, and AI key together to run automated security scans (secrets detection, dependency audit, static analysis) on any Git repository — and surfaces the results in a clean dashboard.

---

## What it does

1. You connect your Jenkins instance (URL + API token) from the Settings page.
2. Optionally connect SonarQube — the app injects `SONAR_HOST_URL` and `SONAR_TOKEN` directly into Jenkins as global environment variables via the Groovy Script API.
3. Start a scan by giving a repo URL. The app generates a `Jenkinsfile`, creates the Jenkins job, triggers a build, and polls for results.
4. When the build finishes the app pulls three artifact files from Jenkins, stores them in Postgres, and renders them in the dashboard.
5. An optional AI key (Groq / Gemini / Claude / OpenAI) generates a plain-English summary of the findings.

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Frontend | React (CRA), inline styles, GitHub dark theme |
| Backend | Node.js + Express |
| Database | PostgreSQL (schema auto-applied on startup) |
| CI engine | Jenkins (Pipeline / Workflow Job plugin) |
| Container | Docker + docker-compose |

---

## Quick start

```bash
# 1. copy env file
cp .env.example .env
# edit JWT_SECRET and DB_PASSWORD

# 2. start everything
docker compose up -d

# Frontend → http://localhost:3000
# Backend  → http://localhost:4500
```

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes | Secret used to sign JWTs |
| `DB_PASSWORD` | Yes | Postgres password (default user: `devsechub`) |
| `PORT` | No | Backend port (default `4500`) |

SonarQube credentials are **not** stored in `.env` — they are pushed directly into Jenkins via the Settings UI (see [SonarQube setup](#sonarqube-setup) below).

---

## Project structure

```
devsecurityhub/
├── backend/
│   └── src/
│       ├── index.js                  # Express app entry, schema init
│       ├── db/
│       │   ├── index.js              # pg Pool wrapper
│       │   └── schema.sql            # All table definitions
│       ├── middleware/
│       │   └── auth.js               # JWT verify middleware
│       ├── routes/
│       │   ├── auth.js               # Register / Login
│       │   ├── jenkins.js            # Jenkins connect + SonarQube push
│       │   ├── scans.js              # Scan CRUD + SSE poll + reports
│       │   ├── settings.js           # AI key management
│       │   └── github.js             # GitHub PAT connect
│       └── services/
│           ├── jenkins.service.js    # Axios client for Jenkins REST API
│           ├── jenkinsfile.js        # Generates pipeline Groovy + job XML
│           ├── ai.service.js         # AI summarisation (multi-provider)
│           └── github.service.js     # GitHub API (push Jenkinsfile)
├── frontend/
│   └── src/
│       ├── App.js                    # Routes
│       ├── api/client.js             # Axios with JWT header
│       └── pages/
│           ├── LoginPage.js
│           ├── DashboardPage.js
│           ├── NewScanPage.js
│           ├── ScanDetailPage.js
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
scans               → user_id, repo_url, branch, job_name, status, last_build, ...
scan_reports        → scan_id, type (gitleaks|semgrep|owasp|trivy|ai_summary), content
```

Each user gets one Jenkins connection and one GitHub connection (upsert on conflict).  
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

#### How `/sonar` works (token injection)

```
User fills in Settings → SonarQube card
       ↓
POST /api/jenkins/sonar { sonarUrl, sonarToken }
       ↓
Backend fetches a CSRF crumb from Jenkins
       ↓
POSTs a Groovy script to /scriptText that sets:
  SONAR_HOST_URL = sonarUrl
  SONAR_TOKEN    = sonarToken
  (as Jenkins GlobalNodeProperty env vars, persisted to jenkins.xml)
       ↓
Every subsequent scan's pipeline reads $SONAR_HOST_URL and $SONAR_TOKEN
automatically — no per-job configuration needed.
```

---

### Scans  `/api/scans`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/` | Create scan → generate job XML → create Jenkins job → trigger build |
| GET | `/` | List all scans for the authenticated user |
| GET | `/:id` | Get single scan |
| POST | `/:id/rerun` | Rerun (clears old reports, re-triggers build) |
| POST | `/:id/stop` | Stop running build |
| DELETE | `/:id` | Delete scan + Jenkins job |
| GET | `/:id/status/poll` | SSE stream — fires every 5 s until build finishes |
| GET | `/:id/reports/:type` | Fetch stored report (`gitleaks`, `semgrep`, `owasp`, `trivy`) |
| GET | `/:id/reports/ai` | Generate (and cache) AI summary |

---

### Settings  `/api/settings`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Returns `{ aiKeySet, aiProvider }` |
| POST | `/ai-key` | Save AI API key (Groq / Gemini / Claude / OpenAI) |
| DELETE | `/ai-key` | Remove AI key |

---

## Jenkins pipeline — stages

The generated `Jenkinsfile` runs four stages on every scan:

### 1. Checkout
Clones the target repo at the specified branch.

### 2. Setup Tools
Downloads and caches three tools to `$HOME/sec-tools/bin` (only on first run):
- **Gitleaks v8.18.4** — secrets scanner
- **Trivy** — vulnerability scanner
- **SonarQube Scanner CLI 6.2.1** — only if `$SONAR_HOST_URL` is set

### 3. Secrets Scan (Gitleaks)
```bash
gitleaks detect --source . --format json --report-path gitleaks-report.json
```
Output artifact: `gitleaks-report.json`

### 4. SAST (SonarQube)
Runs only if `$SONAR_HOST_URL` **and** `$SONAR_TOKEN` are set (injected via Settings → SonarQube):
```bash
sonar-scanner \
  -Dsonar.projectKey=<job-name> \
  -Dsonar.sources=. \
  -Dsonar.host.url=$SONAR_HOST_URL \
  -Dsonar.token=$SONAR_TOKEN
```
Output artifact: `sonarqube-report.json`  
If not configured: artifact contains `{ "status": "NOT_CONFIGURED", "message": "..." }`.

### 5. Dependency Scan (Trivy FS)
```bash
trivy fs . --format json --severity HIGH,CRITICAL --output trivy-fs-report.json
```
Scans filesystem for vulnerable packages (npm, pip, go.sum, etc.).  
Output artifact: `trivy-fs-report.json`

### 6. Container Scan (Trivy image) — optional
Runs only if a `Dockerfile` is present **and** Docker daemon is available:
```bash
docker build -t sec-scan-image:local .
trivy image --severity HIGH,CRITICAL sec-scan-image:local
```
Output artifact: `trivy-report.txt`

---

## SonarQube setup

1. Run SonarQube locally (or point to an existing instance).
2. In SonarQube → **My Account → Security → Generate Token** — create a project analysis token.
3. In DevSecurityHub → **Settings → SonarQube card**:
   - Enter the SonarQube server URL (e.g., `http://host.docker.internal:9000`)
   - Enter the token
   - Click **Push to Jenkins**
4. The app stores `SONAR_HOST_URL` and `SONAR_TOKEN` as Jenkins global environment variables. All future scans automatically include SAST analysis.

> Note: Jenkins must have the **Script Security** and **Workflow Job** plugins installed. The Groovy script API (`/scriptText`) requires an admin-level API token.

---

## Report types

After a scan completes, four report types are fetched and stored:

| Internal type | Jenkins artifact | Tool |
|---------------|-----------------|------|
| `gitleaks` | `gitleaks-report.json` | Gitleaks — leaked secrets |
| `semgrep` | `sonarqube-report.json` | SonarQube SAST |
| `owasp` | `trivy-fs-report.json` | Trivy filesystem CVEs |
| `trivy` | `trivy-report.txt` | Trivy container image CVEs |
| `ai_summary` | (generated) | AI plain-English summary |

The type names `semgrep` and `owasp` are legacy internal names — the actual tools are SonarQube and Trivy respectively.

---

## AI summary

When viewing a completed scan, clicking **AI Summary** calls `GET /api/scans/:id/reports/ai`.  
The backend reads all four raw reports and sends them to whichever AI provider the user configured:

| Key prefix | Provider |
|-----------|---------|
| `gsk_` | Groq |
| `AIza` | Google Gemini |
| `sk-ant-` | Anthropic Claude |
| `sk-` | OpenAI |

The summary is cached in `scan_reports` with type `ai_summary` so it is only generated once per scan.

---

## Docker compose services

```yaml
db       - postgres:16  (port 5432, volume: pgdata)
backend  - node:20      (port 4500, depends on db)
frontend - nginx:alpine  (port 3000, proxies /api → backend:4500)
```

Jenkins runs separately (not in this compose file). When Jenkins is on the host machine, use `http://host.docker.internal:8080` as the Jenkins URL in Settings.
# Devsecurityhub
