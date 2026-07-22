# DevSecurityHub — Technical Specification

## 1. Architecture Overview

```
Browser (React)
    │  HTTP + JWT
    ▼
Express Backend (:4500)
    │
    ├── PostgreSQL  ← stores users, connections, scans, reports
    ├── Jenkins API ← creates jobs, triggers builds, fetches artifacts
    └── AI APIs     ← Groq / Gemini / Claude / OpenAI (optional)
```

The frontend is a single-page React app served by nginx. All data fetching goes through `/api/*` which nginx reverse-proxies to the Express backend.

---

## 2. Authentication

- Registration: `POST /api/auth/register` — hashes password with `bcrypt`, creates user row with a UUID.
- Login: `POST /api/auth/login` — verifies password hash, returns a JWT signed with `JWT_SECRET`.
- All protected routes run the `auth` middleware (`backend/src/middleware/auth.js`) which verifies the JWT and attaches `req.user.id`.

---

## 3. Jenkins Integration

### 3.1 Connection storage
Saved in `jenkins_connections` table (one row per user, upsert on re-connect):
```
url      TEXT   — trailing slash stripped on save
username TEXT   — Jenkins username
token    TEXT   — Jenkins API token (not the password)
```

### 3.2 API client (`jenkins.service.js`)
`getClient(url, username, token)` returns an axios instance with:
- `baseURL` = Jenkins URL
- HTTP Basic auth using username + API token
- `Content-Type: application/xml` (Jenkins job API requires XML)
- 30 s timeout

### 3.3 CSRF crumb
Jenkins CSRF protection requires a crumb header on state-changing requests.  
`getCrumb()` calls `/crumbIssuer/api/json` and returns `{ "Jenkins-Crumb": "<value>" }`.  
If crumb issuer is disabled, returns `{}` silently.

### 3.4 SonarQube token injection (`POST /api/jenkins/sonar`)

This is the mechanism by which the app stores SonarQube credentials inside Jenkins (not in the app's database):

```
1. Fetch CSRF crumb from Jenkins
2. Build a Groovy script that:
   a. Gets the Jenkins singleton instance
   b. Gets (or creates) a GlobalNodeProperty for env vars
   c. Sets ev['SONAR_HOST_URL'] and ev['SONAR_TOKEN']
   d. Calls j.save() to persist to disk
3. POST the script to /scriptText
```

**Why global env vars instead of Jenkins Credentials?**  
Jenkins Credentials API requires a different plugin and more complex Groovy. Global env vars are simpler and sufficient for the Jenkinsfile's `if [ -n "$SONAR_HOST_URL" ]` check.

**Security note:** The Groovy Script Console requires admin privileges. The user's Jenkins API token must belong to an admin account.

---

## 4. Scan Lifecycle

```
POST /api/scans
  │
  ├─ Lookup jenkins_connections for user
  ├─ Generate a unique job name: <repo-slug>-<timestamp-6digits>
  ├─ generateSecurityJenkinsfile(repoUrl, branch, jobName)
  ├─ (optional) Push Jenkinsfile.security to GitHub repo
  ├─ buildJobXml(jenkinsfile)  ← wraps Groovy in Jenkins job XML
  ├─ jenkins.createJob()       ← POST /createItem?name=...
  ├─ jenkins.triggerBuild()    ← POST /job/<name>/build
  └─ INSERT into scans (status='running')

GET /api/scans/:id/status/poll  (SSE)
  │
  └─ Every 5 s: getBuildStatus()
       ├─ building=true  → send {status:'running'}
       └─ building=false → fetchAndStoreReports() → send {status:'done'}

fetchAndStoreReports()
  ├─ getArtifact(..., 'gitleaks-report.json') → INSERT scan_reports type='gitleaks'
  ├─ getArtifact(..., 'sonarqube-report.json') → INSERT scan_reports type='semgrep'
  ├─ getArtifact(..., 'trivy-fs-report.json') → INSERT scan_reports type='owasp'
  └─ getArtifact(..., 'trivy-report.txt') → INSERT scan_reports type='trivy'
```

**SSE timeout:** 360 polls × 5 s = 30 minutes max. After that the scan is marked `failed`.

---

## 5. Jenkinsfile Generation (`jenkinsfile.js`)

`generateSecurityJenkinsfile(repoUrl, branch, jobName)` returns a Groovy pipeline string.

`buildJobXml(jenkinsfile)` wraps the pipeline in Jenkins job XML, XML-escaping all five special characters (`& < > " '`).

### Pipeline stage decisions

| Stage | Runs when |
|-------|----------|
| Checkout | Always |
| Setup Tools | Always (skips already-installed binaries) |
| Secrets Scan | Always |
| SAST (SonarQube) | Always, but inner `sh` is gated on `$SONAR_HOST_URL` and `$SONAR_TOKEN` being non-empty |
| Dependency Scan (Trivy FS) | Always |
| Container Scan (Trivy image) | Only when `Dockerfile` exists AND Docker daemon is reachable |

All stages use `catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE')` so one tool failure does not abort the rest.

---

## 6. Report Types — internal names vs tools

| `scan_reports.type` | Jenkins artifact | Actual tool | Notes |
|--------------------|-----------------|-------------|-------|
| `gitleaks` | `gitleaks-report.json` | Gitleaks | JSON array of secret findings |
| `semgrep` | `sonarqube-report.json` | SonarQube Scanner | JSON with dashboardUrl; `NOT_CONFIGURED` if env vars missing |
| `owasp` | `trivy-fs-report.json` | Trivy FS | JSON Trivy schema v2 |
| `trivy` | `trivy-report.txt` | Trivy image | Plain text table; skipped if no Docker |
| `ai_summary` | (generated on demand) | LLM API | Cached after first generation |

The type names `semgrep` and `owasp` are legacy — the tools were swapped during development but the DB column values were not changed to avoid a migration.

---

## 7. AI Summary (`ai.service.js`)

`detectProvider(key)`:
- `gsk_` → Groq
- `AIza` → Gemini
- `sk-ant-` → Claude (Anthropic)
- `sk-` → OpenAI

`summarizeFindings(gitleaks, semgrep, owasp, trivy, apiKey)` sends all four raw report strings to the detected provider and asks for a plain-English security summary. If no API key is configured, a fallback message is returned.

The summary is inserted into `scan_reports` with `type='ai_summary'` only if an API key is set (otherwise it would be re-generated on every request).

---

## 8. GitHub Integration (`github.service.js`)

`checkAndPushJenkinsfile(token, owner, repo, jfContent)`:
- Uses GitHub Contents API to check if `Jenkinsfile.security` already exists (gets its SHA if so).
- Creates or updates the file with the generated Jenkinsfile content (base64-encoded).
- This is purely informational — the Jenkins job uses an inline script, not the file from the repo.

---

## 9. Database

Schema is in `backend/src/db/schema.sql` and applied automatically on startup via `CREATE TABLE IF NOT EXISTS`.

`backend/src/db/index.js` exports a `pg.Pool` connected via:
```
PGHOST=db  PGUSER=devsechub  PGPASSWORD=$DB_PASSWORD  PGDATABASE=devsechub
```
(These are set in `docker-compose.yml` — not required in `.env`.)

---

## 10. Known issues / improvement areas

1. **AI key stored in plaintext** in the `users` table. Should be encrypted at rest.
2. **Jenkins token stored in plaintext** in `jenkins_connections`. Same concern.
3. **`semgrep`/`owasp` type name mismatch** — see section 6. A DB migration would fix this.
4. **No scan concurrency limit** — a user can queue unlimited scans simultaneously.
5. **SonarQube Groovy script** uses string interpolation which could allow injection if `sonarUrl`/`sonarToken` contain Groovy metacharacters. The current escaping handles `\` and `'` but consider using Jenkins Credentials Binding plugin instead for production.
6. **SSE connection leak** — if Jenkins is down for the full 30 minutes the SSE connection stays open. The `req.on('close')` handler clears the interval when the browser disconnects.
