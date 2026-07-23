# DevSecurityHub — Technical Specification

## 1. Architecture Overview

```
Browser (React SPA)
    │  HTTP + JWT
    ▼
nginx (:4501)  →  /api/* proxy  →  Express Backend (:4500)
                                          │
                               ┌──────────┼──────────────┐
                               ▼          ▼              ▼
                          PostgreSQL   Jenkins API    AI APIs
                          (reports,    (jobs,         (Groq/Gemini/
                           users)      artifacts)      Claude/OpenAI)
                                          │
                                    OSV.dev API
                                    (CVE enrichment,
                                     free, no key)
```

The frontend is a single-page React app (CRA) served by nginx. All data goes through `/api/*` which nginx reverse-proxies to Express. No CSS framework — all styling is inline with the GitHub dark palette (`#0d1117` background, `#161b22` cards, `#58a6ff` accent).

---

## 2. Authentication

- `POST /api/auth/register` — bcrypt password hash, UUID primary key, inserted into `users`.
- `POST /api/auth/login` — verifies hash, returns JWT signed with `JWT_SECRET` (7-day expiry).
- `auth` middleware (`middleware/auth.js`) — verifies JWT on every protected route, attaches `req.user.id`.
- Frontend stores token in `localStorage` under `sechub_token` and user object under `sechub_user`.

---

## 3. Jenkins Integration

### 3.1 Connection storage
`jenkins_connections` table — one row per user, upsert on re-connect:
```
url      TEXT   — trailing slash stripped on save
username TEXT   — Jenkins username
token    TEXT   — Jenkins API token
```

### 3.2 API client (`jenkins.service.js`)
`getClient(url, username, token)` — axios instance with HTTP Basic auth, `Content-Type: application/xml`, 30 s timeout.

### 3.3 CSRF crumb
`getCrumb()` calls `/crumbIssuer/api/json`. Returns `{}` silently if CSRF is disabled.

### 3.4 SonarQube token injection (`POST /api/jenkins/sonar`)
```
1. Fetch CSRF crumb
2. Build Groovy script that sets SONAR_HOST_URL + SONAR_TOKEN
   as Jenkins GlobalNodeProperty env vars and calls j.save()
3. POST script to /scriptText (requires admin Jenkins token)
```
All subsequent pipeline runs read these vars automatically — no per-job config needed.

---

## 4. Scan Lifecycle

```
POST /api/scans
  ├─ Lookup jenkins_connections
  ├─ Generate unique job name: <repo-slug>-<timestamp-6digits>
  ├─ generateSecurityJenkinsfile(repoUrl, branch, jobName)
  ├─ (optional) checkAndPushJenkinsfile() → GitHub Contents API
  ├─ buildJobXml(jenkinsfile) → XML-escape & wrap in job XML
  ├─ jenkins.createJob() → POST /createItem?name=...
  ├─ jenkins.triggerBuild() → POST /job/<name>/build
  └─ INSERT scans (status='running')

GET /api/scans/:id/status/poll  [SSE, 5 s interval, 30 min max]
  └─ getBuildStatus()
       ├─ building=true  → send {status:'running', build:N}
       └─ building=false → fetchAndStoreReports() → send {status:'done'}

fetchAndStoreReports()
  ├─ getArtifact('gitleaks-report.json')      → INSERT type='gitleaks'
  ├─ getArtifact('trufflehog-report.jsonl')   → INSERT type='trufflehog'
  ├─ getArtifact('sonarqube-report.json')     → INSERT type='semgrep'
  ├─ getArtifact('semgrep-sast-report.json')  → INSERT type='semgrep-sast'
  ├─ getArtifact('trivy-fs-report.json')      → INSERT type='owasp'
  ├─ getArtifact('owasp-dc-report.json')      → INSERT type='dependency-check'
  ├─ getArtifact('trivy-report.txt')          → INSERT type='trivy'
  ├─ getArtifact('trivy-image-report.json')   → INSERT type='trivy-image'
  ├─ getArtifact('grype-report.json')         → INSERT type='grype'
  ├─ getArtifact('checkov-report.json')       → INSERT type='checkov'
  ├─ enrichSonarReport()  → fetch SonarQube metrics + issues, UPDATE semgrep report
  └─ enrichOwaspWithOSV() → OSV batch query, UPDATE owasp report
```

SSE timeout: 360 polls × 5 s = 30 minutes. After timeout → scan marked `failed`.

---

## 5. Jenkinsfile Generation (`jenkinsfile.js`)

`generateSecurityJenkinsfile(repoUrl, branch, jobName)` returns a Groovy pipeline string with 10 stages.  
`buildJobXml(jenkinsfile)` wraps it in Jenkins job XML, escaping `& < > " '`.

### Pipeline stage decisions

| Stage | Tool | Condition | Output |
|-------|------|-----------|--------|
| Checkout | git | Always | — |
| Setup Tools | curl/pip | Always (skips already-downloaded binaries) | — |
| Secrets Scan (Gitleaks) | Gitleaks v8 | Always | `gitleaks-report.json` |
| Secrets Scan (TruffleHog) | TruffleHog | Always | `trufflehog-report.jsonl` |
| SAST (SonarQube) | SonarQube Scanner | Always; inner `sh` gated on `$SONAR_HOST_URL`/`$SONAR_TOKEN` | `sonarqube-report.json` |
| SAST (Semgrep) | Semgrep | Always | `semgrep-sast-report.json` |
| Dependency Scan (Trivy FS) | Trivy | Always | `trivy-fs-report.json` |
| Dependency Scan (OWASP DC) | OWASP Dependency-Check | Always | `owasp-dc-report.json` |
| IaC Scan (Checkov) | Checkov | Always | `checkov-report.json` |
| Container Scan (Trivy + Grype) | Trivy image + Grype | Only if `Dockerfile` exists AND Docker daemon reachable | `trivy-image-report.json`, `grype-report.json`, `trivy-report.txt` |

All stages use `catchError(buildResult:'SUCCESS', stageResult:'UNSTABLE')`.

### Tool installation (Setup Tools stage)
All tools are cached in `$HOME/sec-tools/bin` and only downloaded if missing:
- **Gitleaks** — binary from GitHub releases
- **Trivy** — official install script
- **Checkov** — `pip install checkov`
- **SonarQube Scanner** — zip from binaries.sonarsource.com (only if `$SONAR_HOST_URL` set)
- **OWASP Dependency-Check** — zip from GitHub releases (~200 MB NVD DB cached after first run)
- **TruffleHog** — official install script
- **Semgrep** — `pip install semgrep`
- **Grype** — official install script

---

## 6. Report Types

| `scan_reports.type` | Jenkins artifact | Tool | Format |
|--------------------|-----------------|------|--------|
| `gitleaks` | `gitleaks-report.json` | Gitleaks | JSON array of findings |
| `trufflehog` | `trufflehog-report.jsonl` | TruffleHog | JSONL (one JSON object per line) |
| `semgrep` | `sonarqube-report.json` | SonarQube | JSON; `NOT_CONFIGURED` if env vars missing; enriched with metrics+issues |
| `semgrep-sast` | `semgrep-sast-report.json` | Semgrep | JSON `{results:[], errors:[]}` |
| `owasp` | `trivy-fs-report.json` | Trivy FS | Trivy JSON schema v2; enriched with OSV data |
| `dependency-check` | `owasp-dc-report.json` | OWASP Dependency-Check | JSON `{dependencies:[]}` |
| `trivy` | `trivy-report.txt` | Trivy image | Plain text table; absent if no Dockerfile |
| `trivy-image` | `trivy-image-report.json` | Trivy image | Trivy JSON schema v2 |
| `grype` | `grype-report.json` | Grype | JSON `{matches:[]}` |
| `checkov` | `checkov-report.json` | Checkov | JSON with passed/failed checks |
| `ai_summary` | (generated on demand) | LLM API | Structured JSON; cached after first generation |

> The type names `semgrep` and `owasp` are legacy internal names — the actual tools are SonarQube and Trivy respectively. Not changed to avoid a migration.

### Merged report endpoints (server-side deduplication)

| Endpoint | Sources merged | Dedup key |
|----------|---------------|-----------|
| `GET /:id/reports/secrets` | `gitleaks` + `trufflehog` | `detectorType:file` |
| `GET /:id/reports/sast` | `semgrep` + `semgrep-sast` | same file + line within ±3 |
| `GET /:id/reports/dependencies` | `owasp` + `dependency-check` | CVE ID (exact) |
| `GET /:id/reports/container` | `trivy-image` + `grype` | CVE ID (exact) |

Response shape for all merged endpoints:
```json
{
  "totalFindings": N,
  "tool1Count": N,
  "tool2Count": N,
  "bothCount": N,
  "items": [{ "sources": ["tool1","tool2"], "confirmed": true, ...finding }]
}
```
Findings with `sources` length > 1 are flagged `confirmed: true` and rendered with a `✓ CONFIRMED` badge in the UI.

---

## 7. OSV Enrichment (`osv.service.js`)

Called automatically after every scan completes via `enrichOwaspWithOSV(scan)`.

### Flow
1. Read the stored `owasp` (Trivy FS) report from `scan_reports`.
2. Extract all `CVE-*` IDs from `Results[].Vulnerabilities[].VulnerabilityID`.
3. Deduplicate, cap at 50 IDs.
4. `POST https://api.osv.dev/v1/querybatch` with `{ queries: [{id: "CVE-..."}, ...] }`.
5. Map response back to CVE IDs — extract `summary`, `details`, `aliases`, `references[]`, CVSS `score`, and `fixed` version from the first range event.
6. Merge OSV data as `.OSV` field on each matching vulnerability.
7. `UPDATE scan_reports` with the enriched JSON.

**Free, no API key, maintained by Google.** Capped at 50 CVEs per scan to avoid slow responses.

---

## 8. Finding Correlator (`correlator.service.js`)

`buildCorrelatedReport({ gitleaks, semgrep, owasp, checkov })` — pure in-memory computation, no DB writes.

### Parsers per tool
- **Gitleaks** → `{ tool, type:'secret', severity:'CRITICAL', file, line, title, detail }`
- **SonarQube** → `{ tool, type, severity (mapped from BLOCKER/CRITICAL/MAJOR), file, line, title }`
- **Trivy FS** → `{ tool, type:'dependency', severity, file (Target), title (CVE+pkg), fix, cveId }`
- **Checkov** → `{ tool, type:'iac', severity, file, line, title, detail (check_id) }`

### Correlation logic
1. All findings merged into one array.
2. Grouped by `finding.file.toLowerCase()` (empty file → `__no_file__` bucket).
3. Per group: collect unique tools, find worst severity.
4. **Severity bump**: if 2+ tools hit same file and worst severity ≥ MEDIUM → bump to HIGH. If 3+ tools → CRITICAL.
5. Sort: `multiTool=true` first, then by `SEV_RANK`.

### Response shape
```json
{
  "totalFindings": N,
  "uniqueFiles": N,
  "multiToolHits": N,
  "criticalCount": N,
  "highCount": N,
  "toolBreakdown": { "secrets": N, "sast": N, "dependencies": N, "iac": N },
  "items": [{ "file", "tools", "toolCount", "severity", "multiTool", "findings": [...] }]
}
```

---

## 9. AI Analysis (`ai.service.js`)

### Provider detection
| Key prefix | Provider | Model |
|-----------|---------|-------|
| `gsk_` | Groq | llama-3.3-70b-versatile |
| `AIza` | Gemini | gemini-1.5-flash |
| `sk-ant-` | Anthropic Claude | claude-haiku-4-5-20251001 |
| `sk-` | OpenAI | gpt-4o-mini |

### `summarizeFindings(gitleaks, semgrep, owasp, trivy, apiKey, correlated)`

Builds a prompt that includes:
- Per-tool finding counts (secrets, SAST issues, vulnerable deps, container CVEs).
- Top 5 correlated items from `buildCorrelatedReport()` — file path + tools + effective severity.
- Instruction to respond **only with valid JSON** in a defined schema.

Expected response schema:
```json
{
  "riskLevel": "CRITICAL|HIGH|MEDIUM|LOW",
  "riskScore": 0–100,
  "headline": "string",
  "topFindings": [{ "severity", "tool", "issue", "fix" }],
  "immediateActions": ["string", "string", "string"],
  "byTool": { "secrets", "sast", "dependencies", "container" }
}
```

If JSON parsing fails, the raw text is wrapped as `{ rawText: "..." }` so the frontend can fall back to plain display.

Result is stored in `scan_reports` with `type='ai_summary'` and served from cache on subsequent requests.

### `analyzeRepo({ language, frameworks, keyFiles, hasDockerfile }, apiKey)`

Called during `POST /api/scans` (new scan creation) before the Jenkins job is triggered. Returns a markdown-formatted pre-scan risk analysis stored in `scans.pre_analysis`.

---

## 10. Frontend — ScanDetailPage pipeline tracker

`PipelineTracker` component uses **time-based stage estimation** because the Jenkins SSE stream only reports overall build status, not individual stage completion.

```js
const PIPELINE_STAGES = [
  { id: 'checkout',   label: 'Checkout',    icon: '📥', endSec: 15 },
  { id: 'setup',      label: 'Setup Tools', icon: '🔧', endSec: 70 },
  { id: 'gitleaks',   label: 'Gitleaks',    icon: '🔑', endSec: 120 },
  { id: 'trufflehog', label: 'TruffleHog',  icon: '🔒', endSec: 170 },
  { id: 'sonarqube',  label: 'SonarQube',   icon: '🔍', endSec: 270 },
  { id: 'semgrep',    label: 'Semgrep',     icon: '🧪', endSec: 360 },
  { id: 'trivy-fs',   label: 'Trivy FS',    icon: '📦', endSec: 420 },
  { id: 'owasp-dc',   label: 'OWASP DC',    icon: '🛡️', endSec: 560 },
  { id: 'checkov',    label: 'Checkov',     icon: '🏗️', endSec: 630 },
  { id: 'container',  label: 'Container',   icon: '🐳', endSec: 760, dockerOnly: true },
];
```

`elapsed` seconds since `scan.created_at` are compared to `endSec` thresholds:
- `elapsed >= stage.endSec` → `done`
- `elapsed >= prevStage.endSec` → `running`
- otherwise → `pending`

Active stage gets `animation: 'stagePulse 2s ease-in-out infinite'` and a spinning `⟳` icon.

OWASP DC has a longer `endSec` (560 s) because its first run downloads the NVD vulnerability database (~200 MB).

---

## 11. Frontend — Scan Detail merged tab components

Each scan category has a dedicated React component that fetches the merged endpoint and renders findings with source badges.

| Component | Tab | Fetches | Dedup badge |
|-----------|-----|---------|-------------|
| `SecretsReport` | 🔑 Secrets | `/reports/secrets` | `✓ CONFIRMED` when Gitleaks + TruffleHog both find same detector:file |
| `SastReport` | 🔍 SAST | `/reports/sast` + enriched `semgrep` report for SonarQube metrics | `✓ CONFIRMED` when SonarQube + Semgrep match same file ±3 lines |
| `DependenciesReport` | 📦 Dependencies | `/reports/dependencies` | `✓ CONFIRMED` when Trivy FS + OWASP DC share same CVE ID |
| `ContainerReport` | 🐳 Container | `/reports/container` | `✓ CONFIRMED` when Trivy image + Grype share same CVE ID |

Shared badge components (defined at top of `ScanDetailPage.js`):
```js
const ALL_SOURCE_BADGES = {
  gitleaks:   { label: 'Gitleaks',   color: '#f85149' },
  trufflehog: { label: 'TruffleHog', color: '#d29922' },
  sonarqube:  { label: 'SonarQube',  color: '#388bfd' },
  semgrep:    { label: 'Semgrep',    color: '#3fb950' },
  trivy:      { label: 'Trivy',      color: '#d29922' },
  grype:      { label: 'Grype',      color: '#58a6ff' },
};
```
`SourceBadge` — small pill with tool-specific colour.  
`ConfirmedBadge` — green `✓ CONFIRMED` pill, shown when `item.confirmed === true`.  
`MergedBanner` — top-of-tab banner with both tool names and total/confirmed counts.

## 12. Frontend — AI Pre-Scan Analysis card

`PreAnalysisCard` component parses the `scan.pre_analysis` markdown string:
- Lines starting with `### ` → section headers (matched to icons via `SECTION_ICONS` map).
- Lines starting with `- ` → bullet items within the current section.
- `**text**` → `<strong>` inline elements.

Each section renders as a dark card with icon, yellow header, and blue `▸` bullet arrows.

---

## 13. GitHub Integration (`github.service.js`)

`checkAndPushJenkinsfile(token, owner, repo, jfContent)`:
- Checks if `Jenkinsfile.security` exists via GitHub Contents API (gets SHA if so).
- Creates or updates the file (base64-encoded content).
- Purely informational — the Jenkins job uses an inline pipeline script, not the repo file.

---

## 14. Database

Schema: `backend/src/db/schema.sql`, applied via `CREATE TABLE IF NOT EXISTS` on every startup.

Connection: `pg.Pool` using env vars set in `docker-compose.yml`:
```
PGHOST=db  PGUSER=devsechub  PGPASSWORD=$DB_PASSWORD  PGDATABASE=devsechub
```

---

## 15. CSS animations

All keyframes are defined in `frontend/public/index.html` `<style>` block (no CSS files or modules). Referenced by name in inline `animation` style props:

| Keyframe | Used by |
|----------|---------|
| `spin` | Running stage icon, running status badge |
| `pulse` | Skeleton loaders, pending stage dot |
| `glow` | Active pipeline card border |
| `slideUp` | Stat cards on load |
| `stagePulse` | Currently-running pipeline stage card |
| `progressSlide` | Pipeline progress bar (300 s linear) |
| `runDot` | Running/pending status badge dot |
| `fadeIn` | Page and tab transitions |
| `shimmer` | Reserved for skeleton shimmer effect |

---

## 16. Known issues / improvement areas

1. **AI key stored in plaintext** in the `users` table. Should be encrypted at rest.
2. **Jenkins token stored in plaintext** in `jenkins_connections`. Same concern.
3. **`semgrep`/`owasp` type name mismatch** — legacy names, tools swapped during development. A DB migration would clean this up.
4. **No scan concurrency limit** — a user can queue unlimited simultaneous scans.
5. **SonarQube Groovy script** uses string interpolation — `sonarUrl`/`sonarToken` containing Groovy metacharacters could cause issues. Consider Jenkins Credentials Binding plugin for production.
6. **OSV enrichment capped at 50 CVEs** — scans with more CVEs will have partial enrichment.
7. **AI response must be valid JSON** — if the LLM returns markdown-wrapped JSON the parser falls back to raw text display. Prompt tuning per provider may be needed.
8. **Pipeline stage timing is estimated** — `endSec` thresholds are approximate averages; actual stage durations vary by repo size and network speed.
9. **OWASP DC first-run is slow** — downloads ~200 MB NVD database. Subsequent runs are fast (cached). Consider pre-seeding the DB image or mounting a volume.
10. **TruffleHog JSONL format** — TruffleHog outputs one JSON object per line (not a JSON array). Parser splits on newlines; malformed lines are silently skipped.
11. **SAST dedup is approximate** — SonarQube and Semgrep use different rule IDs so exact dedup is impossible. The ±3 line proximity heuristic may produce false merges in dense files or false misses when tools report slightly different offsets.
12. **Semgrep `--config=auto` requires network** — falls back to `--config=p/default` if `auto` fails. Both may fail in air-gapped Jenkins environments.
