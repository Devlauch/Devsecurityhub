CREATE TABLE IF NOT EXISTS users (
  id        TEXT PRIMARY KEY,
  name      TEXT NOT NULL,
  email     TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  ai_api_key TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS github_connections (
  id         SERIAL PRIMARY KEY,
  user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,
  token      TEXT NOT NULL,
  login      TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id)
);

CREATE TABLE IF NOT EXISTS jenkins_connections (
  id         SERIAL PRIMARY KEY,
  user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,
  url        TEXT NOT NULL,
  username   TEXT NOT NULL,
  token      TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id)
);

CREATE TABLE IF NOT EXISTS scans (
  id             SERIAL PRIMARY KEY,
  user_id        TEXT REFERENCES users(id) ON DELETE CASCADE,
  repo_url       TEXT NOT NULL,
  branch         TEXT DEFAULT 'main',
  job_name       TEXT NOT NULL,
  status         TEXT DEFAULT 'pending',
  last_build     INTEGER,
  detected_lang       TEXT DEFAULT '',
  has_dockerfile      BOOLEAN DEFAULT false,
  pre_analysis        TEXT DEFAULT '',
  jenkinsfile_pushed  BOOLEAN DEFAULT false,
  created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sonar_connections (
  id         SERIAL PRIMARY KEY,
  user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,
  url        TEXT NOT NULL,
  token      TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id)
);

CREATE TABLE IF NOT EXISTS scan_reports (
  id         SERIAL PRIMARY KEY,
  scan_id    INTEGER REFERENCES scans(id) ON DELETE CASCADE,
  type       TEXT NOT NULL,
  content    TEXT NOT NULL,
  fetched_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(scan_id, type)
);
