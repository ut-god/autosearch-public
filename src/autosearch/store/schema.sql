-- autosearch findings.db schema
-- Single-writer (orchestrator) + multi-reader (TUI, CLI inspections).
-- WAL mode enabled at connection time. All cycle-phase writes wrapped
-- in transactions.

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------
-- Versioning: catalog and mitigations are append-only by version.
-- An "epoch" is the (catalog_version_id, mitigations_version_id,
-- prompt_version_hash) tuple under which a clean/finding was produced.
-- Retirement is a query bound to the current epoch, NOT a stored flag.
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS catalog_versions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  content_hash TEXT NOT NULL UNIQUE,
  body         TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  rationale    TEXT
);

CREATE TABLE IF NOT EXISTS mitigations_versions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  content_hash TEXT NOT NULL UNIQUE,
  body         TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  rationale    TEXT
);

CREATE TABLE IF NOT EXISTS prompt_versions (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_name      TEXT NOT NULL,           -- 'auditor', 'validator', ...
  template_hash   TEXT NOT NULL,           -- sha256 of the .md file
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(agent_name, template_hash)
);

-- ------------------------------------------------------------------
-- Cycles: idempotent. status='running' at start, 'complete'|'aborted'
-- at end. Crashed restart marks any 'running' rows as 'aborted' and
-- starts a new cycle (no resume mid-cycle).
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cycles (
  n                       INTEGER PRIMARY KEY,
  started_at              TEXT NOT NULL DEFAULT (datetime('now')),
  ended_at                TEXT,
  status                  TEXT NOT NULL CHECK (status IN ('running','complete','aborted')),
  catalog_version_id      INTEGER REFERENCES catalog_versions(id),
  mitigations_version_id  INTEGER REFERENCES mitigations_versions(id),
  target_sha              TEXT,            -- target repo HEAD at cycle start
  score                   REAL,
  breakdown_json          TEXT,            -- counts of memH, memM, prune, clean, etc.
  notes                   TEXT
);

-- ------------------------------------------------------------------
-- agent_runs: every LLM invocation is one row. Immutable. Captures
-- prompt+response+model+CLI version for reproducibility.
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS agent_runs (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  cycle_n            INTEGER REFERENCES cycles(n),     -- nullable for repair-only runs
  agent_name         TEXT NOT NULL,         -- 'auditor', 'validator', ...
  slot               TEXT,                  -- 'auditor#3', 'challenger#1', etc.
  model              TEXT NOT NULL,         -- 'claude-opus-4.7', 'gpt-5.4'
  cli_version        TEXT,                  -- captured from `copilot --version`
  prompt_version_id  INTEGER NOT NULL REFERENCES prompt_versions(id),
  rendered_prompt    TEXT NOT NULL,
  prompt_hash        TEXT NOT NULL,         -- sha256 of rendered_prompt
  raw_response       TEXT,                  -- full stdout of the agent
  response_hash      TEXT,
  parse_status       TEXT NOT NULL CHECK (parse_status IN ('ok','repaired','parse_failed','timeout','error')),
  parsed_json        TEXT,                  -- the extracted JSON (post-repair if needed)
  started_at         TEXT NOT NULL DEFAULT (datetime('now')),
  ended_at           TEXT,
  duration_ms        INTEGER,
  exit_code          INTEGER,
  error_message      TEXT,

  -- cost telemetry (added in schema_version=2; nullable so historical
  -- rows don't break). Tokens are estimates from char counts when the
  -- dispatcher doesn't return real usage stats.
  prompt_tokens      INTEGER,
  completion_tokens  INTEGER,
  cost_usd           REAL
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_cycle ON agent_runs(cycle_n);
CREATE INDEX IF NOT EXISTS idx_agent_runs_agent ON agent_runs(agent_name);

-- ------------------------------------------------------------------
-- claims: structured form of every CLAIM produced by an auditor.
-- Survives forever; state column tracks lifecycle.
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS claims (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_run_id          INTEGER REFERENCES agent_runs(id),  -- nullable: imported rows have no agent run
  cycle_n               INTEGER NOT NULL REFERENCES cycles(n),

  -- canonical identity (used for dedup + quorum)
  canonical_key         TEXT NOT NULL,     -- sha256("class|method|bug_class|file|line_span|sink_kind")
  target_class          TEXT NOT NULL,
  target_method         TEXT NOT NULL,
  bug_class             TEXT NOT NULL,
  unchecked_op_file     TEXT NOT NULL,
  unchecked_op_line     INTEGER NOT NULL,
  missing_check_file    TEXT,
  missing_check_line    INTEGER,

  -- claim payload
  claim_type            TEXT NOT NULL,     -- fresh|deepen|chain|transplant
  builds_on             INTEGER REFERENCES claims(id),
  trust_type            TEXT,
  severity              TEXT,
  reachability          TEXT,
  primitive             TEXT,
  patch_counterfactual  TEXT NOT NULL,
  catalog_match         TEXT,
  novel                 INTEGER NOT NULL DEFAULT 0,
  body                  TEXT NOT NULL,

  -- lifecycle
  state                 TEXT NOT NULL CHECK (state IN (
                          'proposed','validated','contested','confirmed',
                          'settled','reverted','rejected','superseded')),
  state_reason          TEXT,
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at            TEXT NOT NULL DEFAULT (datetime('now')),

  -- epoch under which the claim was made (relevant for re-eval on edit)
  catalog_version_id    INTEGER NOT NULL REFERENCES catalog_versions(id),
  mitigations_version_id INTEGER NOT NULL REFERENCES mitigations_versions(id),
  target_sha            TEXT
);

CREATE INDEX IF NOT EXISTS idx_claims_state ON claims(state);
CREATE INDEX IF NOT EXISTS idx_claims_canonical ON claims(canonical_key);
CREATE INDEX IF NOT EXISTS idx_claims_method ON claims(target_class, target_method);

-- ------------------------------------------------------------------
-- validations: one per validator pass on a claim. Append-only.
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS validations (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  claim_id          INTEGER NOT NULL REFERENCES claims(id),
  agent_run_id      INTEGER REFERENCES agent_runs(id),  -- nullable for imports
  model             TEXT NOT NULL,
  verdict           TEXT NOT NULL CHECK (verdict IN ('accept','reject')),
  code              TEXT,                  -- rejection code, NULL on accept
  rationale         TEXT NOT NULL,
  literal_quote     TEXT,                  -- quoted source line
  patch_check       TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_validations_claim ON validations(claim_id);
CREATE INDEX IF NOT EXISTS idx_validations_code ON validations(code);

-- ------------------------------------------------------------------
-- challenges: pre-commit and post-commit. phase column distinguishes.
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS challenges (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  claim_id          INTEGER NOT NULL REFERENCES claims(id),
  agent_run_id      INTEGER REFERENCES agent_runs(id),  -- nullable for imports
  model             TEXT NOT NULL,
  phase             TEXT NOT NULL CHECK (phase IN ('pre_commit','post_commit')),
  verdict           TEXT NOT NULL CHECK (verdict IN ('survives','reverted')),
  rationale         TEXT NOT NULL,
  disproved_axis    TEXT,
  evidence_json     TEXT,
  target_file_sha   TEXT,                  -- SHA of target file at challenge time
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_challenges_claim ON challenges(claim_id);
CREATE INDEX IF NOT EXISTS idx_challenges_phase ON challenges(phase);

-- ------------------------------------------------------------------
-- cleans: structured form of CLEAN reports. Bound to epoch for
-- retirement queries.
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cleans (
  id                     INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_run_id           INTEGER REFERENCES agent_runs(id),  -- nullable for imports
  cycle_n                INTEGER NOT NULL REFERENCES cycles(n),
  target_class           TEXT NOT NULL,
  target_method          TEXT NOT NULL,
  model                  TEXT NOT NULL,
  checks_verified_json   TEXT NOT NULL,
  body                   TEXT NOT NULL,
  spot_check_verdict     TEXT CHECK (spot_check_verdict IN ('confirm','found_claim','quorum_skip',NULL)),
  spot_check_run_id      INTEGER REFERENCES agent_runs(id),
  catalog_version_id     INTEGER NOT NULL REFERENCES catalog_versions(id),
  mitigations_version_id INTEGER NOT NULL REFERENCES mitigations_versions(id),
  target_sha             TEXT,
  created_at             TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cleans_method ON cleans(target_class, target_method);

-- ------------------------------------------------------------------
-- targets: parsed from workspace targets.md, refreshed each cycle.
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS targets (
  target_class    TEXT NOT NULL,
  target_method   TEXT NOT NULL,
  bug_class_hint  TEXT,
  reason          TEXT,
  campaign        TEXT,
  sub_area        TEXT,
  source_path     TEXT,                    -- path hint, e.g. 'Source/WebCore/...'
  added_at        TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (target_class, target_method)
);

-- ------------------------------------------------------------------
-- raw_commits: legacy import staging table. Idempotent by SHA.
-- Materialization queries derive claims/cleans/challenges from here.
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS raw_commits (
  sha                 TEXT PRIMARY KEY,
  subject             TEXT NOT NULL,
  body                TEXT NOT NULL,
  author_date         TEXT,
  parse_status        TEXT NOT NULL CHECK (parse_status IN ('parsed','partial','unparseable')),
  parsed_fields_json  TEXT,
  imported_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ------------------------------------------------------------------
-- workspace metadata (single-row table)
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS workspace (
  id                INTEGER PRIMARY KEY CHECK (id = 1),
  name              TEXT NOT NULL,
  target_repo       TEXT NOT NULL,
  schema_version    INTEGER NOT NULL,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
