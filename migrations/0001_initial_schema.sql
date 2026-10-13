-- OpenSpective D1 Migration 0001
-- Initial schema

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  is_active INTEGER NOT NULL DEFAULT 1,
  email_verified INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL DEFAULT (datetime('now')),
  user_agent TEXT,
  ip_address TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- Investigations table
CREATE TABLE IF NOT EXISTS investigations (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  target_type TEXT NOT NULL,
  normalized_target TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  modules TEXT NOT NULL DEFAULT '[]', -- JSON array
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT,
  error_message TEXT,
  ai_analysis_id TEXT,
  enable_ai INTEGER NOT NULL DEFAULT 0,
  metadata TEXT NOT NULL DEFAULT '{}', -- JSON object
  notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_investigations_user_id ON investigations(user_id);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_investigations_target_type ON investigations(target_type);
CREATE INDEX IF NOT EXISTS idx_investigations_normalized_target ON investigations(normalized_target);
CREATE INDEX IF NOT EXISTS idx_investigations_started_at ON investigations(started_at DESC);

-- Collector executions
CREATE TABLE IF NOT EXISTS collector_executions (
  id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  collector_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT,
  findings_count INTEGER NOT NULL DEFAULT 0,
  error_message TEXT,
  source_url TEXT
);

CREATE INDEX IF NOT EXISTS idx_collector_exec_investigation ON collector_executions(investigation_id);
CREATE INDEX IF NOT EXISTS idx_collector_exec_status ON collector_executions(status);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  collector_execution_id TEXT REFERENCES collector_executions(id) ON DELETE SET NULL,
  category TEXT NOT NULL,
  subcategory TEXT,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  raw_data TEXT NOT NULL DEFAULT '{}', -- JSON
  confidence TEXT NOT NULL DEFAULT 'unknown',
  severity TEXT NOT NULL DEFAULT 'info',
  source_url TEXT,
  source_name TEXT NOT NULL,
  first_seen TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen TEXT NOT NULL DEFAULT (datetime('now')),
  is_inferred INTEGER NOT NULL DEFAULT 0,
  notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_investigation ON findings(investigation_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
CREATE INDEX IF NOT EXISTS idx_findings_collector_exec ON findings(collector_execution_id);

-- Relationships table
CREATE TABLE IF NOT EXISTS relationships (
  id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  from_entity_type TEXT NOT NULL,
  to_entity_type TEXT NOT NULL,
  from_value TEXT NOT NULL,
  to_value TEXT NOT NULL,
  relationship_type TEXT NOT NULL,
  finding_id TEXT REFERENCES findings(id) ON DELETE SET NULL,
  source_url TEXT,
  confidence TEXT NOT NULL DEFAULT 'unknown',
  is_inferred INTEGER NOT NULL DEFAULT 0,
  collected_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_relationships_investigation ON relationships(investigation_id);
CREATE INDEX IF NOT EXISTS idx_relationships_from_value ON relationships(from_value);
CREATE INDEX IF NOT EXISTS idx_relationships_to_value ON relationships(to_value);

-- AI analyses
CREATE TABLE IF NOT EXISTS ai_analyses (
  id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  model TEXT NOT NULL,
  summary TEXT NOT NULL,
  technical_details TEXT NOT NULL,
  recommendations TEXT NOT NULL DEFAULT '[]', -- JSON array
  gaps TEXT NOT NULL DEFAULT '[]', -- JSON array
  evidence_refs TEXT NOT NULL DEFAULT '[]', -- JSON array
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  token_count INTEGER,
  provider TEXT NOT NULL DEFAULT 'cloudflare-workers-ai'
);

CREATE INDEX IF NOT EXISTS idx_ai_analyses_investigation ON ai_analyses(investigation_id);

-- Reports
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  format TEXT NOT NULL,
  storage_key TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT,
  size_bytes INTEGER
);

CREATE INDEX IF NOT EXISTS idx_reports_investigation ON reports(investigation_id);
CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id);

-- Usage tracking
CREATE TABLE IF NOT EXISTS usage_records (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  period TEXT NOT NULL, -- YYYY-MM
  investigation_count INTEGER NOT NULL DEFAULT 0,
  collector_call_count INTEGER NOT NULL DEFAULT 0,
  ai_inference_count INTEGER NOT NULL DEFAULT 0,
  report_count INTEGER NOT NULL DEFAULT 0,
  storage_bytes INTEGER NOT NULL DEFAULT 0,
  UNIQUE(user_id, period)
);

CREATE INDEX IF NOT EXISTS idx_usage_user_period ON usage_records(user_id, period);

-- Audit events
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  details TEXT NOT NULL DEFAULT '{}', -- JSON
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at DESC);

-- Guest investigation tracking (rate limiting without full account)
CREATE TABLE IF NOT EXISTS guest_investigations (
  id TEXT PRIMARY KEY,
  ip_address TEXT NOT NULL,
  investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_guest_ip ON guest_investigations(ip_address);
CREATE INDEX IF NOT EXISTS idx_guest_created_at ON guest_investigations(created_at);
