CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS stix_objects (
  id TEXT NOT NULL,
  type TEXT NOT NULL,
  spec_version TEXT,
  created TIMESTAMPTZ,
  modified TIMESTAMPTZ,
  revoked BOOLEAN DEFAULT FALSE,
  source TEXT,
  object_json JSONB NOT NULL,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (id, modified)
);

CREATE INDEX IF NOT EXISTS idx_stix_objects_type ON stix_objects(type);
CREATE INDEX IF NOT EXISTS idx_stix_objects_created ON stix_objects(created);
CREATE INDEX IF NOT EXISTS idx_stix_objects_revoked ON stix_objects(revoked);
CREATE INDEX IF NOT EXISTS idx_stix_objects_source ON stix_objects(source);
CREATE INDEX IF NOT EXISTS idx_stix_objects_json_gin ON stix_objects USING GIN (object_json);

CREATE TABLE IF NOT EXISTS stix_relationships (
  rel_id TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  target_ref TEXT NOT NULL,
  relationship_type TEXT,
  modified TIMESTAMPTZ,
  PRIMARY KEY (rel_id, modified)
);

CREATE INDEX IF NOT EXISTS idx_stix_rel_source ON stix_relationships(source_ref);
CREATE INDEX IF NOT EXISTS idx_stix_rel_target ON stix_relationships(target_ref);
CREATE INDEX IF NOT EXISTS idx_stix_rel_type ON stix_relationships(relationship_type);

CREATE TABLE IF NOT EXISTS ingest_runs (
  run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  status TEXT NOT NULL,
  objects_total INT NOT NULL DEFAULT 0,
  upserted INT NOT NULL DEFAULT 0,
  skipped INT NOT NULL DEFAULT 0,
  errored INT NOT NULL DEFAULT 0,
  error_summary JSONB
);

CREATE INDEX IF NOT EXISTS idx_ingest_runs_source_started ON ingest_runs(source, started_at DESC);

CREATE TABLE IF NOT EXISTS ingest_checkpoints (
  source TEXT PRIMARY KEY,
  added_after TIMESTAMPTZ,
  last_run_id UUID REFERENCES ingest_runs(run_id),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
