-- Audit. Fresh-install schema and defaults.

CREATE TABLE audit_log (
    audit_id UUID NOT NULL,
    at TIMESTAMPTZ DEFAULT now() NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    detail JSONB DEFAULT '{}'::JSONB NOT NULL,
    CONSTRAINT audit_log_pkey PRIMARY KEY (audit_id)
);

CREATE INDEX audit_log_recent_idx ON audit_log (at DESC, audit_id);
