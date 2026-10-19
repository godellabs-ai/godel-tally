-- Scanner jobs. Fresh-install schema and defaults.

CREATE TABLE scan_jobs (
    scan_id UUID NOT NULL,
    idempotency_key UUID NOT NULL,
    request_fingerprint TEXT NOT NULL,
    scope_digest TEXT NOT NULL,
    plan JSONB NOT NULL,
    execution_policy JSONB NOT NULL,
    status TEXT NOT NULL,
    authorized_by TEXT NOT NULL,
    authorization_acknowledged_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    planned_probes BIGINT NOT NULL,
    completed_probes BIGINT DEFAULT 0 NOT NULL,
    open_port_count BIGINT DEFAULT 0 NOT NULL,
    fingerprint_attempt_count BIGINT DEFAULT 0 NOT NULL,
    fingerprint_match_count BIGINT DEFAULT 0 NOT NULL,
    resolved_system_count BIGINT DEFAULT 0 NOT NULL,
    results JSONB DEFAULT '[]'::JSONB NOT NULL,
    error_code TEXT,
    content_retained BOOLEAN DEFAULT false NOT NULL,
    CONSTRAINT scan_jobs_completed_probes_check CHECK ((completed_probes >= 0)),
    CONSTRAINT scan_jobs_content_retained_check CHECK ((content_retained = false)),
    CONSTRAINT scan_jobs_fingerprint_attempt_count_check CHECK ((fingerprint_attempt_count >= 0)),
    CONSTRAINT scan_jobs_fingerprint_match_count_check CHECK ((fingerprint_match_count >= 0)),
    CONSTRAINT scan_jobs_open_port_count_check CHECK ((open_port_count >= 0)),
    CONSTRAINT scan_jobs_planned_probes_check CHECK ((planned_probes >= 0)),
    CONSTRAINT scan_jobs_resolved_system_count_check CHECK ((resolved_system_count >= 0)),
    CONSTRAINT scan_jobs_scope_digest_check CHECK ((scope_digest ~ '^[0-9a-f]{64}$')),
    CONSTRAINT scan_jobs_status_check CHECK (status IN ('planned', 'running', 'cancel_requested', 'completed', 'cancelled', 'failed')),
    CONSTRAINT scan_jobs_idempotency_key_key UNIQUE (idempotency_key),
    CONSTRAINT scan_jobs_pkey PRIMARY KEY (scan_id)
);

CREATE INDEX scan_jobs_recent_idx ON scan_jobs (created_at DESC, scan_id DESC);
