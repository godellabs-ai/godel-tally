-- Registry overlays. Fresh-install schema and defaults.

CREATE TABLE local_registry_overlays (
    overlay_id TEXT NOT NULL,
    installation_id UUID NOT NULL,
    "overlay" JSONB NOT NULL,
    overlay_sha256 TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    matcher_count INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    content_retained BOOLEAN DEFAULT false NOT NULL,
    CONSTRAINT local_registry_overlays_content_retained_check CHECK ((content_retained = false)),
    CONSTRAINT local_registry_overlays_entry_count_check CHECK (((entry_count >= 1) AND (entry_count <= 32))),
    CONSTRAINT local_registry_overlays_matcher_count_check CHECK (((matcher_count >= 1) AND (matcher_count <= 256))),
    CONSTRAINT local_registry_overlays_overlay_check CHECK ((jsonb_typeof("overlay") = 'object')),
    CONSTRAINT local_registry_overlays_overlay_sha256_check CHECK ((overlay_sha256 ~ '^[0-9a-f]{64}$')),
    CONSTRAINT local_registry_overlays_pkey PRIMARY KEY (overlay_id),
    CONSTRAINT local_registry_overlays_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES installations(installation_id) ON DELETE CASCADE
);

CREATE INDEX local_registry_overlays_installation_created_idx ON local_registry_overlays (installation_id, created_at, overlay_id);

CREATE TABLE local_registry_mutations (
    idempotency_key UUID NOT NULL,
    installation_id UUID NOT NULL,
    overlay_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    response JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT local_registry_mutations_request_sha256_check CHECK ((request_sha256 ~ '^[0-9a-f]{64}$')),
    CONSTRAINT local_registry_mutations_response_check CHECK ((jsonb_typeof(response) = 'object')),
    CONSTRAINT local_registry_mutations_pkey PRIMARY KEY (idempotency_key),
    CONSTRAINT local_registry_mutations_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES installations(installation_id) ON DELETE CASCADE,
    CONSTRAINT local_registry_mutations_overlay_id_fkey FOREIGN KEY (overlay_id) REFERENCES local_registry_overlays(overlay_id) ON DELETE CASCADE
);

CREATE INDEX local_registry_mutations_installation_created_idx ON local_registry_mutations (installation_id, created_at, idempotency_key);
