-- Ingestion. Fresh-install schema and defaults.

CREATE TABLE ingestion_batches (
    batch_id UUID NOT NULL,
    connector_instance_id UUID NOT NULL,
    installation_id UUID NOT NULL,
    batch_digest TEXT NOT NULL,
    observation_count BIGINT NOT NULL,
    checkpoint TEXT DEFAULT '' NOT NULL,
    status TEXT DEFAULT 'writing' NOT NULL,
    failure_code TEXT,
    accepted_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    completed_at TIMESTAMPTZ,
    CONSTRAINT ingestion_batches_batch_digest_check CHECK ((batch_digest ~ '^[0-9a-f]{64}$')),
    CONSTRAINT ingestion_batches_observation_count_check CHECK ((observation_count >= 0)),
    CONSTRAINT ingestion_batches_status_check CHECK (status IN ('writing', 'completed', 'failed')),
    CONSTRAINT ingestion_batches_connector_instance_id_batch_digest_key UNIQUE (connector_instance_id, batch_digest),
    CONSTRAINT ingestion_batches_pkey PRIMARY KEY (batch_id),
    CONSTRAINT ingestion_batches_connector_instance_id_fkey FOREIGN KEY (connector_instance_id) REFERENCES connector_states(connector_instance_id) ON DELETE CASCADE,
    CONSTRAINT ingestion_batches_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES installations(installation_id) ON DELETE CASCADE
);
