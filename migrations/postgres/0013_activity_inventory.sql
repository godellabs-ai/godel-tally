-- Preserve source-associated activity independently of aggregate finding labels.
CREATE TABLE finding_activity (
    finding_id UUID NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    observation_id UUID NOT NULL,
    installation_id UUID NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
    connector_instance_id UUID NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    context JSONB NOT NULL,
    PRIMARY KEY (finding_id, observation_id)
);
CREATE INDEX finding_activity_page ON finding_activity (installation_id, finding_id, observed_at DESC, observation_id DESC);
CREATE TABLE finding_activity_revisions (
    finding_id UUID NOT NULL,
    observation_id UUID NOT NULL,
    digest TEXT NOT NULL,
    context JSONB NOT NULL,
    conflicts JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(finding_id,observation_id,digest),
    FOREIGN KEY(finding_id,observation_id) REFERENCES finding_activity(finding_id,observation_id) ON DELETE CASCADE
);

-- Facts are scoped to their originating connector/tenant. Hostnames and IPs are aliases,
-- never canonical device keys. Independent facts survive removal of another source.
CREATE TABLE identity_facts (
    fact_id UUID PRIMARY KEY,
    installation_id UUID NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
    entity_id UUID NOT NULL,
    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('device', 'user')),
    connector_instance_id UUID NOT NULL,
    source_scope TEXT NOT NULL,
    observation_id UUID NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    retired BOOLEAN NOT NULL DEFAULT false,
    attributes JSONB NOT NULL,
    CHECK (valid_until IS NULL OR valid_until >= observed_at)
    ,CHECK (last_seen >= observed_at)
);
CREATE INDEX identity_facts_entity ON identity_facts (installation_id, entity_id, observed_at DESC);
CREATE INDEX identity_facts_source ON identity_facts (installation_id, connector_instance_id, observed_at DESC);
CREATE INDEX identity_facts_attributes ON identity_facts USING gin (attributes jsonb_path_ops);

CREATE TABLE identity_device_aliases (
    installation_id UUID NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
    connector_instance_id UUID NOT NULL,
    source_scope TEXT NOT NULL,
    device_key TEXT NOT NULL,
    entity_id UUID NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    observation_id UUID NOT NULL,
    PRIMARY KEY (installation_id, connector_instance_id, source_scope, device_key, observation_id),
    CHECK (valid_until IS NULL OR valid_until >= valid_from)
);
CREATE INDEX identity_device_alias_lookup ON identity_device_aliases (installation_id,connector_instance_id,source_scope,device_key,valid_from DESC);

CREATE TABLE endpoint_process_facts (
    installation_id UUID NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
    connector_instance_id UUID NOT NULL,
    source_scope TEXT NOT NULL,
    device_key TEXT NOT NULL,
    process_key TEXT NOT NULL,
    observation_id UUID NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    context JSONB NOT NULL,
    PRIMARY KEY (installation_id,connector_instance_id,observation_id)
);
CREATE INDEX endpoint_process_lookup ON endpoint_process_facts (installation_id,connector_instance_id,source_scope,device_key,process_key,observed_at DESC);

CREATE TABLE inventory_source_presence (
    installation_id UUID NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
    connector_instance_id UUID NOT NULL,
    device_key TEXT NOT NULL,
    last_snapshot_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ,
    PRIMARY KEY(installation_id,connector_instance_id,device_key)
);
CREATE TABLE inventory_sync_status (
    installation_id UUID NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
    connector_instance_id UUID NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    device_count BIGINT NOT NULL CHECK(device_count>=0),
    PRIMARY KEY(installation_id,connector_instance_id)
);
CREATE TABLE inventory_presence_events (
    installation_id UUID NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
    connector_instance_id UUID NOT NULL,
    device_key TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    present BOOLEAN NOT NULL,
    PRIMARY KEY(installation_id,connector_instance_id,device_key,observed_at)
);

CREATE TABLE identity_links (
    installation_id UUID NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role TEXT NOT NULL,
    observation_id UUID NOT NULL,
    connector_instance_id UUID NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    PRIMARY KEY (installation_id, device_id, user_id, role, observation_id),
    CHECK (valid_until IS NULL OR valid_until >= valid_from)
);
CREATE INDEX identity_links_device ON identity_links (installation_id, device_id, valid_from DESC);

CREATE TABLE identity_corrections (
    correction_id UUID PRIMARY KEY,
    installation_id UUID NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
    subject_id UUID NOT NULL,
    target_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 512),
    undone_at TIMESTAMPTZ,
    CHECK (subject_id <> target_id)
);
CREATE UNIQUE INDEX identity_correction_active ON identity_corrections (installation_id, subject_id) WHERE undone_at IS NULL;

CREATE TABLE identity_replay_jobs (
    installation_id UUID PRIMARY KEY REFERENCES installations(installation_id) ON DELETE CASCADE,
    requested_generation BIGINT NOT NULL DEFAULT 1,
    scan_generation BIGINT NOT NULL DEFAULT 0,
    completed_generation BIGINT NOT NULL DEFAULT 0,
    last_observation_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    processed_count BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE identity_enrichments (
    installation_id UUID NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
    observation_id UUID NOT NULL,
    rule_version TEXT NOT NULL,
    context JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (installation_id, observation_id)
);
