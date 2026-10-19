-- Sample workspace. Fresh-install schema and defaults.

CREATE TABLE tally_sample_workspace (
    installation_id UUID NOT NULL,
    dataset_id UUID NOT NULL,
    version INTEGER NOT NULL,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    manifest JSONB NOT NULL,
    CONSTRAINT tally_sample_workspace_manifest_check CHECK ((jsonb_typeof(manifest) = 'object')),
    CONSTRAINT tally_sample_workspace_state_check CHECK (state IN ('adding', 'ready', 'partial', 'removing')),
    CONSTRAINT tally_sample_workspace_version_check CHECK ((version > 0)),
    CONSTRAINT tally_sample_workspace_dataset_id_key UNIQUE (dataset_id),
    CONSTRAINT tally_sample_workspace_pkey PRIMARY KEY (installation_id),
    CONSTRAINT tally_sample_workspace_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES installations(installation_id) ON DELETE CASCADE
);
