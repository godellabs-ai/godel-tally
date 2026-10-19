-- Findings. Fresh-install schema and defaults.

CREATE TABLE findings (
    finding_id UUID DEFAULT gen_random_uuid() NOT NULL,
    installation_id UUID NOT NULL,
    provider_id UUID NOT NULL,
    model_id UUID,
    model_version TEXT,
    evidence_kind TEXT DEFAULT 'ai_usage' NOT NULL,
    first_used_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL,
    usage_count BIGINT DEFAULT 0 NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    CONSTRAINT findings_check CHECK ((last_used_at >= first_used_at)),
    CONSTRAINT findings_evidence_kind_check CHECK (evidence_kind IN ('ai_usage', 'network_activity', 'resource_discovery')),
    CONSTRAINT findings_model_version_check CHECK (((model_version IS NULL) OR (length(model_version) <= 160))),
    CONSTRAINT findings_usage_count_check CHECK ((usage_count >= 0)),
    CONSTRAINT findings_pkey PRIMARY KEY (finding_id),
    CONSTRAINT findings_usage_identity_key UNIQUE NULLS NOT DISTINCT (installation_id, provider_id, model_id, model_version, evidence_kind),
    CONSTRAINT findings_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES installations(installation_id) ON DELETE CASCADE,
    CONSTRAINT findings_model_id_fkey FOREIGN KEY (model_id) REFERENCES ai_models(model_id) ON DELETE RESTRICT,
    CONSTRAINT findings_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES ai_providers(provider_id) ON DELETE RESTRICT
);

CREATE INDEX findings_recent_idx ON findings (last_used_at DESC, finding_id);

CREATE TABLE finding_observations (
    observation_id UUID NOT NULL,
    finding_id UUID NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    counts_as_usage BOOLEAN DEFAULT true NOT NULL,
    CONSTRAINT finding_observations_pkey PRIMARY KEY (observation_id, finding_id),
    CONSTRAINT finding_observations_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE INDEX finding_observations_finding_idx ON finding_observations (finding_id, observed_at);
