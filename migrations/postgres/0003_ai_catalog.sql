-- Ai catalog. Fresh-install schema and defaults.

CREATE FUNCTION tally_default_provider_sanction(provider_key TEXT) RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT COALESCE(provider_key IN (
        'openai',
        'anthropic',
        'google',
        'google-vertex-ai',
        'azure-ai',
        'microsoft',
        'microsoft-365-copilot',
        'github',
        'aws-bedrock',
        'cohere',
        'mistral',
        'databricks',
        'snowflake',
        'ibm-watsonx'
    ), FALSE)
$$;

CREATE TABLE ai_providers (
    provider_id UUID DEFAULT gen_random_uuid() NOT NULL,
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    country_code CHAR(2),
    catalog BOOLEAN DEFAULT true NOT NULL,
    sanctioned BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    CONSTRAINT ai_providers_category_check CHECK (category IN ('direct_provider', 'managed_platform', 'ai_gateway', 'local_runtime', 'inference_server', 'enterprise_application')),
    CONSTRAINT ai_providers_key_check CHECK (((length(key) >= 1) AND (length(key) <= 160))),
    CONSTRAINT ai_providers_name_check CHECK (((length(name) >= 1) AND (length(name) <= 160))),
    CONSTRAINT ai_providers_key_key UNIQUE (key),
    CONSTRAINT ai_providers_pkey PRIMARY KEY (provider_id)
);

CREATE INDEX ai_providers_sanction_idx ON ai_providers (sanctioned, name);

CREATE TABLE ai_models (
    model_id UUID DEFAULT gen_random_uuid() NOT NULL,
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    family TEXT NOT NULL,
    owner_provider_id UUID,
    country_code CHAR(2),
    modalities TEXT[] DEFAULT '{text}'::TEXT[] NOT NULL,
    capabilities TEXT[] DEFAULT '{}'::TEXT[] NOT NULL,
    aliases TEXT[] DEFAULT '{}'::TEXT[] NOT NULL,
    catalog BOOLEAN DEFAULT true NOT NULL,
    sanctioned BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    CONSTRAINT ai_models_key_check CHECK (((length(key) >= 1) AND (length(key) <= 200))),
    CONSTRAINT ai_models_modalities_check CHECK ((cardinality(modalities) > 0)),
    CONSTRAINT ai_models_name_check CHECK (((length(name) >= 1) AND (length(name) <= 200))),
    CONSTRAINT ai_models_key_key UNIQUE (key),
    CONSTRAINT ai_models_pkey PRIMARY KEY (model_id),
    CONSTRAINT ai_models_owner_provider_id_fkey FOREIGN KEY (owner_provider_id) REFERENCES ai_providers(provider_id) ON DELETE SET NULL
);

CREATE INDEX ai_models_aliases_idx ON ai_models USING gin (aliases);

CREATE INDEX ai_models_capabilities_idx ON ai_models USING gin (capabilities);

CREATE INDEX ai_models_modalities_idx ON ai_models USING gin (modalities);

CREATE INDEX ai_models_sanction_idx ON ai_models (sanctioned, family, name);

CREATE TABLE ai_provider_domains (
    provider_key TEXT NOT NULL,
    domain TEXT NOT NULL,
    source_url TEXT,
    CONSTRAINT ai_provider_domains_domain_check CHECK (((domain = lower(domain)) AND (domain ~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'))),
    CONSTRAINT ai_provider_domains_pkey PRIMARY KEY (provider_key, domain),
    CONSTRAINT ai_provider_domains_provider_key_fkey FOREIGN KEY (provider_key) REFERENCES ai_providers(key) ON DELETE CASCADE
);

CREATE TABLE ai_provider_models (
    provider_id UUID NOT NULL,
    model_id UUID NOT NULL,
    source TEXT DEFAULT 'catalog' NOT NULL,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    CONSTRAINT ai_provider_models_check CHECK (((last_seen IS NULL) OR (first_seen IS NULL) OR (last_seen >= first_seen))),
    CONSTRAINT ai_provider_models_source_check CHECK (source IN ('catalog', 'connector')),
    CONSTRAINT ai_provider_models_pkey PRIMARY KEY (provider_id, model_id),
    CONSTRAINT ai_provider_models_model_id_fkey FOREIGN KEY (model_id) REFERENCES ai_models(model_id) ON DELETE CASCADE,
    CONSTRAINT ai_provider_models_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES ai_providers(provider_id) ON DELETE CASCADE
);
