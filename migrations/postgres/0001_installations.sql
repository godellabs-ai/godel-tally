-- Installations. Fresh-install schema and defaults.

CREATE TABLE installations (
    installation_id UUID NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    CONSTRAINT installations_pkey PRIMARY KEY (installation_id)
);

CREATE TABLE installation_secrets (
    singleton BOOLEAN DEFAULT true NOT NULL,
    installation_id UUID NOT NULL,
    pseudonymization_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    CONSTRAINT installation_secrets_pseudonymization_key_check CHECK ((octet_length(pseudonymization_key) = 32)),
    CONSTRAINT installation_secrets_singleton_check CHECK (singleton),
    CONSTRAINT installation_secrets_pkey PRIMARY KEY (singleton),
    CONSTRAINT installation_secrets_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES installations(installation_id) ON DELETE CASCADE
);
