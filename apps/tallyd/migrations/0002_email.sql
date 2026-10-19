-- Email. Fresh-install schema and defaults.

CREATE TABLE tally_email_config (
    singleton BOOLEAN DEFAULT true NOT NULL,
    provider TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    from_email TEXT NOT NULL,
    from_name TEXT,
    settings JSONB DEFAULT '{}'::JSONB NOT NULL,
    secret_nonce BYTEA,
    secret_ciphertext BYTEA,
    updated_by UUID,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    CONSTRAINT tally_email_config_check CHECK (((secret_nonce IS NULL) = (secret_ciphertext IS NULL))),
    CONSTRAINT tally_email_config_provider_check CHECK (provider IN ('smtp', 'ses', 'sendgrid', 'mailgun', 'postmark', 'resend')),
    CONSTRAINT tally_email_config_singleton_check CHECK (singleton),
    CONSTRAINT tally_email_config_pkey PRIMARY KEY (singleton),
    CONSTRAINT tally_email_config_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES tally_auth_users(user_id) ON DELETE SET NULL
);
