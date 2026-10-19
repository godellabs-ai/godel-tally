-- Auth. Fresh-install schema and defaults.

CREATE TABLE tally_auth_users (
    user_id UUID NOT NULL,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT,
    role TEXT NOT NULL,
    failed_attempts INTEGER DEFAULT 0 NOT NULL,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    disabled_at TIMESTAMPTZ,
    first_name TEXT,
    last_name TEXT,
    CONSTRAINT tally_auth_first_name_nonblank CHECK (((first_name IS NULL) OR (btrim(first_name) <> ''))),
    CONSTRAINT tally_auth_last_name_nonblank CHECK (((last_name IS NULL) OR (btrim(last_name) <> ''))),
    CONSTRAINT tally_auth_users_role_check CHECK (role IN ('admin', 'member')),
    CONSTRAINT tally_auth_users_email_key UNIQUE (email),
    CONSTRAINT tally_auth_users_pkey PRIMARY KEY (user_id)
);

CREATE TABLE tally_auth_invitations (
    token_hash BYTEA NOT NULL,
    email TEXT NOT NULL,
    invited_by UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    CONSTRAINT tally_auth_invitations_pkey PRIMARY KEY (token_hash),
    CONSTRAINT tally_auth_invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES tally_auth_users(user_id)
);

CREATE TABLE tally_auth_password_resets (
    token_hash BYTEA NOT NULL,
    user_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    CONSTRAINT tally_auth_password_resets_pkey PRIMARY KEY (token_hash),
    CONSTRAINT tally_auth_password_resets_user_id_fkey FOREIGN KEY (user_id) REFERENCES tally_auth_users(user_id) ON DELETE CASCADE
);

CREATE INDEX tally_auth_password_resets_user_id_idx ON tally_auth_password_resets (user_id);

CREATE TABLE tally_auth_sessions (
    token_hash BYTEA NOT NULL,
    user_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    CONSTRAINT tally_auth_sessions_pkey PRIMARY KEY (token_hash),
    CONSTRAINT tally_auth_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES tally_auth_users(user_id) ON DELETE CASCADE
);

CREATE INDEX tally_auth_sessions_user_id_idx ON tally_auth_sessions (user_id);
